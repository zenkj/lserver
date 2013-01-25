#include "lserver.h"
#include <string.h>

#define TCP_SERVER         "ls_tcp_server"
#define TCP_CONNECTION     "ls_tcp_connection"

#define MAX_WRITE_BUF_COUNT 16
typedef struct ls_write_s
{
    uv_write_t       req;
    ls_mthread_ref_t mthread_ref0;
    int              data_refs[MAX_WRITE_BUF_COUNT];
    int              refcnt;
} ls_write_t;

static ls_write_t *new_write_req(lua_State *l)
{
    int           i;
    ls_write_t   *wr;

    wr = (ls_write_t*)ls_malloc(l, sizeof(ls_write_t));
    ls_mthread_ref_init(&wr->mthread_ref0, 0);
    for (i=0; i<arraysize(wr->data_refs); i++)
        wr->data_refs[i] = LUA_NOREF;
    wr->refcnt = 0;

    return wr;
}

/* object in C */
typedef struct ls_tcp_s
{
    uv_tcp_t         handle;
    ls_mthread_ref_t mthread_ref0;
    ngx_queue_t      mthread_queue;
} ls_tcp_t;

/* object seen in lua */
typedef struct tcp_udata_s
{
    ls_tcp_t     *handle;
    int           timeout;
} tcp_udata_t;

#define server_udata(l)     ((tcp_udata_t*)luaL_checkudata(l, 1, TCP_SERVER))
#define connection_udata(l) ((tcp_udata_t*)luaL_checkudata(l, 1, TCP_CONNECTION))

static ls_tcp_t *new_tcp_handle(lua_State *l)
{
    ls_tcp_t *tcp = (ls_tcp_t*)ls_malloc(l, sizeof(ls_tcp_t));

    uv_tcp_init(uv_default_loop(), &tcp->handle);

    ls_mthread_ref_init(&tcp->mthread_ref0, 0);

    ngx_queue_init(&tcp->mthread_queue);

    return tcp;
}

static void tcp_close_cb(uv_handle_t *handle)
{
    ls_tcp_t    *tcp;
    lua_State   *l, *nl;
    ngx_queue_t *mthread_queue;

    tcp           = (ls_tcp_t*) handle;
    l             = ls_default_state();
    mthread_queue = &tcp->mthread_queue;

    while (nl = ls_mthread_dequeue(l, mthread_queue))
    {
        if (LUA_YIELD == lua_status(nl))
        {
            ls_error_resume(nl, LS_ERRCODE_EOF, "tcp closed");
            if (nl != l) lua_pop(l, 1);
        }
        else lua_pop(l, 1);
    }

    ls_free(l, handle);
}

static tcp_udata_t *_new_tcp_udata(lua_State *l, ls_tcp_t *handle)
{
    tcp_udata_t *udata = (tcp_udata_t*)lua_newuserdata(l, sizeof(tcp_udata_t));
    udata->handle = handle;
    udata->timeout = -1; // wait forever

    return udata;
}

static tcp_udata_t *new_tcp_server_udata(lua_State *l, ls_tcp_t *handle)
{
    tcp_udata_t *udata;
    udata = _new_tcp_udata(l, handle);
    luaL_setmetatable(l, TCP_SERVER);
    return udata;
}

static tcp_udata_t *new_tcp_connection_udata(lua_State *l, ls_tcp_t *handle)
{
    tcp_udata_t *udata;
    udata = _new_tcp_udata(l, handle);
    luaL_setmetatable(l, TCP_CONNECTION);
    return udata;
}


static uv_buf_t tcp_alloc_cb(uv_handle_t *handle, size_t suggested_size)
{
    static char buf[65536];
    return uv_buf_init(buf, sizeof buf);
}

static void tcp_read_cb(uv_stream_t *handle, ssize_t nread, uv_buf_t buf)
{
    uv_loop_t *loop = uv_default_loop();
    lua_State *l    = ls_default_state();
    ls_tcp_t  *tcp  = (ls_tcp_t*)handle;
    lua_State *nl;

    if (ngx_queue_empty(&tcp->mthread_queue))
        return;

    while (nl = ls_mthread_dequeue(l, &tcp->mthread_queue))
    {
        ls_timer_stop(nl, 1);

        if (LUA_YIELD != lua_status(nl))
            continue;

        if (nread == -1)
            ls_last_error_resume(nl, loop);
        else
        {
            lua_pushboolean(nl, 1);
            lua_pushlstring(nl, buf.base, nread);
            ls_resume(nl, 2);
        }

        // pop the thread after resume, to ensure the thread is not released by GC.
        if (nl != l)
            lua_pop(l, 1);
        return;
    }
}

static void tcp_listen_cb(uv_stream_t *handle, int status)
{
    lua_State   *l             = ls_default_state();
    ls_tcp_t    *server        = (ls_tcp_t *)handle;
    uv_loop_t   *loop          = uv_default_loop();
    ngx_queue_t *mthread_queue = &server->mthread_queue;
    lua_State   *nl;

    if (status != 0)
    {
        while (nl = ls_mthread_dequeue(l, mthread_queue))
        {
            int errcode = uv_last_error(loop).code;
            const char *errmsg = uv_strerror(uv_last_error(loop));
            if (LUA_YIELD == lua_status(nl))
            {
                ls_error_resume(nl, errcode, errmsg);
                if (nl != l) lua_pop(l, 1);
            }
            else
                lua_pop(l, 1);
        }
        return;
    }

    if (!ngx_queue_empty(mthread_queue))
    {
        ls_tcp_t *client = new_tcp_handle(l);

        if (uv_accept(handle, (uv_stream_t*)&client->handle))
        {
            ls_free(l, client);
            luaL_error(l, "accept failed");
        }

        if (uv_read_start((uv_stream_t*)&client->handle, tcp_alloc_cb, tcp_read_cb))
        {
            ls_free(l, client);
            luaL_error(l, "start read failed");
        }

        while (nl = ls_mthread_dequeue(l, mthread_queue))
        {
            if (lua_status(nl) == LUA_YIELD)
            {
                lua_pushboolean(nl, 1);
                new_tcp_connection_udata(nl, client);
                ls_resume(nl, 2);
                if (nl != l) lua_pop(l, 1);
                return;
            }
            else
            {
                lua_pop(l, 1);
            }
        }

        // the client has no mthread to handle it, free it
        ls_free(l, client);
    }
}

static int tcp_create_server(lua_State *l)
{
    const char  *ip4     = "0.0.0.0";
    int          port    = 0;
    ls_tcp_t    *server;
    uv_tcp_t    *handle;
    tcp_udata_t *udata;
    uv_loop_t   *loop    = uv_default_loop();

    if (lua_gettop(l) >= 2)
    {
        ip4 = luaL_checkstring(l, 1);
        port = luaL_checkint(l, 2);
        luaL_argcheck(l, strnlen(ip4, 256) > 0, 1, "invalid ipv4 address");
        luaL_argcheck(l, port >= 0, 2, "port number should >= 0");
    }
    else if (lua_gettop(l) == 1)
    {
        port = luaL_checkint(l, 1);
        luaL_argcheck(l, port >= 0, 1, "port number should >= 0");
    }
    server = new_tcp_handle(l);
    handle = &server->handle;

    if (uv_tcp_bind(handle, uv_ip4_addr(ip4, port)))
    {
        uv_close((uv_handle_t*)server, tcp_close_cb);
        return ls_error_return(l, LS_ERRCODE_ADDRESS_USED, "bind failed: address used.");
    }

    if (uv_listen((uv_stream_t*)handle, 128, tcp_listen_cb))
    {
        uv_close((uv_handle_t*)server, tcp_close_cb);
        return ls_error_return(l, LS_ERRCODE_ERROR, "listen failed.");
    }

    lua_pushboolean(l, 1);
    new_tcp_server_udata(l, server);
    return 2;
}

static void tcp_connect_cb(uv_connect_t *connect_req, int status)
{
    ls_tcp_t *client = (ls_tcp_t*)connect_req->handle;
    uv_tcp_t *handle = &client->handle;
    lua_State *l = ls_default_state();
    lua_State *nl;
    uv_loop_t *loop = uv_default_loop();

    ls_free(l, connect_req);

    nl = ls_mthread_unref(l, &client->mthread_ref0);
    if (nl)
    {
        ls_timer_stop(nl, 1);
        if (status)
        {
            uv_close((uv_handle_t*)handle, tcp_close_cb);
            ls_last_error_resume(nl, loop);
        }
        else
        {
            if (uv_read_start((uv_stream_t*)handle, tcp_alloc_cb, tcp_read_cb))
            {
                uv_close((uv_handle_t*)handle, tcp_close_cb);
                ls_last_error_resume(nl, loop);
                return;
            }
            lua_pushboolean(nl, 1);
            new_tcp_connection_udata(nl, client);
            ls_resume(nl, 2);
        }

        if (nl != l)
            lua_pop(l, 1);
    }
}

static int tcp_create_client(lua_State *l)
{
    const char    *rip4     = "0.0.0.0";
    int            rport    = 0;
    ls_tcp_t      *client;
    uv_tcp_t      *handle;
    uv_loop_t     *loop    = uv_default_loop();
    uv_connect_t  *connect_req;
    int            connect_timeout;

    if (lua_gettop(l) >= 2)
    {
        rip4 = luaL_checkstring(l, 1);
        rport = luaL_checkint(l, 2);
        luaL_argcheck(l, strnlen(rip4, 256) > 0, 1, "invalid ipv4 address");
        luaL_argcheck(l, rport > 0, 2, "port number should > 0");
    }
    else if (lua_gettop(l) == 1)
    {
        rport = luaL_checkint(l, 1);
        luaL_argcheck(l, rport > 0, 1, "port number should > 0");
    }
    else
        return ls_error_return(l, LS_ERRCODE_INVAL, "server ip and port should be specified.");
    client = new_tcp_handle(l);
    handle = &client->handle;
    connect_req = (uv_connect_t*)ls_malloc(l, sizeof(uv_connect_t));
    if (uv_tcp_connect(connect_req, &client->handle, uv_ip4_addr(rip4, rport), tcp_connect_cb))
    {
        ls_free(l, connect_req);
        uv_close((uv_handle_t*)client, tcp_close_cb);
        return ls_last_error_return(l, loop);
    }

    lua_getglobal(l, "tcp");
    lua_getfield(l, -1, "connect_timeout");
    connect_timeout = lua_tointeger(l, -1);
    lua_pop(l, 2);

    ls_make_current_mthread_waiting(l, NULL, &client->mthread_ref0, connect_timeout);

    return lua_yield(l, 0);
}

static int tcp_server_accept(lua_State *l)
{
    tcp_udata_t *udata = server_udata(l);
    ls_tcp_t    *tcp   = udata->handle;

    /* server is closed already */
    if (tcp == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp server closed");

    ls_make_current_mthread_waiting(l, &tcp->mthread_queue, &tcp->mthread_ref0, udata->timeout);

    return lua_yield(l, 0);
}

static int tcp_server_close(lua_State *l)
{
    /* unref handle from tcp server userdata before any callback,
     * preventing dead loop in mthread
     * note: userdata may be GCed already when tcp_close_cb is called
     */

    tcp_udata_t *udata = server_udata(l);
    uv_handle_t *handle = (uv_handle_t*)udata->handle;
    if (handle)
    {
        udata->handle = NULL;
        udata->timeout = -1;
        uv_close(handle, tcp_close_cb);
    }
    return 0;
}

static int tcp_server_get_localip(lua_State *l)
{
    tcp_udata_t        *udata = server_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     sockname;
    int                 namelen = sizeof(sockname);
    struct sockaddr_in *sin = (struct sockaddr_in*)&sockname;
    char                ip[17];

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp server closed");
    
    if (uv_tcp_getsockname(&handle->handle, &sockname, &namelen))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "get sock name error");
    }
    
    if (uv_ip4_name(sin, ip, sizeof ip))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "invalid ipv4.");
    }

    lua_pushboolean(l, 1);
    lua_pushstring(l, ip);
    return 2;
}

static int tcp_server_get_localport(lua_State *l)
{
    tcp_udata_t        *udata = server_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     sockname;
    int                 namelen = sizeof(sockname);
    struct sockaddr_in *sin = (struct sockaddr_in*)&sockname;

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp server closed");
    
    if (uv_tcp_getsockname(&handle->handle, &sockname, &namelen))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "get sock name error");
    }
    
    lua_pushboolean(l, 1);
    lua_pushinteger(l, ntohs(sin->sin_port));
    return 2;
}

static int tcp_server_gc(lua_State *l)
{
    return tcp_server_close(l);
}

static int tcp_server_tostring(lua_State *l)
{
    tcp_udata_t        *udata = server_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     sockname;
    int                 namelen = sizeof(sockname);
    struct sockaddr_in *sin = (struct sockaddr_in*)&sockname;
    char                ip[17];

    if (handle == NULL)
        lua_pushliteral(l, "tcp server (closed)");
    else if (!uv_tcp_getsockname(&handle->handle, &sockname, &namelen) &&
             !uv_ip4_name(sin, ip, sizeof ip))
        lua_pushfstring(l, "tcp server (%s:%d)", ip, ntohs(sin->sin_port));
    else
        lua_pushliteral(l, "tcp server (invalid)");
    
    return 1;
}

static int tcp_read(lua_State *l)
{
    tcp_udata_t *udata = connection_udata(l);
    ls_tcp_t    *tcp   = udata->handle;

    if (tcp == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed.");

    ls_make_current_mthread_waiting(l, &tcp->mthread_queue, &tcp->mthread_ref0, udata->timeout);

    return lua_yield(l, 0);
}

static void tcp_write_cb(uv_write_t *req, int status)
{
    ls_write_t *write_req = (ls_write_t*)req;
    lua_State *l, *nl;
    int i;

    l = ls_default_state();
    for (i=0; i<write_req->refcnt; i++)
    {
        ls_unref(l, write_req->data_refs[i]);
        lua_pop(l, 1);
        write_req->data_refs[i] = LUA_NOREF;
    }
    write_req->refcnt = 0;

    nl = ls_mthread_unref(l, &write_req->mthread_ref0);

    if (nl)
    {
        ls_timer_stop(nl, 1);
        if (status)
            ls_last_error_resume(nl, req->handle->loop);
        else
            ls_ok_resume(nl);
        if (nl != l)
            lua_pop(l, 1);
    }
    ls_free(l, write_req);
}

static int tcp_write(lua_State *l)
{
    tcp_udata_t *udata  = connection_udata(l);
    ls_tcp_t    *tcp    = udata->handle;
    uv_stream_t *handle = (uv_stream_t *)&tcp->handle;
    uv_buf_t     bufs[MAX_WRITE_BUF_COUNT];
    int          refs[MAX_WRITE_BUF_COUNT];
    int          datacnt;
    int          i;
    ls_write_t   *write_req;

    if (tcp == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed.");

    datacnt = lua_gettop(l) - 1;

    if (datacnt > arraysize(bufs))
        return ls_error_return(l, LS_ERRCODE_ARGSIZE, "too much data to write.");
    else if (datacnt <= 0)
    {
        lua_pushboolean(l, 1);
        return 1;
    }

    for (i=0; i<datacnt; i++)
    {
        size_t len;
        const char *data = lua_tolstring(l, i+2, &len);
        if (data == NULL)
            return ls_error_return(l, LS_ERRCODE_INVAL, "invalid data to be writen: should be string or number");
        bufs[i] = uv_buf_init((char*)data, len);
    }

    // now, number in the stack has already been converted into string

    write_req = new_write_req(l);

    
    if (uv_write(&write_req->req, handle, bufs, datacnt, tcp_write_cb))
    {
        ls_free(l, write_req);
        return ls_last_error_return(l, handle->loop);
    }

    // make ref to the string
    for (i=0; i<datacnt; i++)
    {
        write_req->data_refs[i] = ls_ref_value(l, i+2);
    }

    write_req->refcnt = datacnt;

    // libuv make sure now tcp_write_cb is not called, even the data
    // has been writen already.
    ls_make_current_mthread_waiting(l, NULL, &write_req->mthread_ref0, udata->timeout);

    return lua_yield(l, 0);
}

static int tcp_close(lua_State *l)
{
    tcp_udata_t *udata = connection_udata(l);
    uv_handle_t *handle = (uv_handle_t*)udata->handle;
    if (handle)
    {
        udata->handle = NULL;
        udata->timeout = -1;
        uv_close(handle, tcp_close_cb);
    }
    return 0;
}

static int tcp_get_timeout(lua_State *l)
{
    tcp_udata_t *udata = connection_udata(l);
    lua_pushboolean(l, 1);
    lua_pushinteger(l, udata->timeout);
    return 2;
}

static int tcp_set_timeout(lua_State *l)
{
    tcp_udata_t *udata   = connection_udata(l);
    int          timeout = luaL_checkint(l, 2);
    udata->timeout = timeout;
    
    return 0;
}

static int tcp_keepalive(lua_State *l)
{
    tcp_udata_t        *udata = connection_udata(l);
    ls_tcp_t           *handle = udata->handle;
    int                 enable;
    int                 delay = 0;

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed");

    enable = lua_toboolean(l, 2);

    if (enable)
    {
        delay = luaL_checkint(l, 3);
        luaL_argcheck(l, delay>0, 3, "delay should be > 0");
    }
    
    if (uv_tcp_keepalive(&handle->handle, enable, (unsigned int)delay))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "set keepalive failed.");
    }
    
    lua_pushboolean(l, 1);
    return 1;
}

static int tcp_nodelay(lua_State *l)
{
    tcp_udata_t        *udata = connection_udata(l);
    ls_tcp_t           *handle = udata->handle;
    int                 enable;

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed");

    enable = lua_toboolean(l, 2);

    if (uv_tcp_nodelay(&handle->handle, enable))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "set nodelay failed.");
    }
    
    lua_pushboolean(l, 1);
    return 1;
}

static int tcp_get_localip(lua_State *l)
{
    tcp_udata_t        *udata = connection_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     sockname;
    int                 namelen = sizeof(sockname);
    struct sockaddr_in *sin = (struct sockaddr_in*)&sockname;
    char                ip[17];

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed");
    
    if (uv_tcp_getsockname(&handle->handle, &sockname, &namelen))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "get sock name error");
    }
    
    if (uv_ip4_name(sin, ip, sizeof ip))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "invalid ipv4.");
    }

    lua_pushboolean(l, 1);
    lua_pushstring(l, ip);
    return 2;
}

static int tcp_get_localport(lua_State *l)
{
    tcp_udata_t        *udata = connection_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     sockname;
    int                 namelen = sizeof(sockname);
    struct sockaddr_in *sin = (struct sockaddr_in*)&sockname;

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed");
    
    if (uv_tcp_getsockname(&handle->handle, &sockname, &namelen))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "get sock name error");
    }
    
    lua_pushboolean(l, 1);
    lua_pushinteger(l, ntohs(sin->sin_port));
    return 2;
}

static int tcp_get_peerip(lua_State *l)
{
    tcp_udata_t        *udata = connection_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     sockname;
    int                 namelen = sizeof(sockname);
    struct sockaddr_in *sin = (struct sockaddr_in*)&sockname;
    char                ip[17];

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed");
    
    if (uv_tcp_getpeername(&handle->handle, &sockname, &namelen))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "get sock name error");
    }
    
    if (uv_ip4_name(sin, ip, sizeof ip))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "invalid ipv4.");
    }

    lua_pushboolean(l, 1);
    lua_pushstring(l, ip);
    return 2;
}

static int tcp_get_peerport(lua_State *l)
{
    tcp_udata_t        *udata = connection_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     sockname;
    int                 namelen = sizeof(sockname);
    struct sockaddr_in *sin = (struct sockaddr_in*)&sockname;

    if (handle == NULL)
        return ls_error_return(l, LS_ERRCODE_EOF, "tcp connection closed");
    
    if (uv_tcp_getpeername(&handle->handle, &sockname, &namelen))
    {
        return ls_error_return(l, LS_ERRCODE_ERROR, "get sock name error");
    }
    
    lua_pushboolean(l, 1);
    lua_pushinteger(l, ntohs(sin->sin_port));
    return 2;
}

static int tcp_gc(lua_State *l)
{
    return tcp_close(l);
}

static int tcp_tostring(lua_State *l)
{
    tcp_udata_t        *udata = connection_udata(l);
    ls_tcp_t           *handle = udata->handle;
    struct sockaddr     lsockname, rsockname;
    int                 lnamelen = sizeof(lsockname);
    int                 rnamelen = sizeof(rsockname);
    struct sockaddr_in *lsin = (struct sockaddr_in*)&lsockname;
    struct sockaddr_in *rsin = (struct sockaddr_in*)&rsockname;
    char                lip[17], rip[17];

    if (handle == NULL)
        lua_pushliteral(l, "tcp connection (closed)");
    else if (!uv_tcp_getsockname(&handle->handle, &lsockname, &lnamelen) &&
             !uv_ip4_name(lsin, lip, sizeof lip) &&
             !uv_tcp_getpeername(&handle->handle, &rsockname, &rnamelen) &&
             !uv_ip4_name(rsin, rip, sizeof rip))
        lua_pushfstring(l, "tcp connection (local: %s:%d, remote: %s:%d)", lip, ntohs(lsin->sin_port), rip, ntohs(rsin->sin_port));
    else
        lua_pushliteral(l, "tcp connection (invalid)");
    
    return 1;
}

static const luaL_Reg tcp_lib[] = {
    {"createServer", tcp_create_server},
    {"createClient", tcp_create_client},
    {NULL, NULL}
};

static const luaL_Reg tcp_server_lib[] = {
    {"accept", tcp_server_accept},
    {"close", tcp_server_close},
    {"getLocalIP", tcp_server_get_localip},
    {"getLocalPort", tcp_server_get_localport},
    {"__gc", tcp_server_gc},
    {"__tostring", tcp_server_tostring},
    {NULL, NULL}
};

static const luaL_Reg tcp_connection_lib[] = {
    {"read", tcp_read},
    {"write", tcp_write},
    {"close", tcp_close},
    {"getTimeout", tcp_get_timeout},
    {"setTimeout", tcp_set_timeout},
    {"keepalive", tcp_keepalive},
    {"nodelay", tcp_nodelay},
    {"getLocalIP", tcp_get_localip},
    {"getLocalPort", tcp_get_localport},
    {"getPeerIP", tcp_get_peerip},
    {"getPeerPort", tcp_get_peerport},
    {"__gc", tcp_gc},
    {"__tostring", tcp_tostring},
    {NULL, NULL}
};

LUAMOD_API int luaopen_tcp(lua_State *l)
{
    luaL_newlib(l, tcp_lib);
    lua_pushinteger(l, 30*1000);
    lua_setfield(l, -2, "connect_timeout");

    ls_create_metatable(l, TCP_SERVER, tcp_server_lib);
    ls_create_metatable(l, TCP_CONNECTION, tcp_connection_lib);

    return 1;
}

