#include "lserver.h"

#include <stdlib.h>

void *ls_malloc(lua_State *l, size_t size)
{
    void *data = malloc(size);
    if (!data)
        luaL_error(l, "no enough memory");
    return data;
}

void ls_free(lua_State *l, void *data)
{
    free(data);
}

void ls_error_resume(lua_State *l, int code, const char *msg)
{
    lua_pushboolean(l, 0);
    lua_newtable(l);
    lua_pushinteger(l, code);
    lua_setfield(l, -2, "code");
    lua_pushstring(l, msg);
    lua_setfield(l, -2, "msg");
    lua_resume(l, NULL, 2);
}

void ls_last_error_resume(lua_State *l, uv_loop_t *loop)
{
    uv_err_t err = uv_last_error(loop);
    ls_error_resume(l, err.code, uv_strerror(err));
}

void ls_ok_resume(lua_State *l)
{
    lua_pushboolean(l, 1);
    lua_resume(l, NULL, 1);
}

int ls_error_return(lua_State *l, int code, const char *msg)
{
    lua_pushboolean(l, 0);
    lua_newtable(l);
    lua_pushinteger(l, code);
    lua_setfield(l, -2, "code");
    lua_pushstring(l, msg);
    lua_setfield(l, -2, "msg");
    return 2;
}

int ls_last_error_return(lua_State *l, uv_loop_t *loop)
{
    uv_err_t err = uv_last_error(loop);
    return ls_error_return(l, err.code, uv_strerror(err));
}

int ls_ok_return(lua_State *l)
{
    lua_pushboolean(l, 1);
    return 1;
}

void ls_create_metatable(lua_State *l, const char *name, const luaL_Reg *lib)
{
    luaL_newmetatable(l, name);
    lua_pushvalue(l, -1);
    lua_setfield(l, -2, "__index");
    luaL_setfuncs(l, lib, 0);
    lua_pop(l, 1);
}

/* TODO is it better to create a ls_mthread_ref_queue_t type?
 * this type will include mthread_ref0
 * TODO this method is not efficient, should improve.
 */
void ls_make_current_mthread_waiting(lua_State *l, ngx_queue_t *mthread_queue, ls_mthread_ref_t *mthref, int timeout)
{
    if (mthread_queue)
    {
        /* TODO is this suitable?? */
        if (!ngx_queue_empty(mthread_queue))
            mthref = NULL;
        mthref = ls_mthread_enqueue(l, mthread_queue, mthref);
    }

    if (timeout >= 0)
    {
        ls_timer_start(l, timeout, mthref);
    }

    if (mthref)
    {
        /* make sure thread is refed even when mthread_queue
         * is null, and no timer is set
         */
        ls_mthread_ref(l, mthref);
    }
}

int ls_ref_value(lua_State *l, int value)
{
    lua_pushvalue(l, value);
    return luaL_ref(l, LUA_REGISTRYINDEX);
}

int ls_ref(lua_State *l)
{
    return luaL_ref(l, LUA_REGISTRYINDEX);
}

void ls_unref(lua_State *l, int ref)
{
    lua_rawgeti(l, LUA_REGISTRYINDEX, ref);
    luaL_unref(l, LUA_REGISTRYINDEX, ref);
}

