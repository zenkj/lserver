#include "lserver.h"

#include <stdlib.h>
#include <assert.h>

void *ls_malloc(lua_State *l, size_t size)
{
    void *data = malloc(size);
    if (!data)
        luaL_error(l, "no enough memory");
    return data;
}

void ls_free(lua_State *l, void *data)
{
    (void)l;
    free(data);
}

int ls_resume(lua_State *l, int nargs)
{
    int result = lua_resume(l, NULL, nargs);
    if (result != LUA_OK && result != LUA_YIELD)
    {
        luaL_error(l, lua_tostring(l, -1));
    }
    return result;
}

int ls_error_resume(lua_State *l, int code, const char *msg)
{
    lua_pushboolean(l, 0);
    lua_newtable(l);
    lua_pushinteger(l, code);
    lua_setfield(l, -2, "code");
    lua_pushstring(l, msg);
    lua_setfield(l, -2, "msg");
    return ls_resume(l, 2);
}

int ls_last_error_resume(lua_State *l, uv_loop_t *loop)
{
    uv_err_t err = uv_last_error(loop);
    return ls_error_resume(l, err.code, uv_strerror(err));
}

int ls_ok_resume(lua_State *l)
{
    lua_pushboolean(l, 1);
    return ls_resume(l, 1);
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

void ls_set_waiting(lua_State *l, ls_wait_object_t *wait_object, int timeout)
{
    ls_state_extra_t *extra = state2extra(l);
    assert(extra->wait_object == NULL);
    assert(!ls_object_is_waited(&extra->timer->wait_object));
    if (wait_object)
    {
        lua_pushthread(l);
        wait_object->mthread_ref = ls_ref(l);
        extra->wait_object = wait_object;
    }

    if (timeout >= 0)
    {
        ls_timer_start(l, timeout);
    }
}

void ls_clear_waiting(lua_State *l)
{
    ls_state_extra_t *extra = state2extra(l);
    if (extra->wait_object)
    {
        ls_unref(l, extra->wait_object->mthread_ref);
        extra->wait_object->mthread_ref = LUA_NOREF;
        extra->wait_object = NULL;
    }

    ls_timer_stop(l);
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

void ls_getref(lua_State *l, int ref)
{
    lua_rawgeti(l, LUA_REGISTRYINDEX, ref);
}

void ls_unref(lua_State *l, int ref)
{
    luaL_unref(l, LUA_REGISTRYINDEX, ref);
}

void ls_wait_object_init(ls_wait_object_t *wait_object)
{
    wait_object->mthread_ref = LUA_NOREF;
}

int ls_object_is_waited(ls_wait_object_t *wait_object)
{
    if (wait_object == NULL)
        return 0;
    if (wait_object->mthread_ref >= 0)
        return 1;
    return 0;
}

