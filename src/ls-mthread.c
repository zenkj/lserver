#include "lserver.h"

static int mthread_sleep(lua_State *l)
{
    int timeout = luaL_checkint(l, 1);
    luaL_argcheck(l, timeout >= 0, 1, "sleep time should >= 0");

    ls_timer_start(l, timeout);

    return lua_yield(l, 0);
}

static int mthread_wakeup(lua_State *l)
{
    lua_State *nl = lua_tothread(l, 1);
    luaL_argcheck(l, nl, 1, "mthread should be specified to wakeup");

    if (LUA_YIELD == lua_status(nl))
    {
        ls_timer_stop(nl);
        ls_error_resume(nl, LS_ERRCODE_INTERRUPT, "wake up by others");
    }
    return 0;
}

static const luaL_Reg mthread_lib[] = {
    {"sleep", mthread_sleep},
    {"wakeup", mthread_wakeup},
    {NULL, NULL}
};

LUAMOD_API int luaopen_mthread(lua_State *l)
{
    luaL_newlib(l, mthread_lib);
    return 1;
}

