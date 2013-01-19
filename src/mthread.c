#include "lserver.h"

static int mthread_sleep(lua_State *l)
{
    int timeout = luaL_checkint(l, 1);
    luaL_checkarg(l, timeout >= 0, "sleep time should >= 0");

    ls_timer_start(l, timeout, NULL);

    return lua_yield(l, 0);
}

static const luaL_Reg mthread_lib[] = {
    {"sleep", mthread_sleep},
    {NULL, NULL}
};

LUAMOD_API int luaopen_mthread(lua_State *l)
{
    luaL_newlib(l, tcplib);
    return 1;
}

