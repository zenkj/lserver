#include "lserver.h"
#include <stdlib.h>
#include <stdio.h>

static lua_State *default_lua_state = NULL;

lua_State *ls_default_state()
{
    if (default_lua_state != NULL)
        return default_lua_state;

    default_lua_state = luaL_newstate();
    if (default_lua_state == NULL)
    {
        fprintf(stderr, "no enough memory\n");
        exit(-1);
    }

    return default_lua_state;
}

static void ls_openlibs(lua_State *l)
{
    luaL_requiref(l, "mthread", luaopen_mthread, 1);
    lua_pop(l, 1);
    luaL_requiref(l, "tcp", luaopen_tcp, 1);
    lua_pop(l, 1);
}

int main(int argc, char *argv[])
{

    lua_State *l;
    int result = 0;

    l = ls_default_state();

    luaL_openlibs(l);

    ls_openlibs(l);

    if (argc != 2)
    {
        fprintf(stderr, "a lua file should specified\n");
        return -1;
    }

    result = luaL_loadfile(l, argv[1]);
    if (result != LUA_OK)
    {
        const char *msg = lua_tostring(l, -1);
        fprintf(stderr, "load lua file %s error: %s\n", argv[1], msg);
        return -1;
    }

    result = ls_resume(l, 0);
    while (result == LUA_YIELD)
    {
        result = uv_run(uv_default_loop(), UV_RUN_ONCE);
        if (result == 0)
            break;
        result = lua_status(l);
    }

    if (result != LUA_OK)
    {
        const char *msg = lua_tostring(l, -1);
        fprintf(stderr, "execute lua file %s error: %s\n", argv[1], msg);
        return -1;
    }
    
    return result;
}
