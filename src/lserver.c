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

    l = ls_default_state();

    luaL_openlibs(l);

    ls_openlibs(l);

    if (argc == 2)
    {
        luaL_loadfile(l, argv[1]);
        lua_resume(l, NULL, 0);
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    
    return 0;
}
