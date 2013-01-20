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

int main(int argc, char *argv[])
{
    
    return 0;
}
