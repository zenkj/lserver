#ifndef ls_timer_h
#define ls_timer_h

#include <lua.h>
#include <uv.h>
#include "ls-wait-object.h"

typedef struct ls_timer_s
{
    ls_wait_object_t  wait_object;
    uv_timer_t        handle;
} ls_timer_t;

void ls_timer_start(lua_State *l, int timeout);
void ls_timer_stop(lua_State *l);
void ls_timer_close(lua_State *l);

#endif // ls_timer_h
