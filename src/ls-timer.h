#ifndef ls_timer_h
#define ls_timer_h

#include <lua.h>
#include <uv.h>
#include "ls-mthread-ref.h"

typedef struct ls_timer_s
{
    uv_timer_t        handle;
    ls_mthread_ref_t  mthread_ref0;
    ls_mthread_ref_t *mthread_ref;
} ls_timer_t;

void ls_timer_start(lua_State *l, int timeout, ls_mthread_ref_t *mthread_ref);
void ls_timer_stop(lua_State *l, int iofinished);
void ls_timer_close(lua_State *l);

#endif // ls_timer_h
