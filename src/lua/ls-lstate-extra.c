#include "ls-lstate-extra.h"
#include "ls-timer.h"

void userstate_init(lua_State *l)
{
    ls_thread_extra_t *extra = state2extra(l);
    extra->timer = NULL;
}

void userstate_clean(lua_State *l)
{
    ls_timer_close(l);
}


