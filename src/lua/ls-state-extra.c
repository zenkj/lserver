#include "lserver.h"

void userstate_init(lua_State *l)
{
    ls_state_extra_t *extra = state2extra(l);
    extra->wait_object = NULL;
    extra->timer = NULL;
}

void userstate_clean(lua_State *l)
{
    ls_state_extra_t *extra = state2extra(l);

    if (extra->wait_object != NULL)
    {
        int ref = extra->wait_object->mthread_ref;
        extra->wait_object->mthread_ref = LUA_NOREF;
        ls_unref(l, ref);

        extra->wait_object = NULL;
    }

    ls_timer_close(l);
}


