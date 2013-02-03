#include "lserver.h"
#include "lua/ls-state-extra.h"
#include <assert.h>

static void timer_cb(uv_timer_t *handle, int status)
{
    lua_State *l, *nl = NULL;
    ls_timer_t *timer = containerof(handle, ls_timer_t, handle);
    ls_wait_object_t *wait_object = &timer->wait_object;
    int ref = wait_object->mthread_ref;

    wait_object->mthread_ref = LUA_NOREF;

    l = ls_default_state();

    if (ref >= 0)
    {
        ls_getref(l, ref);
        nl = lua_tothread(l, -1);
        lua_pop(l, 1);
        if (nl)
        {
            ls_state_extra_t *extra = state2extra(nl);
            if (extra->wait_object)
            {
                int r = extra->wait_object->mthread_ref;
                extra->wait_object->mthread_ref = LUA_NOREF;
                extra->wait_object = NULL;
                ls_unref(l, r);
            }
            ls_error_resume(nl, LS_ERRCODE_TIMEOUT, "timeout");
        }
        ls_unref(l, ref);
    }
}

void ls_timer_start(lua_State *l, int timeout)
{
    ls_state_extra_t  *extra = state2extra(l);
    ls_timer_t        *timer = extra->timer;

    if (timeout < 0)
        return;

    if (timer == NULL)
    {
        timer = extra->timer = (ls_timer_t *)ls_malloc(l, sizeof(ls_timer_t));
        uv_timer_init(uv_default_loop(), &timer->handle);
    }

    lua_pushthread(l);
    timer->wait_object.mthread_ref = ls_ref(l);

    uv_timer_start(&timer->handle, timer_cb, timeout, 0);
}

void ls_timer_stop(lua_State *l)
{
    ls_state_extra_t *extra = state2extra(l);
    ls_timer_t *timer = extra->timer;
    int ref;
    if (timer == NULL)
        return;

    uv_timer_stop(&timer->handle);

    ref = timer->wait_object.mthread_ref;

    if (ref == LUA_NOREF)
        return;

    timer->wait_object.mthread_ref = LUA_NOREF;

    ls_unref(l, ref);
}

static void timer_close_cb(uv_handle_t *handle)
{
    ls_timer_t *timer = containerof(handle, ls_timer_t, handle);
    ls_free(ls_default_state(), timer);
}

void ls_timer_close(lua_State *l)
{
    ls_state_extra_t *extra = state2extra(l);
    ls_timer_t        *timer = extra->timer;
    if (timer == NULL)
        return;

    /* no need to call ls_mthread_unref, because when this
     * function is called, all reference must have already
     * been released.
     */
    uv_close((uv_handle_t*)&timer->handle, timer_close_cb);
    extra->timer = NULL;
}

