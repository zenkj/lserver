#include "lserver.h"
#include "lua/ls-lstate-extra.h"

static void timer_cb(uv_timer_t *handle, int status)
{
    lua_State *l, *nl = NULL;
    ls_mthread_ref_t *mthread_ref;
    ls_timer_t *timer = (ls_timer_t*)handle;

    l = ls_default_state();

    if (timer->mthread_ref)
        nl = ls_mthread_unref(l, timer->mthread_ref);

    timer->mthread_ref = NULL;

    if (nl)
        ls_error_resume(nl, LS_ERRCODE_TIMEOUT, "timeout");
}

void ls_timer_start(lua_State *l, int timeout, ls_mthread_ref_t *mthread_ref)
{
    ls_thread_extra_t *extra = state2extra(l);
    ls_timer_t        *timer = extra->timer;

    if (timeout < 0)
        return;

    if (timer == NULL)
    {
        timer = extra->timer = (ls_timer_t *)ls_malloc(l, sizeof(ls_timer_t));
        uv_timer_init(uv_default_loop(), &timer->handle);
        ls_mthread_ref_init(&timer->mthread_ref0, 0);
    }

    if (mthread_ref)
        timer->mthread_ref = mthread_ref;
    else
        timer->mthread_ref = &timer->mthread_ref0;

    ls_mthread_ref(l, timer->mthread_ref);

    uv_timer_start(&timer->handle, timer_cb, timeout, 0);
}

void ls_timer_stop(lua_State *l, int iofinished)
{
    ls_thread_extra_t *extra = state2extra(l);
    ls_timer_t *timer = extra->timer;
    if (timer == NULL)
        return;

    uv_timer_stop(&timer->handle);

    if (!timer->mthread_ref)
        return;

    /* when io finished, mthread_ref is managed outside, so no need to unref it */
    if (!iofinished || timer->mthread_ref == &timer->mthread_ref0)
        ls_mthread_unref(l, timer->mthread_ref);
    
    timer->mthread_ref = NULL;
}

static void timer_close_cb(uv_handle_t *handle)
{
    ls_free(ls_default_state(), handle);
}

void ls_timer_close(lua_State *l)
{
    ls_thread_extra_t *extra = state2extra(l);
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

