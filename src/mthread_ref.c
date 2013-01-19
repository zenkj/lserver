#include "lserver.h"

void ls_mthread_ref_init(ls_mthread_ref_t *mthread_ref, int need_free)
{
    mthread_ref->mthread_ref = LUA_NOREF;
    mthread_ref->need_free = need_free;
    ngx_queue_init(&mthread_ref->mthread_queue);
}

ls_mthread_ref_t *ls_mthread_ref_new(lua_State *l)
{
    ls_mthread_ref_t *mthread_ref = (ls_mthread_ref_t*)ls_malloc(l, sizeof(ls_mthread_ref_t));

    ls_mthread_ref_init(mthread_ref, 1);

    return mthread_ref;
}

void ls_mthread_ref_del(lua_State *l, ls_mthread_ref_t *mthread_ref)
{
    ngx_queue_remove(&mthread_ref->mthread_queue);
    mthread_ref->mthread_ref = LUA_NOREF;
    if (mthread_ref->need_free)
        ls_free(l, mthread_ref);
}

ls_mthread_ref_t *ls_mthread_ref(lua_State *l, ls_mthread_ref_t *mthread_ref)
{
    if (mthread_ref == NULL)
        mthread_ref = ls_mthread_ref_new(l);

    if (mthread_ref->mthread_ref == LUA_NOREF)
    {
        lua_pushthread(l);
        mthread_ref->mthread_ref = ls_ref(l);
    }

    return mthread_ref;
}

lua_State *ls_mthread_unref(lua_State *l, ls_mthread_ref_t *mthread_ref)
{
    lua_State *nl;
    int        ref;

    if (mthread_ref == NULL)
        return NULL;
    ref = mthread_ref->mthread_ref;

    ls_mthread_ref_del(mthread_ref);

    ls_unref(l, ref);

    nl = lua_tothread(l, -1);

    if (!nl) lua_pop(l, 1);

    return nl;
}

lua_State *ls_mthread_dequeue(lua_State *l, ngx_queue_t *mthread_queue)
{
    ngx_queue_t      *mth;
    ls_mthread_ref_t *mthread_ref;
    lua_State        *nl;
    if (ngx_queue_empty(mthread_queue))
        return NULL;

    mth = ngx_queue_head(mthread_queue);

    mthread_ref = ngx_queue_data(mth, ls_mthread_ref_t, mthread_queue);

    return ls_mthread_unref(l, data);
}

ls_mthread_ref_t *ls_mthread_enqueue(lua_State *l, ngx_queue_t *mthread_queue, ls_mthread_ref_t *mthread_ref)
{
    mthread_ref = ls_mthread_ref(l, mthread_ref);

    ngx_queue_insert_tail(mthread_queue, &mthread_ref->mthread_queue);

    return mthread_ref;
}

