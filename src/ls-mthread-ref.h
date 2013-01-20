#ifndef mthread_ref_h
#define mthread_ref_h

#include "ngx-queue.h"
#include <lua.h>

typedef struct ls_mthread_ref_s
{
    int           mthread_ref;
    int           need_free;
    ngx_queue_t   mthread_queue;
} ls_mthread_ref_t;

/* get mthread ref from the queue, then unref it from lua registry.
 * push the mthread on stack, then return it.
 */
lua_State *ls_mthread_dequeue(lua_State *l, ngx_queue_t *mthread_queue);

/* make ref to the current mthread in the registry,
 * then create ls_mthread_ref_t, add it to the specified mthread_queue.
 * return the created ls_mthread_ref_t.
 */
ls_mthread_ref_t *ls_mthread_enqueue(lua_State *l, ngx_queue_t *mthread_queue, ls_mthread_ref_t *mthread_ref);

ls_mthread_ref_t *ls_mthread_ref(lua_State *l, ls_mthread_ref_t *mthread_ref);

lua_State *ls_mthread_unref(lua_State *l, ls_mthread_ref_t *data);

ls_mthread_ref_t *ls_mthread_ref_new(lua_State *l);

void ls_mthread_ref_del(lua_State *l, ls_mthread_ref_t *mthread_ref);

void ls_mthread_ref_init(ls_mthread_ref_t *mthread_ref, int need_free);

#endif
