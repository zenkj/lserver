#ifndef lstate_extra_h
#define lstate_extra_h


/* this file will be included in luaconf.h, when it's included,
 * lua_State struct is not declared then, so lua_State typedef is useless
 */
typedef struct ls_timer_s ls_timer_t;

typedef struct ls_thread_extra_s
{
    ls_timer_t *timer;
} ls_thread_extra_t;

#define state2extra(l) ((ls_thread_extra_t*)l - 1)

typedef struct lua_State  lua_State;
void userstate_init(lua_State *l);
void userstate_clean(lua_State *l);

#endif // lstate_extra_h
