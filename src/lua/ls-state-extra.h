#ifndef ls_state_extra_h
#define ls_state_extra_h


/* this file will be included in luaconf.h, when it's included,
 * lua_State struct is not declared then, so lua_State typedef is useless
 */
struct ls_timer_s;
struct ls_wait_object_s;

typedef struct ls_state_extra_s
{
    struct ls_wait_object_s  *wait_object;
    struct ls_timer_s        *timer;
} ls_state_extra_t;

#define state2extra(l) ((ls_state_extra_t*)(l) - 1)

struct lua_State;
void userstate_init(struct lua_State *l);
void userstate_clean(struct lua_State *l);

#endif // ls_state_extra_h
