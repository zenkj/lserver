#ifndef ls_luaconf_h
#define ls_luaconf_h

#include "ls-lstate-extra.h"

/* definition for lua. lua's compilation needs the following */
#define LUAI_EXTRASPACE (sizeof(ls_thread_extra_t))

#define luai_userstateopen(l)          userstate_init(l)
#define luai_userstateclose(l)         userstate_clean(l)
#define luai_userstatethread(l, l1)    userstate_init(l1)
#define luai_userstatefree(l, l1)      userstate_clean(l1)

#endif // ls_luaconf_h
