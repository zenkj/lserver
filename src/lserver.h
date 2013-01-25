#ifndef _LSERVER_H_
#define _LSERVER_H_

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <uv.h>

#include "ls-mthread-ref.h"

#include "ls-timer.h"

#define LS_ERRCODE_ERROR -1
#define LS_ERRCODE_EOF -2
#define LS_ERRCODE_TIMEOUT -3
#define LS_ERRCODE_ADDRESS_USED -4
#define LS_ERRCODE_ARGSIZE -5
#define LS_ERRCODE_INTERRUPT -6
#define LS_ERRCODE_INVAL -7

#define containerof(data, type, member) ((type*)((unsigned char*)data - offsetof(type, member)))
#define arraysize(a) (sizeof(a) / sizeof((a)[0]))

lua_State *ls_default_state();
void      *ls_malloc(lua_State *l, size_t size);
void       ls_free(lua_State *l, void *data);
int        ls_resume(lua_State *l, int nargs);
void       ls_error_resume(lua_State *l, int code, const char *msg);
void       ls_last_error_resume(lua_State *l, uv_loop_t *loop);
void       ls_ok_resume(lua_State *l);
int        ls_error_return(lua_State *l, int code, const char *msg);
int        ls_last_error_return(lua_State *l, uv_loop_t *loop);
int        ls_ok_return(lua_State *l);
void       ls_create_metatable(lua_State *l, const char *name, const luaL_Reg *lib);
void       ls_make_current_mthread_waiting(lua_State *l, ngx_queue_t *mthread_queue, ls_mthread_ref_t *mthref, int timeout);
int        ls_ref_value(lua_State *l, int value);
int        ls_ref(lua_State *l);
void       ls_unref(lua_State *l, int ref);

/* libraries */

LUAMOD_API int luaopen_mthread(lua_State *l);
LUAMOD_API int luaopen_tcp(lua_State *l);


#endif //_LSERVER_H_
