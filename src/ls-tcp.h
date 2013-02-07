#ifndef ls_tcp_h
#define ls_tcp_h

#include "lserver.h"
/* object in C */
typedef struct ls_tcp_s
{
    ls_wait_object_t wait_object;
    uv_tcp_t         handle;
} ls_tcp_t;

#endif
