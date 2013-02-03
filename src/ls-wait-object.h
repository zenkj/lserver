#ifndef ls_wait_object_h
#define ls_wait_object_h

typedef struct ls_wait_object_s {
    int mthread_ref;
} ls_wait_object_t;

void ls_wait_object_init(ls_wait_object_t *wait_object);
int ls_object_is_waited(ls_wait_object_t *wait_object);

#endif //ls_wait_object_h

