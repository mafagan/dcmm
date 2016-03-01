#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>
#include "../lib/dcmm_utils.h"

void thread_pool_init();
void thread_pool_destroy();
void thread_pool_add_task(void (*func)(void *), void *arg);

#endif
