#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <sys/time.h>

#include "session_manager.h"
#include "mem_cache.h"
#include "memory_pool.h"

#define CAN_SEND 1
#define CAN_NOT_SEND 2
#define LACK_CREDIT 3

struct session;
struct message;

void scheduler_init();
void scheduler_destroy();
bool scheduler_can_session_connect(struct session *session);
int scheduler_can_session_send(struct session *session);
int scheduler_send(struct session *session, struct message *msg);
struct timeval scheduler_get_wait_time(struct session *session);
void scheduler_increase_connect_wait_time(struct session *session);
void scheduler_update_credit();


#endif
