#ifndef IO_HANDLER_H
#define IO_HANDLER_H

#include <event.h>

#include "session_manager.h"

#define DCMM_MQTT_MSG_MASK 0xf0
#define DCMM_MQTT_MSG_CONNECT 0x10
#define DCMM_MQTT_MSG_DISCONNECT 0xe0

struct session;

void io_init();
void io_destroy();
void try_to_connect(struct session *session);
int send_reply(session_t *session, void *buff, uint32_t size);

#endif
