#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include "session_manager.h"

typedef enum network_state {
    ns_normal,
    ns_down,
    ns_congested,
} network_state_t;

void connection_init();
void connection_destroy();
network_state_t connection_network_state();
void connection_start(struct session *session);
void connection_failed(struct session *session);
void connection_succeed(struct session *session);
void connection_closed(struct session *session);
void connection_interrupted(struct session *session);

#endif
