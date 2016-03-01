#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <time.h>
#include <sys/queue.h>
#include <netinet/in.h>

#include <event.h>
#include <openssl/ssl.h>

#include "mem_cache.h"
#include "../lib/dcmm.h"

#define PRI_TYPE_SIZE 3

struct message;
struct dcmm_status;
struct dcmm_register_info;

typedef enum client_state {
    cs_new,
    cs_connected,
    cs_disconnected,
} client_state_t;

typedef enum server_state {
    ss_new,
    ss_connecting,
    ss_waiting_to_connect,
    ss_connection_failed,
    ss_connected,
    ss_interrupted,
    ss_disconnected,//normal disconnect
} server_state_t;

typedef struct session {
    uint32_t id;
    char dest_ip[DCMM_IP_SIZE];
    uint16_t dest_port;
    client_state_t client_state;
    server_state_t server_state;
    int priority;

    uint32_t count_msg_cache;// number of msg in cache
    uint32_t count_msg_db;// number of msg in db

    int protocol;
    struct message *conn_msg;

    SSL *ssl;
    SSL_CTX *ssl_ctx;
    char *tls_cafile;
    char *tls_capath;
    char *tls_certfile;
    char *tls_keyfile;

    struct message *curr_msg;
    int conn_id;
    /* timeval */
    struct timeval conn_wait_tv;//the time it should wait before connecting to server
    /* attributes for client */
    int control_sd;
    struct event *client_read_ev;
    /* attributes for server */
    struct bufferevent *server_conn_ev;
    struct event *timer_ev;//for connection or sending relay
    struct event *server_read_ev;
    struct event *server_write_ev;
    /* pointers for this session's messages */
    struct message *msgs_head;//the first msg of this session in the cache
    struct message *msgs_tail;//the last msg of this session in the cache
    /* pointers for session queue */
    struct session *session_next;//the next session in the same session queue
    struct session *session_prev;//the previous session in the same session queue
    /* pointers for app queue */
    //struct session *app_next;//the next session of the same app
    //struct session *app_prev;//the previous session of the same app
    SLIST_ENTRY(session) entries;
} session_t;

typedef struct session_queue {
    struct session *sessions_head;
    struct session *sessions_tail;
    uint32_t length;//the number of sessions in this queue
} session_queue_t;

void session_init();
void session_destroy();
void session_add(struct session *session);
void session_remove(struct session *session);
void session_close_client(struct session *session);
void session_close_server(struct session *session);
uint32_t session_count();
void session_status(struct session *session, struct dcmm_status *status);
struct session *session_get(uint32_t id);
void session_update_info(struct session *session, struct dcmm_register_info *info);

#endif
