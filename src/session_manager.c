#include <unistd.h>
#include <event.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/ssl.h>

#include "logging.h"
#include "session_manager.h"
#include "mem_cache.h"
#include "memory_pool.h"


/* queues for different priority sessions,
 * 0 or sp_platinum for Platinum
 * 1 or sp_gold for Gold
 * 2 or sp_silver for Silver
 * priority     0   session_1 -> session_2 -> NULL
 *                  head         tail
 *              1   session_3 -> NULL
 *                  head tail
 *              2   session_4 -> NULL
 *                  head tail
 */
session_queue_t sessions[PRI_TYPE_SIZE];

static void list_session();
static void remove_session_from_list(session_t *session);
/**
 * Initialize all data structures related to session management
 *
 * @param size the size of the session pool
 */
void session_init()
{
    log_debug("Initialize the `session_manager` module");
    syslog_debug("Initialize the `session_manager` module");
    uint32_t i;
    for (i = 0; i < (sizeof(sessions)/sizeof(session_queue_t)); ++ i) {
        sessions[i].sessions_head = sessions[i].sessions_tail = NULL;
        sessions[i].length= 0;
    }
}
/**
 * Destroy all data structures related to session management
 */
void session_destroy()
{
    log_debug("Destroy the `session_manager` module");
    syslog_debug("Destroy the `session_manager` module");
    uint32_t i;
    /* return all sessions back to the pool */
    for (i = 0; i < 3; ++ i) {
        while (sessions[i].sessions_head != NULL) {
            session_remove(sessions[i].sessions_head);
        }
    }
}
/**
 * Add a session into the sessions structure
 *
 * @param session the session will we add
 */
void session_add(session_t *session)
{
    assert(session);
    log_debug("Add session(%d)", session->id);
    syslog_debug("Add session(%d)", session->id);
    int sp = session->priority;
    /* in case of array boundary */
    assert(sp == DCMM_PRIORITY_PLATINUM || sp == DCMM_PRIORITY_GOLD ||
            sp == DCMM_PRIORITY_SILVER);
    /* already have some sessions of the same priority
     * append to the back */
    if (sessions[sp].sessions_tail != NULL) {
        sessions[sp].sessions_tail->session_next = session;
        session->session_prev = sessions[sp].sessions_tail;
        session->session_next = NULL;
        sessions[sp].sessions_tail = session;
    }
    /* the first session of this priority */
    else {
        sessions[sp].sessions_head = sessions[sp].sessions_tail = session;
        session->session_next = session->session_prev = NULL;
    }
    ++ sessions[sp].length;
}
static void remove_session_from_list(session_t *session)
{
    log_debug("Remove session(%d) from list", session->id);
    syslog_debug("Remove session(%d) from list", session->id);
    int sp = session->priority;
    /* se -> se_del -> se -> ... -> NULL */
    if (session->session_prev != NULL && session->session_next != NULL) {
        session->session_prev->session_next = session->session_next;
        session->session_next->session_prev = session->session_prev;
    }
    /* se -> se_del -> NULL
     * the tail of sessions will change! */
    else if (session->session_prev != NULL && session->session_next == NULL) {
        session->session_prev->session_next = NULL;
        sessions[sp].sessions_tail = session->session_prev;
    }
    /* se_del -> se -> ... -> NULL
     * the head of this sessions will change! */
    else if (session->session_prev == NULL && session->session_next != NULL) {
        session->session_next->session_prev = NULL;
        sessions[sp].sessions_head = session->session_next;
    }
    /* se_del -> NULL
     * only one session in the sessions of this priority
     * the head and tail of this sessions will change! */
    else {
        sessions[sp].sessions_head = sessions[sp].sessions_tail = NULL;
    }
    session->session_prev = session->session_next = NULL;
    -- sessions[sp].length;
}
/**
 * Remove a session from the sessions structure
 *
 * @param session the session we will remove
 */
void session_remove(session_t *session)
{
    assert(session);
    log_debug("Remove session(%d)", session->id);
    syslog_debug("Remove session(%d)", session->id);
    int sp = session->priority;
    /* in case of array boundary */
    assert(sp == DCMM_PRIORITY_PLATINUM || sp == DCMM_PRIORITY_GOLD ||
            sp == DCMM_PRIORITY_SILVER);
    remove_session_from_list(session);

    if (session->conn_msg != NULL) {
        free(session->conn_msg);
    }
    if (session->timer_ev) {
        event_free(session->timer_ev);
    }
    if (session->tls_cafile) {
        free(session->tls_cafile);
    }
    if (session->tls_capath) {
        free(session->tls_capath);
    }
    if (session->tls_certfile) {
        free(session->tls_certfile);
    }
    if (session->tls_keyfile) {
        free(session->tls_keyfile);
    }
    if (session->ssl) {
        SSL_free(session->ssl);
    }
    if (session->ssl_ctx) {
        SSL_CTX_free(session->ssl_ctx);
    }
    session_close_client(session);
    session_close_server(session);
    // return_block will set session's all attributes to 0(NULL)
    return_session_block(session);
}
/**
 * Close client, including freeing event, closing socket descriptor
 *
 * @param session the session we will close
 */
void session_close_client(session_t *session)
{
    assert(session);
    int client_sd;
    if (session->client_read_ev) {
        log_debug("Close client(%d)", session->id);
        syslog_debug("Close client(%d)", session->id);
        client_sd = session->client_read_ev->ev_fd;
        event_del(session->client_read_ev);
        event_free(session->client_read_ev);
        session->client_read_ev = NULL;
        if (client_sd >= 0) {
            evutil_closesocket(client_sd);
        }
    }
    session->client_state = cs_disconnected;
}
/**
 * Close server, including freeing event, closing socket descriptor
 * Note that, in `session_close_client`, we change the `client_state`
 * but in `session_close_server`, we don't change the `server_state`, because we
 * will change it in the `connection_manager` module
 *
 * @param session the session we will close
 */
void session_close_server(session_t *session)
{
    assert(session);
    int server_sd;
    if (session->server_conn_ev) {
        log_debug("Close server of client(%d)", session->id);
        syslog_debug("Close server of client(%d)", session->id);
        server_sd = bufferevent_getfd(session->server_conn_ev);
        if (session->server_read_ev) {
            event_del(session->server_read_ev);
            event_free(session->server_read_ev);
            session->server_read_ev = NULL;
        }
        if (session->server_write_ev) {
            event_del(session->server_write_ev);
            event_free(session->server_write_ev);
            session->server_write_ev = NULL;
        }
        if (session->server_conn_ev) {
            bufferevent_free(session->server_conn_ev);
            session->server_conn_ev = NULL;
        }
        if (session->ssl) {
            SSL_free(session->ssl);
            session->ssl = NULL;
            session->ssl_ctx = NULL;
        }
        if (server_sd >= 0) {
            evutil_closesocket(server_sd);
        }
    }
}
/**
 * Get the total number of sessions
 *
 * @return the number of sessions which are still active
 */
uint32_t session_count()
{
    uint32_t count = 0;
    uint32_t i;
    for (i = 0; i < PRI_TYPE_SIZE; ++ i) {
        count += sessions[i].length;
    }
    return count;
}

void session_status(session_t *session, dcmm_status_t *status)
{
    switch (session->server_state) {
        case ss_new:
        case ss_connecting:
            status->status = DCMM_CONN_IN_PROGRESS;
            break;
        case ss_connected:
            status->status = DCMM_CONN_READY;
            break;
        case ss_waiting_to_connect:
            status->status = DCMM_CONN_STALLED;
            break;
        case ss_connection_failed:
        case ss_interrupted:
        case ss_disconnected:
        default:
            status->status = DCMM_CONN_NETERR;
            break;
    }
    status->num_cached_msgs = session_count();
    status->avg_sending_rate = 0;
    status->cur_allocated_rate = 0;
}

session_t *session_get(uint32_t id)
{
    session_t *session;
    uint32_t i;
    for (i = 0; i < PRI_TYPE_SIZE; ++ i) {
        session = sessions[i].sessions_head;
        while (session != NULL) {
            if (session->id == id) {
                return session;
            }
            session = session->session_next;
        }
    }
    return NULL;
}
void session_update_info(session_t *session, dcmm_register_info_t *info)
{
    log_info("Client(%d): update session info", session->id);
    syslog_info("Client(%d): update session info", session->id);
    remove_session_from_list(session);
    session->priority = info->priority;
    session_add(session);
}

static void list_session()
{
    session_t *session;
    uint32_t i;
    for (i = 0; i < PRI_TYPE_SIZE; ++ i) {
        printf("Priority: %d\n", i);
        session = sessions[i].sessions_head;
        while (session != NULL) {
            printf("%d:%d\n", session->id, session->priority);
            session = session->session_next;
        }
    }
}
