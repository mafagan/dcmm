#include <string.h>
#include <assert.h>
#include <event.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/queue.h>

#include "logging.h"
#include "io_handler.h"
#include "connection_manager.h"
#include "session_manager.h"
#include "scheduler.h"
#include "memory_pool.h"

#define NETWORK_STATE_UPDATE_TIME 5

#define DOWN_CON_THRESHOLD 5//the number of failed or interrupted connections
#define SUCCESS_CON_THRESHOLD 1//the number of success connection
#define CONGESTED_CON_THRESHOLD 1//the number of succeed connections
#define CONGESTED_MSG_THRESHOLD 10 //the number of messages
#define NORMAL_MSG_THRESHOLD 5


/* Defined in `main.c` */
extern struct event_base *ev_base;

static struct event *ev_network_state = NULL;
static uint32_t count_failed;
static uint32_t count_interrupted;
static uint32_t count_success;
static uint32_t count_msg_pre;
static network_state_t network_state;

static void reset_statistic()
{
    count_failed = 0;
    count_interrupted = 0;
    count_success = 0;
    count_msg_pre = cache_count();
}
/**
 * According to the statistic, update the network state
 * @todo
 */
static void update_network_state(int sd, short events, void *arg)
{
    //printf("update_network_state\n");
    return ;
    switch (network_state) {
        case ns_normal:
            /* high number of connections failed or interrupted  */
            if (count_failed + count_interrupted >= DOWN_CON_THRESHOLD) {
                network_state = ns_down;
            }
            else if ((cache_count() - count_msg_pre) >= CONGESTED_MSG_THRESHOLD) {
                network_state = ns_congested;
            }
            break;
        case ns_congested:
            /* high number of connections failed or interrupted  */
            if (count_failed + count_interrupted >= DOWN_CON_THRESHOLD) {
                network_state = ns_down;
            }
            else if (cache_count() < NORMAL_MSG_THRESHOLD) {
                network_state = ns_normal;
            }
            break;
        case ns_down:
            if (count_success >= SUCCESS_CON_THRESHOLD) {
                network_state = ns_congested;
            }
            break;
        default:
            assert(0);
            break;
    }
    //printf("the network state is %d now\n", network_state);
    reset_statistic();
}
/**
 * Initialize the `connection_manager` module
 */
void connection_init()
{
    log_debug("Initialize the `connection_manager` module");
    syslog_debug("Initialize the `connection_manager` module");

    struct timeval tv;
    reset_statistic();
    network_state = ns_normal;
    /* init the network status update event */
    ev_network_state = event_new(ev_base, -1, EV_PERSIST,
            update_network_state, NULL);
    tv.tv_sec = NETWORK_STATE_UPDATE_TIME;
    tv.tv_usec = 0;
    event_add(ev_network_state, &tv);
}
/**
 * Destroy the `connection_manager` module
 */
void connection_destroy()
{
    log_debug("Destroy the `connection_manager` module");
    syslog_debug("Destroy the `connection_manager` module");
    if (ev_network_state) {
        event_free(ev_network_state);
        ev_network_state = NULL;
    }
}
/**
 * Get current network's state
 */
network_state_t connection_network_state()
{
    return network_state;
}
/**
 * Start a connection of a session
 *
 * @param session
 */
void connection_start(session_t *session)
{
    log_debug("Client(%d): connection start", session->id);
    syslog_debug("Client(%d): connection start", session->id);
    session->server_state = ss_connecting;
}
/**
 * Fail to connect to server
 *
 * @param session
 */
void connection_failed(session_t *session)
{
    log_debug("Client(%d): connection failed", session->id);
    syslog_debug("Client(%d): connection failed", session->id);

    session->server_state = ss_connection_failed;
    session_close_server(session);

    ++ count_failed;
}
/**
 * Succeed to connect to server
 *
 * @param session
 */
void connection_succeed(session_t *session)
{
    log_debug("Client(%d): connection succeed", session->id);
    syslog_debug("Client(%d): connection succeed", session->id);

    session->server_state = ss_connected;
    bzero(&(session->conn_wait_tv), sizeof(struct timeval));

    ++ count_success;
}
/**
 * Normally close a connection of server
 *
 * @param session
 */
void connection_closed(session_t *session)
{
    log_debug("Client(%d): connection closed", session->id);
    syslog_debug("Client(%d): connection closed", session->id);

    session->server_state = ss_disconnected;
    session_close_server(session);
}
/**
 * Abnormally close a connection of server
 *
 * @param session
 */
void connection_interrupted(session_t *session)
{
    log_debug("Client(%d): connection interrupted", session->id);
    syslog_debug("Client(%d): connection interrupted", session->id);

    session->server_state = ss_interrupted;
    session_close_server(session);

    ++ count_interrupted;
}
