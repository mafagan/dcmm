#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/queue.h>

#include "scheduler.h"
#include "session_manager.h"
#include "io_handler.h"
#include "connection_manager.h"
#include "config_manager.h"
#include "logging.h"
#include "../lib/dcmm_utils.h"

#define INFINITE_RATE 10240 //10MB/s
#define INIT_CREDIT 1000.0
#define CREDIT_PER_MESSAGE 256.0
#define CREDIT_LIMIT 1000.0
#define MICROSECOND_PER_SECOND 1000000
#define CONN_DELAY_TIME_LIMIT 10

typedef struct controller {
    double rate;//rate of a priority
    double credit;//credit of a priority
    struct timeval tv;//last time of increasing credit
} controller_t;

/* Defined in `main.c` */
extern struct event_base *ev_base;
/* Defined in `session_manager` */
extern session_queue_t sessions[PRI_TYPE_SIZE];
/* Defined in `config_manager` */
extern config_t config;
/* Local variables */
static controller_t controller;

static double time_diff_in_double(struct timeval *tv1, struct timeval *tv2);
/**
 * Dime difference of `tv1` and `tv2`
 *
 * @param tv1
 * @param tv2
 * @return the time difference of `tv1` and `tv2` in double
 */
static double time_diff_in_double(struct timeval *tv1, struct timeval *tv2)
{
    if (tv1->tv_sec < tv2->tv_sec ||
            (tv1->tv_sec == tv2->tv_sec && tv1->tv_usec < tv2->tv_usec)) {
        struct timeval tmp;
        memcpy(&tmp, tv1, sizeof(struct timeval));
        memcpy(tv1, tv2, sizeof(struct timeval));
        memcpy(tv2, &tmp, sizeof(struct timeval));
    }
    if (tv1->tv_usec < tv2->tv_usec) {
        -- tv1->tv_sec;
        tv1->tv_usec += MICROSECOND_PER_SECOND;
    }
    double usec = (double)(tv1->tv_usec - tv2->tv_usec) / MICROSECOND_PER_SECOND;
    return tv1->tv_sec - tv2->tv_sec + usec;
}
/**
 * Initialize the `scheduler` module
 */
void scheduler_init()
{
    log_debug("Initialize the 'scheduler' moduel");
    syslog_debug("Initialize the 'scheduler' moduel");
    assert(ev_base);
    /* init the controller */
    bzero(&controller, sizeof(controller));
    controller.rate = config.rate;
    controller.credit = INIT_CREDIT;
    bzero(&(controller.tv), sizeof(controller.tv));
    if (controller.rate <= 0.0) {
        controller.rate = INFINITE_RATE;
    }
}
/**
 * Destroy the `scheduler` module
 */
void scheduler_destroy()
{
    log_debug("Destroy the 'scheduler' moduel");
    syslog_debug("Destroy the 'scheduler' moduel");
}
/**
 * Check if the session can connect
 *
 * @param session
 * @return 1 if can, or 0 if not
 */
bool scheduler_can_session_connect(session_t *session)
{
    assert(session);
    switch (connection_network_state()) {
        case ns_normal:
            return true;
        case ns_congested://only high priority can connect
            if (session->priority == DCMM_PRIORITY_PLATINUM) {
                return true;
            }
            return false;
        case ns_down:
            return false;
        default:
            assert(0);
            break;
    }
}
/**
 * Check is the session can send message
 *
 * @param session
 * @return
 */
int scheduler_can_session_send(session_t *session)
{
    scheduler_update_credit();
    assert(session);
    switch (connection_network_state()) {
        case ns_congested:
            /* only `sp_platinum` can send if there are some `sp_platinum` */
            if (sessions[DCMM_PRIORITY_PLATINUM].length > 0 &&
                    session->priority != DCMM_PRIORITY_PLATINUM) {
                return CAN_NOT_SEND;
            }
            /* no break */
        case ns_normal:
            if (controller.credit < CREDIT_PER_MESSAGE) {
                return LACK_CREDIT;
            }
            /* absolute priority */
            if ((sessions[DCMM_PRIORITY_PLATINUM].length > 0 &&
                        session->priority > DCMM_PRIORITY_PLATINUM) ||
                    (sessions[DCMM_PRIORITY_PLATINUM].length + sessions[DCMM_PRIORITY_GOLD].length > 0 &&
                     session->priority > DCMM_PRIORITY_GOLD)) {
                return CAN_NOT_SEND;
            }
            return CAN_SEND;
        case ns_down:
            return CAN_NOT_SEND;
        default:
            assert(0);
            break;
    }
}
/**
 * Send data to the server
 *
 * @param session
 * @param buff the data we will send
 * @param size the number of bytes
 * @return 1 if success, 0 if not
 */
int scheduler_send(session_t *session, message_t *msg)
{
    dcmm_header_t header;
    uint32_t i;
    int n;
    if (session->ssl) {
        n = SSL_write(session->ssl, msg->data, msg->len);
    }
    else {
        if (session->server_state == ss_connected) {
            n = write(EVENT_FD(session->server_write_ev), msg->data, msg->len);
        }
        else {
            return 0;
        }
    }
    if (n != msg->len) {
        perror("Short write from dcmm to server\n");
        log_debug("Short write from dcmm to server");
        syslog_debug("Short write from dcmm to server");
    }
    //consume one credit for a byte
    controller.credit -= n;
    if (n == msg->len) {
        if (session->client_state == cs_connected &&
                msg->need_reply) {
            reset_header(&header);
            header.type = DCMM_MSG_SEND_REPLY;
            header.length = sizeof(header);
            header.cfm_id = msg->id;
            network_transfer_header(&header);
            send_reply(session, &header, sizeof(header));
        }
        if (session->client_state == cs_connected &&
                session->protocol == DCMM_PROTOCOL_MQTT &&
                ((int)(msg->data[0]) & DCMM_MQTT_MSG_MASK) == DCMM_MQTT_MSG_DISCONNECT) {
            perror("Send MQTT disconnect msg\n");
            log_debug("Send MQTT disconnect msg");
            syslog_debug("Send MQTT disconnect msg");
            session_close_client(session);
        }
        return 1;
    }
    return 0;
}
/**
 * Get the waiting time of re-sending message when scheduler doesn't permit to
 * send
 *
 * @param session
 */
struct timeval scheduler_get_wait_time(session_t *session)
{
    struct timeval delay;
    delay.tv_sec = 1 * (session->priority + 1);
    delay.tv_usec = 0;
    return delay;
}
/**
 * Increase the waiting time of connecting to the server when connection failed or
 * interrupted
 *
 * @param session
 */
void scheduler_increase_connect_wait_time(session_t *session)
{
    struct timeval *delay = &session->conn_wait_tv;
    if (connection_network_state() == ns_down) {
        return ;
    }
    if (delay->tv_sec == 0) {
        delay->tv_sec = 1;
    }
    else if (delay->tv_sec < CONN_DELAY_TIME_LIMIT){
        delay->tv_sec <<= 1;
    }
}
/**
 * Credit will increase according to the rate of different priority
 */
void scheduler_update_credit()
{
    struct timeval now;
    uint32_t pri;
    double credit_add;

    gettimeofday(&now, NULL);

    if (!controller.tv.tv_sec) {
        memcpy(&(controller.tv), &now, sizeof(struct timeval));
        return;
    }
    /* increase the credit basing on the rate and time */
    credit_add += (1024 * controller.rate) *
        time_diff_in_double(&now, &(controller.tv));

    if (controller.credit + credit_add < CREDIT_LIMIT) {
        controller.credit += credit_add;
    }
    else {
        controller.credit = CREDIT_LIMIT;
    }

    memcpy(&(controller.tv), &now, sizeof(struct timeval));
}

