#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <event.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <openssl/ssl.h>

#include "http_https.h"
#include "logging.h"
#include "io_handler.h"
#include "session_manager.h"
#include "scheduler.h"
#include "mem_cache.h"
#include "connection_manager.h"
#include "memory_pool.h"
#include "../lib/dcmm_utils.h"

#define LISTEN_SIZE 50

/* Defined in `main.c` */
extern struct event_base *ev_base;
/* Event for local socket's accept */
static struct event *ev_accept_control = NULL;
static struct event *ev_accept_client = NULL;
/* Buffer for server write callback */
static char buff[DCMM_BUFF_SIZE];

static void setup_socket(struct event *ev, const char *socket_file,
        event_callback_fn callback);
static void setup_control_socket();
static void setup_client_socket();
static void send_message_directly(session_t *session, message_t *msg);
static void send_message_from_cache(session_t *session);
/* callbacks */
static void timer_connect_cb(int sd, short events, void *arg);
static void accept_control_cb(int sd, short events, void *arg);
static void accept_client_cb(int sd, short events, void *arg);
static void client_read_cb(int client_sd, short events, void *arg);
static void server_event_cb(struct bufferevent *bufferev, short events, void *arg);
static void server_read_cb(int server_sd, short events, void *arg);
static void server_write_cb(int server_sd, short events, void *arg);


/**
 * Used for setting up unix socket
 *
 * @param ev the `struct event *` variable we will initialize
 * @param socket_file the socket file for unix socket
 * @param callback
 */
static void setup_socket(struct event *ev, const char *socket_file,
        event_callback_fn callback)
{
    assert(ev_base);
    int error = 0;
    int sd = -1;
    struct sockaddr_un xsun;

    unlink(socket_file);
    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket\n");
        log_error("Set up socket %s failed in socket", socket_file);
        syslog_error("Set up socket %s failed in socket", socket_file);
        exit(EXIT_FAILURE);
    }

    error = evutil_make_listen_socket_reuseable(sd);
    if (error) {
        perror("setsockopt\n");
        log_error("Set up socket %s failed in making it reuseable", socket_file);
        syslog_error("Set up socket %s failed in making it reuseable", socket_file);
        exit(EXIT_FAILURE);
    }

    bzero(&xsun, sizeof(xsun));
    xsun.sun_family = AF_UNIX;
    strcpy(xsun.sun_path, socket_file);
    error = bind(sd, (struct sockaddr *)&xsun, sizeof(xsun));
    if (error) {
        perror("bind\n");
        log_error("Set up socket %s failed in bind", socket_file);
        syslog_error("Set up socket %s failed in bind", socket_file);
        exit(EXIT_FAILURE);
    }
    /* make it non-block*/
    error = evutil_make_socket_nonblocking(sd);
    if (error) {
        perror("nonblock\n");
        log_error("Set up socket %s failed in making it nonblocking", socket_file);
        syslog_error("Set up socket %s failed in making it nonblocking", socket_file);
        exit(EXIT_FAILURE);
    }

    error = chmod(socket_file, S_IRWXU | S_IRWXG | S_IRWXO);
    if (error) {
        perror("chmod\n");
        log_error("Set up socket %s failed in chmod", socket_file);
        syslog_error("Set up socket %s failed in chmod", socket_file);
        exit(EXIT_FAILURE);
    }

    error = listen(sd, LISTEN_SIZE);
    if (error) {
        perror("listen\n");
        log_error("Set up socket %s failed in listen", socket_file);
        syslog_error("Set up socket %s failed in listen", socket_file);
        exit(EXIT_FAILURE);
    }
    /* set up the accept event */
    ev = event_new(ev_base, sd, EV_READ | EV_PERSIST,
            callback, NULL);
    event_add(ev, NULL);
}
/**
 * Set up unix socket for client's controlling connection
 */
static void setup_control_socket()
{
    setup_socket(ev_accept_control, DCMM_CONTROL_SOCKET_FILE, accept_control_cb);
}
/**
 * Set up unix socket for client's data connection
 */
static void setup_client_socket()
{
    setup_socket(ev_accept_client, DCMM_DATA_SOCKET_FILE, accept_client_cb);
}
/**
 * Send message directely, this function will be called when receiving a new
 * message from client and the session has no other messages in the cache
 *
 ***************************************************************************
 * @todo deal with short write
 ***************************************************************************
 *
 * @param session
 * @param msg the new message we will send
 */
static void send_message_directly(session_t *session, message_t *msg)
{
    log_debug("Try to send message directly for client(%d)", session->id);
    syslog_debug("Try to send message directly for client(%d)", session->id);
    assert(! cache_session_has_msg_not_sent(session));//if fails, it's an error usage.
    struct timeval tv = {0, 0};
    switch (scheduler_can_session_send(session)) {
        case CAN_SEND:
            if (scheduler_send(session, msg)) {
                //send success, reuse the msg
                if (! cache_is_db_cache_memory(msg)) {
                    //only if this message is in the cache, should we call
                    //`cache_return_msg_block`
                    cache_return_msg_block(msg);
                }
                log_debug("Send successfully");
                syslog_debug("Send successfully");
            }
            else {
                //write failure, insert msg to the cache
                cache_insert_msg(session, msg);
                connection_interrupted(session);
                try_to_connect(session);
            }
            break;
        case CAN_NOT_SEND:
            break;
        case LACK_CREDIT:
            cache_insert_msg(session, msg);
            tv = scheduler_get_wait_time(session);
            event_add(session->server_write_ev, &tv);
            break;
        default:
            assert(0);
            break;
    }
}
/**
 * Send the first message of the session in the cache, this function will be
 * called at the `server_write_cb`
 *
 ***************************************************************************
 * @todo deal with short write
 ***************************************************************************
 *
 * @param session
 */
static void send_message_from_cache(session_t *session)
{
    log_debug("Try to send message from cache for client(%d)", session->id);
    syslog_debug("Try to send message from cache for client(%d)", session->id);
    assert(cache_session_has_msg_not_sent(session));//if fails, it's an error usage.
    struct timeval tv = {0, 0};
    message_t *msg = NULL, *cur = NULL, *tmp = NULL;

    switch (scheduler_can_session_send(session)) {

        case CAN_SEND:
            // may be all the messages of this session are in database
            if (session->count_msg_cache > 0) {
                msg = cache_get_curr_msg(session);
                if (scheduler_send(session, msg)) {
                    session->curr_msg = msg->session_msg_next;
                    if (msg->is_final_block) {
                        cur = cache_first_session_msg(session);
                        while (cur != msg) {
                            tmp = cur->session_msg_next;
                            cache_pop_session_msg(session, cur);
                            cur = tmp;
                        }
                        cache_pop_session_msg(session, msg);
                    }
                    log_debug("Send successfully");
                    syslog_debug("Send successfully");
                    if (cache_session_has_msg_not_sent(session)) {
                        event_add(session->server_write_ev, NULL);
                    }
                    else if (session->client_state != cs_connected) {
                        session_remove(session);
                    }
                }
                else {
                    connection_interrupted(session);
                    try_to_connect(session);
                }
            }
            break;
        case CAN_NOT_SEND:
            /*  */
        case LACK_CREDIT:
            tv = scheduler_get_wait_time(session);
            session->timer_ev = evtimer_new(ev_base, server_write_cb, session);
            evtimer_add(session->timer_ev, &tv);
            break;
        default:
            assert(0);
            break;
    }
}
/**
 * Callback function for connecting to server when the waiting time is over
 *
 * @param sd as this callback is for evtimer, sd is useless
 * @param events also useless
 * @param arg a user-supplied argument, it should be a session
 */
static void timer_connect_cb(int sd, short events, void *arg)
{
    assert(arg);
    session_t *session = (session_t *)arg;
    struct sockaddr_in server_addr;

    if (! scheduler_can_session_connect(session)) {
        evtimer_add(session->timer_ev, &(session->conn_wait_tv));
        scheduler_increase_connect_wait_time(session);
        return ;
    }
    /* free the evtimer and the old bufferevent */
    event_free(session->timer_ev);
    session->timer_ev = NULL;
    if (session->server_conn_ev) {
        bufferevent_free(session->server_conn_ev);
        session->server_conn_ev = NULL;
    }

    bzero(&server_addr, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(session->dest_ip);
    server_addr.sin_port = htons(session->dest_port);
    /* set up bufferevent, just for connecting, notice that, there is no need to
     * enable as we just use it to connect */
    session->server_conn_ev = bufferevent_socket_new(
                ev_base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (bufferevent_socket_connect(session->server_conn_ev,
                (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "Client(%d): bufferevent_socket_connect failed\n", session->id);
        log_error("Client(%d): bufferevent_socket_connect failed\n", session->id);
        syslog_error("Client(%d): bufferevent_socket_connect failed\n", session->id);
        session_close_server(session);
        return ;
    }
    bufferevent_setcb(session->server_conn_ev, NULL, NULL,
                            server_event_cb, session);
    connection_start(session);
}
/**
 * Callback function for accepting client's controlling connection
 *
 * Note that, `ev_base` which is an extern variable, should been initilize outside
 * this module before calling this function
 *
 * @param sd the socket descriptor related to this event
 * @param events one or more EV_* flags
 * @param arg a user-supplied argument, it's useless here as we don't use it
 */
static void accept_control_cb(int sd, short events, void *arg)
{
    socklen_t addr_len = 0;
    dcmm_header_t *header;
    struct sockaddr control_addr;
    uint32_t *id = NULL;
    int error = 0;
    int control_sd;

    addr_len = sizeof(struct sockaddr);

    bzero(&control_addr, addr_len);
    if ((control_sd = accept(sd, &control_addr, &addr_len)) == -1) {
        perror("Library connection failed\n");
        log_error("Library connection failed");
        syslog_error("Library connection failed");
        return ;
    }
    error = evutil_make_socket_nonblocking(control_sd);
    if (error) {
        perror("Make library's socket nonblocking failed, disconnecting\n");
        log_error("Make library's socket nonblocking failed, disconnecting");
        syslog_error("Make library's socket nonblocking failed, disconnecting");
        close(control_sd);
        return ;
    }

    log_info("New library(%d) connected.", control_sd);
    syslog_info("New library(%d) connected.", control_sd);
    header = (dcmm_header_t *)buff;
    reset_header(header);
    header->type = DCMM_MSG_CONTROL_REPLY;
    id = (uint32_t *)(buff + sizeof(dcmm_header_t));
    *id = htonl(control_sd);
    write(control_sd, buff, sizeof(dcmm_header_t) + sizeof(int));
}
/**
 * Callback function for accepting client's data connection
 *
 * Note that, `ev_base` which is an extern variable, should been initilize outside
 * this module before calling this function
 *
 * @param sd the socket descriptor related to this event
 * @param events one or more EV_* flags
 * @param arg a user-supplied argument, it's useless here as we don't use it
 */
static void accept_client_cb(int sd, short events, void *arg)
{
    session_t *session = NULL;
    struct sockaddr client_addr;
    int client_sd = -1;
    int error = 0;
    socklen_t addr_len = sizeof(client_addr);

    /* accept client */
    bzero(&client_addr, sizeof(client_addr));
    if ((client_sd = accept(sd, &client_addr, &addr_len)) == -1) {
        perror("New client set up failed in accept\n");
        log_error("New client set up failed in accept");
        syslog_error("New client set up failed in accept");
        return ;
    }

    /* accept success, init a new session for the client */
    session = get_session_block();
    if (session == NULL) {
        perror("Session created failed, disconnecting\n");
        log_error("Session created failed, disconnecting");
        syslog_error("Session created failed, disconnecting");
        close(client_sd);
        return ;
    }
    session->priority = DCMM_PRIORITY_SILVER;
    /* add new session to the sessions */
    session_add(session);

    read(client_sd, &(session->control_sd), sizeof(int));
    error = evutil_make_socket_nonblocking(client_sd);
    if (error) {
        perror("Make client's socket nonblocking failed, disconnecting\n");
        log_error("Make client's socket nonblocking failed, disconnecting");
        syslog_error("Make client's socket nonblocking failed, disconnecting");
        close(client_sd);
        return ;
    }

    log_info("New client(%d) connected", session->id);
    syslog_info("New client(%d) connected", session->id);
    /*****************************************************************
     * @todo add pointers of the app's sessions
     ****************************************************************/
    session->client_read_ev = event_new(ev_base, client_sd,
            EV_READ | EV_PERSIST, client_read_cb, session);
    event_add(session->client_read_ev, NULL);
    session->client_state = cs_connected;
}
/**
 * Callback function for reading client's data
 *
 * @param client_sd the socket descriptor related to this event
 * @param events one or more EV_* flags
 * @param arg a user-supplied argument, it should be a session
 */
static void client_read_cb(int client_sd, short events, void *arg)
{
    assert(arg);
    session_t *session = (session_t *)arg;
    int n = 0;
    dcmm_header_t *header = NULL;
    dcmm_addr_t *addr = NULL;
    dcmm_status_t *status = NULL;
    dcmm_register_info_t *info = NULL;
    dcmm_tls_t *tls = NULL;
    message_t *msg = NULL;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    uint32_t cfm_id = 0;
    uint32_t *lbr_id = NULL;
    int *protocol = NULL;
    char *buff_ptr = buff;

    /* read data header first */
    header = (dcmm_header_t *)buff_ptr;
    size_header = sizeof(dcmm_header_t);
    buff_ptr += size_header;
    n = read(client_sd, header, size_header);
    if (n <= 0) {
        session_close_client(session);
        if (! cache_session_has_msg_not_sent(session)) {
            connection_closed(session);
            session_remove(session);
        }
        return ;
    }
    network_retransfer_header(header);
    size_body = header->length - size_header;
    /* check the header */
    if (! is_header_valid(header)) {
        fprintf(stderr, "Recv invalid message from client(%d), ignore it\n", session->id);
        log_warn("Recv invalid message from client(%d), ignore it", session->id);
        syslog_warn("Recv invalid message from client(%d), ignore it", session->id);
        return ;
    }

    switch (header->type) {
         case DCMM_MSG_CONNECT_SVR:
            log_debug("Recv DCMM_MSG_CONNECT_SVR from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_CONNECT_SVR from client(%d)", session->id);
            if (header->opt == DCMM_OPT_BLOCKING) {
                session->conn_id = header->msg_id;
            }
            else {//if client doesn't want reply, we set `conn_reply_msg_id` to -1
                session->conn_id = -1;
            }
            /* read server information into struct dcmm_addr */
            addr = (dcmm_addr_t *)buff_ptr;
            buff_ptr += sizeof(dcmm_addr_t);
            n = read(client_sd, addr, sizeof(dcmm_addr_t));

            protocol = (int *)buff_ptr;
            buff_ptr += sizeof(int);
            n = read(client_sd, protocol, sizeof(int));
            *protocol = ntohl(*protocol);

            session->protocol = *protocol;

            network_retransfer_addr(addr);

            if (session->server_state != ss_new) {
                /* server address is already set */
                perror("Server addr is already set\n");
                log_warn("Server address has already set");
                syslog_warn("Server address has already set");
                /*******************************************************
                 * @todo send message back to the client
                 ******************************************************/
            }
            else {
                session->dest_port = addr->port;
                strcpy(session->dest_ip, addr->ip);
                /* connect to the destination */
                try_to_connect(session);
            }
            break;

       case DCMM_MSG_SEND:
            log_debug("Recv DCMM_MSG_SEND from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_SEND from client(%d)", session->id);
            /* get the message, if the size is too large, split it */
            while (size_body > DCMM_MAX_MSG_SIZE) {
                msg = cache_get_msg_block();
                msg->id = header->msg_id;
                msg->need_reply = false;
                n = read(client_sd, msg->data, DCMM_MAX_MSG_SIZE);
                if (n != DCMM_MAX_MSG_SIZE) {
                    fprintf(stderr, "Short read from client(%d)\n", session->id);
                    log_warn("Short read from client(%d)\n", session->id);
                    syslog_warn("Short read from client(%d)\n", session->id);
                }
                msg->len = n;
                msg->is_final_block = false;

                cache_insert_msg(session, msg);
                size_body -= DCMM_MAX_MSG_SIZE;
            }
            msg = cache_get_msg_block();
            msg->id = header->msg_id;
            msg->need_reply = (header->opt == DCMM_OPT_BLOCKING);
            n = read(client_sd, msg->data, size_body);
            if (n != size_body) {
                fprintf(stderr, "Short read from client(%d)\n", session->id);
                log_warn("Short read from client(%d)\n", session->id);
                syslog_warn("Short read from client(%d)\n", session->id);
            }
            msg->len = n;
            msg->is_final_block = true;
            /* special handling of different protocol */
            if (session->protocol == DCMM_PROTOCOL_MQTT) {
                if (((int)(msg->data[0]) & DCMM_MQTT_MSG_MASK) == DCMM_MQTT_MSG_CONNECT) {
                    if (session->conn_msg != NULL) {
                        //cache_return_block(session->conn_msg);
                        free(session->conn_msg);
                    }
                    if (session->ssl)
                        SSL_write(session->ssl, msg->data, msg->len);
                    else
                        write(EVENT_FD(session->server_write_ev), msg->data, msg->len);

                    session->conn_msg = (message_t *)calloc(1, sizeof(message_t));
                    memcpy(session->conn_msg, msg, sizeof(message_t));
                    break;
                }
            }

            switch (session->server_state) {
                case ss_new:
                case ss_disconnected:
                    fprintf(stderr, "Client(%d) hasn't connected to server", session->id);
                    log_error("Client(%d) hasn't connected to server", session->id);
                    syslog_error("Client(%d) hasn't connected to server", session->id);
                    break;
                case ss_connecting:
                case ss_waiting_to_connect:
                    /* insert into the cache */
                    cache_insert_msg(session, msg);
                    break;
                case ss_connected:
                    if (cache_session_has_msg_not_sent(session)) {
                        //some data is already in the cache
                        cache_insert_msg(session, msg);
                        send_message_from_cache(session);
                    }
                    else {//send directely
                        send_message_directly(session, msg);
                    }
                    break;
                case ss_connection_failed:
                case ss_interrupted:
                    /* as we reconnect_to_server,
                     * these states may not occur when
                     * recving client's data
                     * if happens, the server state machine may have some bugs*/
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
            break;

        case DCMM_MSG_REGISTER_SESSION:
            log_debug("Recv DCMM_MSG_REGISTER_SESSION from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_REGISTER_SESSION from client(%d)", session->id);

            cfm_id = header->msg_id;

            info = (dcmm_register_info_t *)buff_ptr;
            buff_ptr += size_body;
            read(client_sd, info, size_body);
            network_retransfer_register_info(info);
            session_update_info(session, info);

            header = (dcmm_header_t *)buff_ptr;
            buff_ptr += size_header;
            reset_header(header);
            header->type = DCMM_MSG_REGISTER_SESSION_REPLY;
            header->length = size_header;
            header->cfm_id = cfm_id;

            network_transfer_header(header);
            write(session->control_sd, header, size_header);
            break;

        case DCMM_MSG_DISCONNECT:
            log_debug("Recv DCMM_MSG_DISCONNECT from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_DISCONNECT from client(%d)", session->id);

            cache_clear_session_msg(session);
            connection_closed(session);
            break;

        case DCMM_MSG_STATUS:
            log_debug("Recv DCMM_MSG_STATUS from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_STATUS from client(%d)", session->id);

            cfm_id = header->msg_id;
            size_body = sizeof(dcmm_status_t);

            header = (dcmm_header_t *)buff_ptr;
            buff_ptr += size_header;
            reset_header(header);
            header->type = DCMM_MSG_STATUS_REPLY;
            header->length = size_header + size_body;
            header->cfm_id = cfm_id;

            status = (dcmm_status_t *)buff_ptr;
            buff_ptr += size_body;
            session_status(session, status);

            network_transfer_header(header);
            network_transfer_status(status);
            write(session->control_sd, header,
                    size_header + size_body);
            break;

        case DCMM_MSG_DELETE:
            log_debug("Recv DCMM_MSG_DELETE from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_DELETE from client(%d)", session->id);
            cache_clear_session_msg(session);
            break;

        case DCMM_MSG_TLS:
            log_debug("Recv DCMM_MSG_TLS from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_TLS from client(%d)", session->id);

            cfm_id = header->msg_id;
            tls = (dcmm_tls_t *)buff_ptr;
            buff_ptr += size_body;
            read(client_sd, tls, size_body);
            if (strlen(tls->ca_file) > 0)
                session->tls_cafile = strdup(tls->ca_file);
            if (strlen(tls->ca_path) > 0)
                session->tls_capath = strdup(tls->ca_path);
            if (strlen(tls->cert_file) > 0)
                session->tls_certfile = strdup(tls->cert_file);
            if (strlen(tls->key_file) > 0)
                session->tls_keyfile = strdup(tls->key_file);
            break;

        case DCMM_MSG_HTTP_HTTPS:
            log_debug("Recv DCMM_MSG_HTTP_HTTPS from client(%d)", session->id);
            syslog_debug("Recv DCMM_MSG_HTTP_HTTPS from client(%d)", session->id);
            n = read(client_sd, buff_ptr, size_body);
            buff_ptr[n] = '\0';
            syslog_debug("make http request");
            make_http_request(buff_ptr, session);
            syslog_debug("end");
            break;

        default:
            /* unknown data type, ignore currently */
            perror("Data type incorrect, ignore it\n");
            log_error("Data type incorrect, ignore it");
            syslog_debug("Data type incorrect, ignore it");
            read(client_sd, buff_ptr, size_body);
            break;
    }
}
/**
 * Callback function for server connection event
 *
 * Note that, `ev_base` which is an extern variable, should been initilize outside
 * this module before calling this function
 *
 * @param buffev the bufferevent related to this event
 * @param events one or more `EV_*` flags
 * @param arg a user-supplied argument, it should be a session
 */
static void server_event_cb(struct bufferevent *buffev, short events, void *arg)
{
    assert(arg);
    session_t *session = (session_t *)arg;
    dcmm_header_t *header = (dcmm_header_t *)buff;
    int n;
    int result;

    if (events & BEV_EVENT_CONNECTED) {
        if (session->tls_cafile || session->tls_capath) {
            // make it blocking for ssl handshake
            fcntl_block(bufferevent_getfd(buffev));
            session->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
            log_debug("Client(%d): ca_file:%s\n", session->id,
                    (session->tls_cafile ? session->tls_cafile : "NULL"));
            syslog_debug("Client(%d): ca_path:%s\n", session->id,
                    (session->tls_capath? session->tls_capath: "NULL"));
            result = SSL_CTX_load_verify_locations(session->ssl_ctx,
                    session->tls_cafile, session->tls_capath);
            if (result != 1) {
                SSL_CTX_free(session->ssl_ctx);
                session->ssl_ctx = NULL;
                connection_closed(session);
                session_close_client(session);
                session_remove(session);
                return ;
            }
            log_debug("Client(%d): SSL_CTX_load_verify return %d", session->id, result);
            syslog_debug("Client(%d): SSL_CTX_load_verify return %d", session->id, result);
            SSL_CTX_set_verify(session->ssl_ctx, SSL_VERIFY_PEER, NULL);
            if (session->tls_certfile && session->tls_keyfile) {
                result = SSL_CTX_use_certificate_file(session->ssl_ctx, session->tls_certfile,
                        SSL_FILETYPE_PEM);
                log_debug("Client(%d): SSL_CTX_use_certificate_file return %d",
                        session->id, result);
                syslog_debug("Client(%d): SSL_CTX_use_certificate_file return %d",
                        session->id, result);

                result = SSL_CTX_use_PrivateKey_file(session->ssl_ctx, session->tls_keyfile,
                        SSL_FILETYPE_PEM);
                log_debug("Client(%d): SSL_CTX_use_PrivateKey_file return %d",
                        session->id, result);
                syslog_debug("Client(%d): SSL_CTX_use_PrivateKey_file return %d",
                        session->id, result);
                if (! SSL_CTX_check_private_key(session->ssl_ctx)) {
                    //fail
                    fprintf(stderr, "Client(%d): SSL_CTX_check_private_key failed\n", session->id);
                    log_debug("Client(%d): SSL_CTX_check_private_key failed\n", session->id);
                    syslog_debug("Client(%d): SSL_CTX_check_private_key failed\n", session->id);
                    SSL_CTX_free(session->ssl_ctx);
                    session->ssl_ctx = NULL;
                    connection_closed(session);
                    session_close_client(session);
                    session_remove(session);
                    return ;
                }
            }
            session->ssl = SSL_new(session->ssl_ctx);
            result = SSL_set_fd(session->ssl, bufferevent_getfd(buffev));
            log_debug("Client(%d): SSL_set_fd return %d", session->id, result);
            syslog_debug("Client(%d): SSL_set_fd return %d", session->id, result);

            result = SSL_connect(session->ssl);
            log_debug("Client(%d): SSL_connect return %d", session->id, result);
            syslog_debug("Client(%d): SSL_connect return %d", session->id, result);

            if (result != 1) {
                //fail
                fprintf(stderr, "Client(%d): SSL_connect failed\n", session->id);
                log_error("Client(%d): SSL_connect failed\n", session->id);
                syslog_error("Client(%d): SSL_connect failed\n", session->id);
                //SSL_free(session->ssl);
                connection_closed(session);
                session_close_client(session);
                session_remove(session);
                return ;
            }
            if (SSL_get_verify_result(session->ssl) != X509_V_OK) {
                //fail
                fprintf(stderr, "Client(%d): SSL_get_verify_result failed\n", session->id);
                log_error("Client(%d): SSL_get_verify_result failed\n", session->id);
                syslog_error("Client(%d): SSL_get_verify_result failed\n", session->id);
            }
            fcntl_nonblock(bufferevent_getfd(buffev));
        }
        connection_succeed(session);
        if (session->client_state != cs_connected &&
                ! cache_session_has_msg_not_sent(session)) {
            session_close_client(session);
            connection_closed(session);
            session_remove(session);
            return ;
        }
        /* if the client wants reply */
        if (session->conn_id >= 0) {
            reset_header(header);
            header->type = DCMM_MSG_CONNECT_REPLY;
            header->length = 0;
            header->cfm_id = session->conn_id;
            network_transfer_header(header);
            send_reply(session, header, sizeof(dcmm_header_t));
        }
        /* begin the read and write events of server */
        session->server_read_ev = event_new(ev_base, bufferevent_getfd(buffev),
                EV_READ | EV_PERSIST, server_read_cb, session);
        event_add(session->server_read_ev, NULL);
        session->server_write_ev = event_new(ev_base, bufferevent_getfd(buffev),
                EV_WRITE, server_write_cb, session);
        event_add(session->server_write_ev, NULL);
        if (session->protocol == DCMM_PROTOCOL_MQTT) {
            if (session->conn_msg != NULL) {
                if (session->ssl)
                    n = SSL_write(session->ssl, session->conn_msg->data,
                            session->conn_msg->len);
                else
                    n = write(EVENT_FD(session->server_write_ev), session->conn_msg->data,
                            session->conn_msg->len);
            }
        }
    }
    else {
        if (events & BEV_EVENT_EOF) {
            log_debug("Client(%d)'s server disconnected", session->id);
            syslog_debug("Client(%d)'s server disconnected", session->id);
            if (cache_session_has_msg_not_sent(session)) {
                connection_interrupted(session);
                try_to_connect(session);
            }
            else {
                connection_closed(session);
                session_close_client(session);
                session_remove(session);
            }
        }
        else {
            log_error("Client(%d): server socket error", session->id);
            syslog_error("Client(%d): server socket error", session->id);
            if (session->server_state == ss_connecting) {
                connection_failed(session);
            }
            else {
                /* error occur when reading or writing */
                connection_interrupted(session);
            }
            try_to_connect(session);
        }
    }
}
/**
 * Callback function for reading server's data
 *
 * @param server_sd the socket descriptor related to this event
 * @param events one or more EV_* flags
 * @param arg a user-supplied argument, it should be a session
 */
static void server_read_cb(int server_sd, short events, void *arg)
{
    assert(arg);
    dcmm_header_t *header = (dcmm_header_t *)buff;
    int n = 0;
    session_t *session = (session_t *)arg;
    int client_sd = -1;
    uint32_t size_header = sizeof(dcmm_header_t);
    if (session->ssl) {
        n = SSL_read(session->ssl, buff, DCMM_BUFF_SIZE);
    }
    else
        n = read(server_sd, buff, DCMM_BUFF_SIZE);
    if (n <= 0) {
        connection_closed(session);
        if (session->client_state == cs_disconnected) {
            session_remove(session);
        }
        else {
            try_to_connect(session);
        }
        return ;
    }
    if (session->client_state == cs_connected &&
            session->client_read_ev) {
        n = write(EVENT_FD(session->client_read_ev), buff, n);
    }
}
/**
 * Callback function for writing data to server
 *
 * Note that, server's write event isn't `EV_PERSIST`,
 * it will be enable when the session's message isn't empty and the scheduler
 * module permits sending
 *
 * @param server_sd the socket descriptor related to this event
 * @param events one or more EV_* flags
 * @param arg a user-supplied argument, it should be a session
 */
static void server_write_cb(int server_sd, short events, void *arg)
{
    assert(arg);
    session_t *session = (session_t *)arg;
    if (session->timer_ev) {
        event_free(session->timer_ev);
        session->timer_ev = NULL;
    }
    if (cache_session_has_msg_not_sent(session)) {
        send_message_from_cache(session);
    }
}
/**
 * Initialize the `io_handler` module, set up socket for app to send data
 */
void io_init()
{
    log_debug("Initialize the `io_handler` module");
    syslog_debug("Initialize the `io_handler` module");
    setup_control_socket();
    setup_client_socket();
}
/**
 * Free the resource of `io_handler`
 */
void io_destroy()
{
    log_debug("Destroy the `io_handler` module");
    syslog_debug("Destroy the `io_handler` module");
    if (ev_accept_control) {
        close(EVENT_FD(ev_accept_control));
        event_free(ev_accept_control);
        ev_accept_control = NULL;
    }
    unlink(DCMM_CONTROL_SOCKET_FILE);
    if (ev_accept_client) {
        close(EVENT_FD(ev_accept_client));
        event_free(ev_accept_client);
        ev_accept_client = NULL;
    }
    unlink(DCMM_DATA_SOCKET_FILE);
}
/**
 * Try to connect to the server
 *
 * This function sets up a `evtimer`, and the waiting time is got by calling
 * `scheduler_get_connect_wait_time`
 *
 * @param session the session related to
 */
void try_to_connect(session_t *session)
{
    assert(session);
    log_debug("Client(%d) try to connect in %lu seconds\n",
            session->id, session->conn_wait_tv.tv_sec);
    syslog_debug("Client(%d) try to connect in %lu seconds\n",
            session->id, session->conn_wait_tv.tv_sec);
    session->server_state = ss_waiting_to_connect;
    session->timer_ev = evtimer_new(ev_base, timer_connect_cb, session);
    evtimer_add(session->timer_ev, &(session->conn_wait_tv));
    scheduler_increase_connect_wait_time(session);
}

int send_reply(session_t *session, void *buff, uint32_t size)
{
    log_debug("Send reply to client(%d)", session->id);
    syslog_debug("Send reply to client(%d)", session->id);
    return write(session->control_sd, buff, size);
}
