#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/event.h>
#include <evhttp.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include <event.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <event2/event_compat.h>

#include "io_handler.h"
#include "http_https.h"
#include "logging.h"
#include "io_handler.h"
#include "session_manager.h"
#include "../lib/dcmm_utils.h"


extern struct event_base *ev_base;

static void http_send_reply(char MESSAGE_TYPE, int http_response_code, session_t *session, int body_len);
static void http_request_done(struct evhttp_request *req, void *session);

/*
 * send reply to client
 * @param msg_type result code for the request to dcmm
 * @param http_response_code response code from the request server
 * @param session session btween dcmm and client
 * @param body_len length of the respond content
 */
static void http_send_reply(char msg_type, int http_response_code,
        session_t *session, int body_len)
{

    char buf[HTTP_REP_HEADER_SIZE];
    char *req_1_byte = buf;
    int *ser_rep_code_4_byte = (int *)(buf + sizeof(char));
    int *body_len_4_byte = (int *)(buf+sizeof(char)+sizeof(int));

    *req_1_byte = msg_type;

    switch(msg_type)
    {
        case DCMM_HTTP_ERRORURL:
            *ser_rep_code_4_byte = 0;
            *body_len_4_byte = 0;
            break;

        case DCMM_HTTP_CANNOTCONNECT:
            *ser_rep_code_4_byte = 0;
            *body_len_4_byte = 0;
            break;

        case DCMM_HTTP_TIMEOUT:
            *ser_rep_code_4_byte = 0;
            *body_len_4_byte = 0;
            break;


        case DCMM_HTTP_UNKNOWNERROR:
            *ser_rep_code_4_byte = 0;
            *body_len_4_byte = 0;
            break;

        case DCMM_HTTP_SUCCESS:
            *ser_rep_code_4_byte = http_response_code;
            *body_len_4_byte = body_len;

        default:
            syslog_error("Error type in http_send_reply()");
            log_error("Error type in http_send_reply()");
            break;
    }

    printf("status_code: %d\n", (int)msg_type);
    printf("response_code: %d\n", http_response_code);
    printf("mag_len: %d\n", body_len+HTTP_REP_HEADER_SIZE);

    //printf("content_length: %d\n", *(int *))
    write(EVENT_FD(session->client_read_ev), buf, sizeof(char)+2*sizeof(int));
    return;
}
/*
 * callback function called when request was replied
 * @param req message of request
 * @param session session between dcmm and client
 */
static void http_request_done(struct evhttp_request *req, void *session)
{

    if(req == NULL)
    {
        log_error("req failed");
        syslog_error("req failed");
        http_send_reply(DCMM_HTTP_CANNOTCONNECT, 0, (session_t*)session, 0);
        return;
    }

    int response_code, len, send_len;
    char buffer[HTTP_BUF_SIZE];

    response_code = evhttp_request_get_response_code(req);
    len = EVBUFFER_LENGTH(req->input_buffer);
    printf("page source:\n %s", EVBUFFER_DATA(req->input_buffer));
    http_send_reply(DCMM_HTTP_SUCCESS, response_code, (session_t*)session, len);

    while((send_len = evbuffer_remove(req->input_buffer, buffer, HTTP_BUF_SIZE)) > 0)
    {
        int wr;
        wr = write(EVENT_FD(((session_t*)session)->client_read_ev), buffer, send_len);
    }
    return;
}

/*
 * make http request with URL indocated by client
 * @param url url to make request indicated by client
 * @param session message of the session between client and dcmm
 * */
void make_http_request(const char *url, session_t *session)
{
    struct evhttp_uri *http_uri;
    struct bufferevent *bev;
    struct evhttp_connection *evcon;
    struct evhttp_request *req;
    struct evkeyvalq *output_headers;
    struct evbuffer *output_buffer;
	const char *scheme, *host, *path, *query;
    int req_result, port;
	char uri[256];

    SSL_CTX *ssl_ctx;
    SSL *ssl;

    fprintf(stderr, "url: %s\n", url);
    http_uri = evhttp_uri_parse(url);
    if(http_uri== NULL)
    {
        log_error("url parse fail");
        syslog_error("url parse fail");
        http_send_reply(DCMM_HTTP_ERRORURL, 0, (session_t*)session, 0);
        return;
    }

    scheme = evhttp_uri_get_scheme(http_uri);
    if(scheme == NULL || (strcasecmp(scheme, "https") != 0 && strcasecmp(scheme, "http") !=  0))
    {
        log_error("url must be http or https");
        syslog_error("url must be http or https");
        http_send_reply(DCMM_HTTP_ERRORURL, 0, (session_t*)session, 0);
        return;
    }


    host = evhttp_uri_get_host(http_uri);
    if(host == NULL)
    {
        log_error("url must contain host");
        syslog_error("url must contain host");
        http_send_reply(DCMM_HTTP_ERRORURL, 0, (session_t*)session, 0);
        return;
    }

    port = evhttp_uri_get_port(http_uri);
    if(port == -1)
        port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;


    path = evhttp_uri_get_path(http_uri);
    if(path[0] == '\0')
    {
        path = "/";
    }


    query = evhttp_uri_get_query(http_uri);

    if(query == NULL)
    {
        //TODO check snprintf
        snprintf(uri, sizeof(uri), "%s", path);
    }else{

        snprintf(uri, sizeof(uri), "%s?%s", path, query);
    }
    uri[sizeof(uri)-1] = '\0';


    /* TODO find out what it did
    RAND_poll();
    */

    ssl_ctx = SSL_CTX_new(SSLv23_method());

    if(!ssl_ctx)
    {
        log_error("SSL_CTX_new()");
        syslog_error("SSL_CTX_new()");
        http_send_reply(DCMM_HTTP_UNKNOWNERROR, 0, (session_t*)session, 0);
        return;
    }

    if(strcasecmp(scheme, "http") == 0)
        bev = bufferevent_socket_new(ev_base, -1, BEV_OPT_CLOSE_ON_FREE);
    else
    {
        //TODO: https support needs libevent-2.1.x
        ;
    }

    if (bev == NULL)
    {
        log_error("bufferevent_(openssl)_socket_new()");
        syslog_error("bufferevent_(openssl)_socket_new()");
        http_send_reply(DCMM_HTTP_UNKNOWNERROR, 0, (session_t*)session, 0);
        return;
    }


    //TODO: needs libevent-2.1.x
    //evcon = evhttp_connection_base_bufferevent_new(ev_base, NULL, bev, host, port);
    evcon = evhttp_connection_base_new(ev_base, NULL, host, port);
    if(evcon == NULL)
    {
        log_error("evhttp_connection_base_new()");
        syslog_error("evhttp_connection_base_new()");
        http_send_reply(DCMM_HTTP_UNKNOWNERROR, 0, (session_t*)session, 0);
        return;
    }

    req = evhttp_request_new(http_request_done, session);

    if(req == NULL)
    {
        log_error("evhttp_request_new()");
        syslog_error("evhttp_request_new()");
        http_send_reply(DCMM_HTTP_UNKNOWNERROR, 0, (session_t*)session, 0);
        return;
    }

    evhttp_add_header(req->output_headers, "Host", host);
    evhttp_add_header(req->output_headers, "Connection", HEADER_CONNECTION);
    evhttp_add_header(req->output_headers, "User-agent", HEADER_USER_AGENT);

    req_result = evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);

    if(req_result != 0)
    {
        log_error("evhttp_make_request()");
        syslog_error("evhttp_make_request()");
        http_send_reply(DCMM_HTTP_UNKNOWNERROR, 0, (session_t*)session, 0);
        return;
    }

    return;
}

