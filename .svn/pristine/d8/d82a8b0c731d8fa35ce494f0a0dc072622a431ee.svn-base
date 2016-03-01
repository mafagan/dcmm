#ifndef HTTP_HTTPS_H
#define HTTP_HTTPS_H

#include "session_manager.h"
#include <event.h>

#define HTTP_BUF_SIZE 10000
#define HTTP_REP_HEADER_SIZE (2*sizeof(int)+sizeof(char))
#define HEADER_CONNECTION "keep-alive" 
#define HEADER_USER_AGENT "DCMM"

void make_http_request(const char *url, session_t *session);

#endif
