#ifndef DCMM_H
#define DCMM_H

#include <stdint.h>
#include <sys/time.h>

#include "dcmm_utils.h"

int dcmm_init() __attribute__((constructor));
void dcmm_destroy() __attribute__((destructor));

struct dcmm_header;
struct dcmm_addr;
struct dcmm_register_info;
struct dcmm_status;
struct dcmm_tls;

int dcmm_init();
void dcmm_destroy();
dsocket_t dcmm_socket(int type);
int dcmm_register_session(dsocket_t dsocket, int priority);
int dcmm_connect(dsocket_t dsocket, struct dcmm_addr *addr,
        int options, struct timeval *timeout);
int dcmm_disconnect(dsocket_t dsocket);

int dcmm_send_ex(dsocket_t dsocket, void *data, uint32_t size_data,
        int options, struct timeval *timeout);
int dcmm_send(dsocket_t dsocket, void *data, uint32_t size_data);
int dcmm_recv_ex(dsocket_t dsocket, void *data, uint32_t size_data,
        int options, struct timeval *timeout);
int dcmm_recv(dsocket_t dsocket, void *data, uint32_t size_data);

int dcmm_status(dsocket_t dsocket, struct dcmm_status *status);

int dcmm_close(dsocket_t dsocket);
int dcmm_delete(dsocket_t dsocket);
int dcmm_tls_set(dsocket_t dsocket, const char *ca_file, const char *ca_path,
        const char *cert_file, const char *key_file);
int dcmm_http_https_get(const char *url, char *buff, int max_size);


#endif
