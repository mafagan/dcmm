#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <sys/time.h>


#define DCMM_DATA_SOCKET_FILE "/tmp/dcmm.data.socket"
#define DCMM_CONTROL_SOCKET_FILE "/tmp/dcmm.control.socket"
#define DCMM_PID_FILE "/tmp/dcmm.pid"
#define DCMM_CONFIG_FILE "/etc/dcmm.conf"

#define DCMM_SOCKET_READ_READY 1
#define DCMM_SOCKET_NOT_READ_READY 2
#define DCMM_SOCKET_ERR 3

#define DCMM_MAGIC "DCMM"
#define DCMM_MAGIC_SIZE 4

#define DCMM_BUFF_SIZE 1024

#define DCMM_PROTOCOL_VERSION 1

#define DCMM_PROTOCOL_MQTT 1

#define DCMM_MSG_CONTROL_REPLY 2
#define DCMM_MSG_CONNECT_SVR 3
#define DCMM_MSG_CONNECT_REPLY 4
#define DCMM_MSG_SEND 5
#define DCMM_MSG_SEND_REPLY 6
#define DCMM_MSG_RECV 7
#define DCMM_MSG_STATUS 8
#define DCMM_MSG_STATUS_REPLY 9
#define DCMM_MSG_DELETE 10
#define DCMM_MSG_REGISTER_SESSION 11
#define DCMM_MSG_REGISTER_SESSION_REPLY 12
#define DCMM_MSG_DISCONNECT 14
#define DCMM_MSG_TLS 15
#define DCMM_MSG_HTTP_HTTPS 16

#define DCMM_RUN_FAILURE 0
#define DCMM_RUN_SUCCESS 1
#define DCMM_RUNNING 2

#define DCMM_OPT_NOWAIT 1
#define DCMM_OPT_EXPECTREPLY 2
#define DCMM_OPT_BLOCKING 3

#define DCMM_CONN_IN_PROGRESS 1
#define DCMM_CONN_READY 2
#define DCMM_CONN_STALLED 3
#define DCMM_CONN_NETERR 4

#define DCMM_OP_SUCCESS 1
#define DCMM_OP_FAILURE 2
#define DCMM_OP_IN_PROGRESS 3
#define DCMM_OP_NO_REPLY 4

#define DCMM_PRIORITY_PLATINUM 0
#define DCMM_PRIORITY_GOLD 1
#define DCMM_PRIORITY_SILVER 2


#define DCMM_IP_SIZE 126
#define DCMM_FILE_SIZE 128

#define DCMM_HTTP_ERRORURL      0
#define DCMM_HTTP_CANNOTCONNECT 1
#define DCMM_HTTP_TIMEOUT       2
#define DCMM_HTTP_SUCCESS       3
#define DCMM_HTTP_UNKNOWNERROR  4


typedef int dsocket_t;

typedef struct dcmm_header {
    char magic[4];
    uint32_t version:8;
    uint32_t type:8;
    uint32_t length:16;

    uint32_t msg_id;
    uint32_t cfm_id;
    uint32_t opt:8;
    uint32_t flags:8;
    uint32_t reseved:16;
} dcmm_header_t;

typedef struct dcmm_addr {
    uint16_t port;
    char ip[DCMM_IP_SIZE];
} dcmm_addr_t;

typedef struct dcmm_register_info {
    int priority;
} dcmm_register_info_t;

typedef struct dcmm_status {
    int status;
    uint32_t num_cached_msgs;
    float avg_sending_rate;
    float cur_allocated_rate;
} dcmm_status_t;

typedef struct dcmm_tls {
    char ca_file[DCMM_FILE_SIZE];
    char ca_path[DCMM_FILE_SIZE];
    char cert_file[DCMM_FILE_SIZE];
    char key_file[DCMM_FILE_SIZE];
} dcmm_tls_t;


#ifndef bool
#define bool uint8_t
#endif
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

void reset_header(dcmm_header_t *header);
int is_header_valid(dcmm_header_t *header);
void network_transfer_header(dcmm_header_t *header);
void network_retransfer_header(dcmm_header_t *header);
void network_transfer_addr(dcmm_addr_t *addr);
void network_retransfer_addr(dcmm_addr_t *addr);
void network_transfer_status(dcmm_status_t *status);
void network_retransfer_status(dcmm_status_t *status);
void network_transfer_register_info(dcmm_register_info_t *info);
void network_retransfer_register_info(dcmm_register_info_t *info);

int fcntl_nonblock(int sd);
int fcntl_block(int sd);
int wait_till_ready(int sd, struct timeval *timeout);
int time_cmp(struct timeval *tv_1, struct timeval *tv_2);
struct timeval time_differ(struct timeval *tv_1, struct timeval *tv_2);
uint32_t time_differ_in_microsecond(struct timeval *tv_1, struct timeval *tv_2);
uint32_t time_differ_in_second(struct timeval *tv_1, struct timeval *tv_2);
bool is_dcmm_running();
bool run_dcmm();

#endif
