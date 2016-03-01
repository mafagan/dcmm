#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <openssl/ssl.h>

#include "dcmm_utils.h"


#define SECOND_PER_DAY 3600
#define MICROSECOND_PER_SECOND 1000000

#define DCMM_COMMAND_PATH "dcmm"
#define DCMM_PROC_NAME "dcmm"
/**
 * Check if `target` is in `str`
 *
 * @return true if in, or false if not
 */
static bool str_find(const char *str, const char *target)
{
    assert(str && target);
    uint32_t i;
    for (i = 0; i < strlen(str); ++ i) {
        if (! strncmp(str + i, target, strlen(target))) {
            return true;
        }
    }
    return false;
}
static bool is_small_endian()
{
    union {
        uint16_t s;
        char c[2];
    } un;
    un.s = 0x0102;
    if (un.c[1] == 1 && un.c[0] == 2) {
        return true;
    }
    return false;
}
static float htonf(float f)
{
    float ret = f;
    if (is_small_endian()) {
        unsigned char *c = (unsigned char *)&ret;
        unsigned char tmp = c[0];
        c[0] = c[3];
        c[3] = tmp;
        tmp = c[1];
        c[1] = c[2];
        c[2] = tmp;
    }
    return ret;
}
static float ntohf(float f)
{
    return htonf(f);
}
void reset_header(dcmm_header_t *header)
{
    bzero(header, sizeof(dcmm_header_t));
    memcpy(header->magic, DCMM_MAGIC, DCMM_MAGIC_SIZE);
    header->version = DCMM_PROTOCOL_VERSION;
}
void network_transfer_header(dcmm_header_t *header)
{
    header->length = htons(header->length);
    header->msg_id = htonl(header->msg_id);
    header->cfm_id = htonl(header->cfm_id);
    header->reseved = htons(header->reseved);
}
void network_retransfer_header(dcmm_header_t *header)
{
    header->length = ntohs(header->length);
    header->msg_id = ntohl(header->msg_id);
    header->cfm_id = ntohl(header->cfm_id);
    header->reseved = ntohs(header->reseved);
}
void network_transfer_addr(dcmm_addr_t *addr)
{
    addr->port = htons(addr->port);
}
void network_retransfer_addr(dcmm_addr_t *addr)
{
    addr->port = ntohs(addr->port);
}
void network_transfer_status(dcmm_status_t *status)
{
    status->status = htonl(status->status);
    status->num_cached_msgs = htonl(status->num_cached_msgs);
    status->avg_sending_rate = htonf(status->avg_sending_rate);
    status->cur_allocated_rate = htonf(status->cur_allocated_rate);
}
void network_retransfer_status(dcmm_status_t *status)
{
    status->status = ntohl(status->status);
    status->num_cached_msgs = ntohl(status->num_cached_msgs);
    status->avg_sending_rate = ntohf(status->avg_sending_rate);
    status->cur_allocated_rate = ntohf(status->cur_allocated_rate);
}
void network_transfer_register_info(dcmm_register_info_t *info)
{
    info->priority = htonl(info->priority);
}
void network_retransfer_register_info(dcmm_register_info_t *info)
{
    info->priority = ntohl(info->priority);
}
/**
 * Check if the header of a package is valid
 *
 * @param dcmm_header a pointer of struct dcmm_header
 * @return 1 if valid, or 0 if invalid
 */
int is_header_valid(dcmm_header_t *header)
{
    if ((! strncmp(header->magic, "DCMM", 4)) &&
            header->version == DCMM_PROTOCOL_VERSION) {
        return true;
    }
    return false;
}

int fcntl_nonblock(int sd)
{
    int flags;
    int error;

    flags = fcntl(sd, F_GETFL);
    if (flags == -1) {
        return -1;
    }

    error = fcntl(sd, F_SETFL, flags | O_NONBLOCK);
    if (error) {
        return -1;
    }
    return 0;
}
int fcntl_block(int sd)
{
    int flags;
    int error;

    flags = fcntl(sd, F_GETFL);
    if (flags == -1) {
        return -1;
    }

    error = fcntl(sd, F_SETFL, flags ^ O_NONBLOCK);
    if (error) {
        return -1;
    }
    return 0;
}

int wait_till_ready(int sd, struct timeval *timeout)
{
    fd_set sds;
    int max_sd;

    max_sd = sd + 1;
    FD_ZERO(&sds);
    FD_SET(sd, &sds);
    if (select(max_sd, &sds, NULL, NULL, timeout) < 0) {
        return DCMM_SOCKET_ERR;
    }
    if (FD_ISSET(sd, &sds)) {
        return DCMM_SOCKET_READ_READY;
    }
    return DCMM_SOCKET_NOT_READ_READY;
}
int time_cmp(struct timeval *tv_1, struct timeval *tv_2)
{
    if (tv_1->tv_sec == tv_2->tv_sec) {
        return tv_1->tv_usec - tv_2->tv_usec;
    }
    return tv_1->tv_sec - tv_2->tv_sec;
}
struct timeval time_differ(struct timeval *tv_1, struct timeval *tv_2)
{
    struct timeval ret;
    if (tv_1->tv_usec < tv_2->tv_usec) {
        -- tv_1->tv_sec;
        tv_1->tv_usec += MICROSECOND_PER_SECOND;
    }
    ret.tv_sec = tv_1->tv_sec - tv_2->tv_sec;
    ret.tv_usec = tv_1->tv_usec - tv_2->tv_usec;
    return ret;
}
/**
 * Get the difference between two `timeval` in microseconds
 *
 * @param tv_1 the newer `timeval`
 * @param tv_2 the older `timeval`
 * @return the microseconds of the period
 */
uint32_t time_differ_in_microsecond(struct timeval *tv_1, struct timeval *tv_2)
{
    uint32_t ret = (tv_1->tv_sec - tv_2->tv_sec) * MICROSECOND_PER_SECOND +
                    (tv_1->tv_usec - tv_2->tv_usec);
    return ret;
}
/**
 * Get the difference between two `timeval` in seconds
 *
 * @param tv_1 the newer `timeval`
 * @param tv_2 the older `timeval`
 * @return the seconds of the period
 */
uint32_t time_differ_in_second(struct timeval *tv_1, struct timeval *tv_2)
{
    uint32_t ret = (tv_1->tv_sec - tv_2->tv_sec);
    return ret;
}
/**
 * Check if the dcmm if running
 * In this function, we will get the pid of `dcmm` in the `DCMM_PID_FILE`, and
 * get the process's status in the `/proc/pid/status`, if the name is equal to
 * `DCMM_PROC_NAME`, we consider `dcmm` is running
 *
 * @return true if running, or false if not
 */
bool is_dcmm_running()
{
    pid_t pid;
    FILE *f;
    int n;
    char buffer[DCMM_BUFF_SIZE];
    /* get dcmm's pid from the `pid file` */
    f = fopen(DCMM_PID_FILE, "r");
    if (f == NULL) {
        return false;
    }
    bzero(buffer, DCMM_BUFF_SIZE);
    n = fread(buffer, sizeof(char), DCMM_BUFF_SIZE, f);
    fclose(f);
    buffer[n] = '\0';
    pid = atoi(buffer);
    /* get process's status from `/proc/pid/status` */
    bzero(buffer, DCMM_BUFF_SIZE);
    snprintf(buffer, DCMM_BUFF_SIZE, "/proc/%d/status", pid);
    f = fopen(buffer, "r");
    if (f == NULL) {
        return false;
    }
    bzero(buffer, DCMM_BUFF_SIZE);
    fgets(buffer, DCMM_BUFF_SIZE, f);
    fclose(f);
    /* check if the process's name is correct */
    return str_find(buffer, DCMM_PROC_NAME);
}
/**
 * Run dcmm in daemon
 *
 * @return true if success, or false if failure
 */
bool run_dcmm()
{
#ifdef API_DEBUG
    printf("run_dcmm\n");
#endif
    struct rlimit rl;
    pid_t pid;
    int fd;
    uint32_t i;
    char *argv[] = {NULL};

    umask(0);
    /* get maximum number of file descriptors */
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        perror("can't get file limit\n");
        return false;
    }
    /* beconme a session leader to lose controlling tty */
    if ((pid = fork()) < 0) {
        perror("fork error\n");
        return false;
    }
    else if (pid != 0) {//parent, the client's process
        signal(SIGCHLD, SIG_IGN);
        /* wait 1 second, supposing that, it's enough for daemon setting up
         * `dcmm`*/
        sleep(1);
        return is_dcmm_running();
    }
    setsid();
    /* ensure future opens won't allocate controlling ttys */
    signal(SIGHUP, SIG_IGN);
    if ((pid = fork()) < 0) {
        perror("fork again error\n");
        exit(EXIT_FAILURE);
    }
    else if (pid != 0) {//parent
        exit(EXIT_SUCCESS);
    }
    /* change the current working directory */
    if (chdir("/") < 0) {
        perror("chdir\n");
        exit(EXIT_FAILURE);
    }
    /* close all open file descriptors */
    if (rl.rlim_max == RLIM_INFINITY) {
        rl.rlim_max = 1024;
    }
    for (i = 0; i < rl.rlim_max; ++ i) {
        close(i);
    }
    /* close stdin and attach stdout and stderr to `/dev/null` */
    close(STDIN_FILENO);
    fd = open("/dev/null", O_WRONLY);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    /* run `dcmm` */
    execvp(DCMM_COMMAND_PATH, argv);
    return true;
}
