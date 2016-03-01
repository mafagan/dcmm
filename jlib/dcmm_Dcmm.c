#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "dcmm_Dcmm.h"
#include "../lib/dcmm_utils.h"

#define SLEEP_TIME 100
#define WAIT_TIME 100000

#define API_DEBUG
#undef API_DEBUG


static int library_id = -1;
static pthread_mutex_t mutex_msg_id = PTHREAD_MUTEX_INITIALIZER;
static uint32_t msg_id = 1;
static pthread_mutex_t mutex_control_socket = PTHREAD_MUTEX_INITIALIZER;
static int control_sd = -1;
static struct timeval tv_wait = {.tv_sec=0, .tv_usec=WAIT_TIME};

static int get_new_msg_id();
static bool init_control_socket();
static int loop_check_status(int id, struct timeval *timeout,
        dcmm_status_t *status);
/**
 * Generate a new message id, thread safe
 *
 * @return a new message id
 */
static int get_new_msg_id()
{
    int ret = -1;
    pthread_mutex_lock(&mutex_msg_id);
    ret = msg_id ++;
    pthread_mutex_unlock(&mutex_msg_id);
    return ret;
}
/**
 * Initialize the control socket to the `dcmm`, for the whole progress
 *
 * @return TRUE if success, or FALSE if not
 */
static bool init_control_socket()
{
    struct sockaddr_un un;
    uint32_t size_un = 0;
    int keepalive = 0;
    void *buff = NULL;

    if (control_sd != -1) {
        return true;
    }

    control_sd = socket(AF_UNIX, SOCK_STREAM, 0);
    keepalive = 1;
    size_un = sizeof(un);

    bzero(&un, size_un);
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, DCMM_CONTROL_SOCKET_FILE);

    if (connect(control_sd, (struct sockaddr *)&un, size_un) < 0) {
        perror("connect control socket failed\n");
        control_sd = -1;
        return false;
    }

    if (setsockopt(control_sd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
                sizeof(keepalive)) < 0) {
        perror("setsockopt failed\n");
        close(control_sd);
        control_sd = -1;
        return false;
    }

    buff = malloc(DCMM_BUFF_SIZE);

    read(control_sd, buff, sizeof(dcmm_header_t));
    read(control_sd, buff, sizeof(int));
    library_id = ntohl(*((uint32_t *)buff));

    fcntl_nonblock(control_sd);
#ifdef API_DEBUG
    printf("control sd: %d\n", control_sd);
#endif

    return true;
}
/**
 * Loop to check if `dcmm` have finished the operation
 *
 * @param op_id the operation's id
 * @param timeout if NULL, then forever
 * @status only used for `dcmm_status`
 */
static int loop_check_status(int op_id, struct timeval *timeout,
        dcmm_status_t *status)
{
#ifdef API_DEBUG
    printf("loop_check_status\n");
#endif
    struct timeval tv_begin;
    struct timeval tv_curr;
    struct timeval tv_diff;
    dcmm_header_t header;
    uint32_t size_header;
    int ret;

    size_header = sizeof(dcmm_header_t);
    gettimeofday(&tv_begin, NULL);
    while (true) {
        pthread_mutex_lock(&mutex_control_socket);
        gettimeofday(&tv_curr, NULL);
        tv_diff = time_differ(&tv_curr, &tv_begin);
        /* timeout */
        if (timeout != NULL &&
                time_cmp(&tv_diff, timeout) > 0) {
            pthread_mutex_unlock(&mutex_control_socket);
            return DCMM_OP_IN_PROGRESS;
        }
        /* wait for data */
        if ((ret = wait_till_ready(control_sd, &tv_wait)) == DCMM_SOCKET_READ_READY) {
            reset_header(&header);
            read(control_sd, &header, size_header);
            network_retransfer_header(&header);
            if (header.cfm_id == op_id) {
                if (header.type == DCMM_MSG_STATUS_REPLY) {
                    read(control_sd, status, header.length - size_header);
                    network_retransfer_status(status);
                }
                pthread_mutex_unlock(&mutex_control_socket);
                return DCMM_OP_SUCCESS;
            }
        }
        else if (ret == DCMM_SOCKET_ERR) {
            pthread_mutex_unlock(&mutex_control_socket);
            return DCMM_OP_FAILURE;
        }
        pthread_mutex_unlock(&mutex_control_socket);
        usleep(SLEEP_TIME);
    }
}
/*
 * Class:     dcmm_Dcmm
 * Method:    getStruct
 * Signature: ()Ldcmm/DcmmHeader;
 */
JNIEXPORT jobject JNICALL Java_dcmm_Dcmm_getStruct(JNIEnv *env, jobject obj) {
    jclass obj_class = (*env)->FindClass(env, "DcmmHeader");
    jfieldID str = (*env)->GetFieldID(env, obj_class, "magic",
            "Ljava/lang/String;");
    jfieldID ival = (*env)->GetFieldID(env, obj_class, "version",
            "J");
    (*env)->SetObjectField(env, obj_class, str,
            (*env)->NewStringUTF(env, "hello world"));
    (*env)->SetLongField(env, obj_class, ival, 100);

    return obj_class;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    test
 * Signature: ()V
 */

JNIEXPORT void JNICALL Java_dcmm_Dcmm_test(JNIEnv *env, jobject obj) {
    printf("hello world\n");
}
/*
 * Class:     dcmm_Dcmm
 * Method:    init
 * Signature: ()I
 */
/**
 * Initialize the `dcmm`
 *
 * @return `DCMM_RUNNING` if `dcmm` is already running
 *         `DCMM_RUN_SUCCESS` if run successfully
 *         `DCMM_RUN_FAILURE` if run failed
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_init(JNIEnv *env,
        jobject obj) {
    if (is_dcmm_running()) {
        init_control_socket();
        return DCMM_RUNNING;
    }
    if (run_dcmm()) {
        init_control_socket();
        return DCMM_RUN_SUCCESS;
    }
    return DCMM_RUN_FAILURE;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    destroy
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_dcmm_Dcmm_destroy(JNIEnv *env,
        jobject obj) {
    pthread_mutex_lock(&mutex_control_socket);
    close(control_sd);
    pthread_mutex_unlock(&mutex_control_socket);
}
/*
 * Class:     dcmm_Dcmm
 * Method:    socket
 * Signature: (I)I
 */
/**
 * Create a local channel to the local `dcmm` server
 *
 * @return a socket handler `dsocket_t`
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_socket(JNIEnv *env,
        jobject obj, jint type) {
    dsocket_t dsocket = -1;
    struct sockaddr_un un;

    dsocket = socket(AF_UNIX, SOCK_STREAM, 0);
    /* create unix socket for control */
    bzero(&un, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, DCMM_DATA_SOCKET_FILE);

    if (connect(dsocket, (struct sockaddr *)&un, sizeof(un)) < 0) {
        perror("connect dcmm failed\n");
        dsocket = -1;
        return dsocket;
    }
    write(dsocket, &library_id, sizeof(library_id));

    return dsocket;
}

dsocket_t dcmm_socket(int type)
{
    dsocket_t dsocket = -1;
    struct sockaddr_un un;

    dsocket = socket(AF_UNIX, SOCK_STREAM, 0);
    /* create unix socket for control */
    bzero(&un, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, DCMM_DATA_SOCKET_FILE);

    if (connect(dsocket, (struct sockaddr *)&un, sizeof(un)) < 0) {
        perror("connect dcmm failed\n");
        dsocket = -1;
        return dsocket;
    }
    write(dsocket, &library_id, sizeof(library_id));

    return dsocket;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    registerSession
 * Signature: (II)I
 */
/**
 * Update the session's setting
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_registerSession(JNIEnv *env,
        jobject obj, jint dsocket, jint priority) {
    dcmm_header_t header;
    dcmm_register_info_t info;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    uint32_t size = 0;
    void *buff = NULL;
    uint32_t op_id = -1;
    struct iovec iov[2];

    size_header = sizeof(dcmm_header_t);
    size_body = sizeof(dcmm_register_info_t);
    size = size_header + size_body;

    reset_header(&header);
    header.type = DCMM_MSG_REGISTER_SESSION;
    header.length = size;
    header.msg_id = get_new_msg_id();

    info.priority = priority;

    op_id = header.msg_id;

    network_transfer_header(&header);
    network_transfer_register_info(&info);

    iov[0].iov_base = &header;
    iov[0].iov_len = size_header;
    iov[1].iov_base = &info;
    iov[1].iov_len = size_body;

    writev(dsocket, iov, 2);
    return loop_check_status(op_id, NULL, NULL);
}
/*
 * Class:     dcmm_Dcmm
 * Method:    connect
 * Signature: (ILdcmm/DcmmAddr;ILdcmm/Timeval;)I
 */
/**
 * Send a connect command to `dcmm`
 *
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_connect(JNIEnv *env,
        jobject obj, jint dsocket, jobject obj_dcmm_addr,
        jint options, jobject obj_timeout) {
#ifdef API_DEBUG
    printf("dcmm_connect\n");
#endif
    assert(options == DCMM_OPT_NOWAIT || options == DCMM_OPT_BLOCKING);

    dcmm_header_t header;
    int protocol;
    int n = 0;
    void *buff = NULL;
    uint32_t conn_id = -1;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    struct iovec iov[3];


    jclass dcmm_addr_class = (*env)->GetObjectClass(env,
            obj_dcmm_addr);
    if (dcmm_addr_class == NULL) {
        printf("GetObjectClass failed\n");
    }
    jfieldID port_fieldID = (*env)->GetFieldID(env, dcmm_addr_class,
            "port", "I");
    jfieldID ip_fieldId = (*env)->GetFieldID(env, dcmm_addr_class,
            "ip", "Ljava/lang/String;");
    jint port = (*env)->GetIntField(env, obj_dcmm_addr,
            port_fieldID);
    jstring ip = (jstring)(*env)->GetObjectField(env,
            obj_dcmm_addr, ip_fieldId);
    const char *ip_ptr = (*env)->GetStringUTFChars(env, ip, NULL);
    dcmm_addr_t dcmm_addr;
    dcmm_addr.port = port;
    strcpy(dcmm_addr.ip, ip_ptr);
#ifdef API_DEBUG
    printf("port:%d\n", port);
    printf("ip_addr:%s\n", ip_ptr);
#endif

    jclass timeval_class = (*env)->GetObjectClass(env, obj_timeout);
    if (timeval_class == NULL) {
        printf("GetObjectClass failed\n");
    }
    jfieldID tv_sec_fieldID = (*env)->GetFieldID(env,
            timeval_class, "tvSec", "J");
    jfieldID tv_usec_fieldID = (*env)->GetFieldID(env,
            timeval_class, "tvUsec", "J");
    jlong tv_sec = (*env)->GetLongField(env, obj_timeout,
            tv_sec_fieldID);
    jlong tv_usec = (*env)->GetLongField(env, obj_timeout,
            tv_usec_fieldID);
    struct timeval timeout;
    timeout.tv_sec = tv_sec;
    timeout.tv_usec = tv_usec;
#ifdef API_DEBUG
    printf("timeout.tv_sec:%ld\n", timeout.tv_sec);
    printf("timeout.tv_usec:%ld\n", timeout.tv_usec);
#endif

    size_header = sizeof(dcmm_header_t);
    size_body = sizeof(dcmm_addr_t) + sizeof(int);


    reset_header(&header);
    header.type = DCMM_MSG_CONNECT_SVR;
    header.msg_id = get_new_msg_id();
    header.length = size_header + size_body;
    header.opt = options;

    conn_id = header.msg_id;

    //*protocol = htonl(DCMM_PROTOCOL_MQTT);
    protocol = htonl(0);
    network_transfer_header(&header);
    network_transfer_addr(&dcmm_addr);

    iov[0].iov_base = &header;
    iov[0].iov_len = size_header;
    iov[1].iov_base = &dcmm_addr;
    iov[1].iov_len = sizeof(dcmm_addr_t);
    iov[2].iov_base = &protocol;
    iov[2].iov_len = sizeof(int);

    n = writev(dsocket, iov, 3);
    if (n <= 0) {
        return DCMM_OP_FAILURE;
    }

    if (options == DCMM_OPT_NOWAIT) {
        return DCMM_OP_IN_PROGRESS;
    }
    else {
        return loop_check_status(conn_id, &timeout, NULL);
    }
}
/*
 * Class:     dcmm_Dcmm
 * Method:    disconnect
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_disconnect(JNIEnv *env,
        jobject obj, jint dsocket) {
    dcmm_header_t header;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    int n = 0;

    size_header = sizeof(dcmm_header_t);

    reset_header(&header);
    header.type = DCMM_MSG_DISCONNECT;
    header.length = size_header;

    network_transfer_header(&header);
    n = write(dsocket, &header, size_header);
    return n == size_header;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    sendEx
 * Signature: (I[BJILdcmm/Timeval;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_sendEx(JNIEnv *env,
        jobject obj, jint dsocket, jbyteArray java_data,
        jlong size_data, jint options, jobject obj_timeout) {
#ifdef API_DEBUG
    printf("enter dcmm send\n");
#endif
    assert(options == DCMM_OPT_NOWAIT || options == DCMM_OPT_BLOCKING ||
            options == DCMM_OPT_EXPECTREPLY);

    dcmm_header_t header;
    int n = 0;
    int ret = 0;
    uint32_t send_id = -1;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    struct iovec iov[2];

    size_header = sizeof(dcmm_header_t);
    size_body = size_data;

    int length = (*env)->GetArrayLength(env, java_data);
#ifdef API_DEBUG
    printf("send data length = %d\n", length);
#endif
    char *data = NULL;
    data = (char *)malloc(length);
    (*env)->GetByteArrayRegion(env, java_data, 0, length, data);
#ifdef API_DEBUG
    printf("send msg : %s\n", data);
#endif

    jclass timeval_class = (*env)->GetObjectClass(env, obj_timeout);

    if (timeval_class == NULL) {
        printf("GetObjectClass failed\n");
    }
    jfieldID tv_sec_fieldID = (*env)->GetFieldID(env, timeval_class,
            "tvSec", "J");
    jfieldID tv_usec_fieldID = (*env)->GetFieldID(env, timeval_class,
            "tvUsec", "J");
    jlong tv_sec = (*env)->GetLongField(env, obj_timeout,
            tv_sec_fieldID);
    jlong tv_usec = (*env)->GetLongField(env, obj_timeout,
            tv_usec_fieldID);
    struct timeval timeout;
    timeout.tv_sec = tv_sec;
    timeout.tv_usec = tv_usec;

    reset_header(&header);
    header.type = DCMM_MSG_SEND;
    header.length = size_header + size_body;
    header.msg_id = get_new_msg_id();
    header.opt = options;

    send_id = header.msg_id;

    network_transfer_header(&header);

    iov[0].iov_base = &header;
    iov[0].iov_len = size_header;
    iov[1].iov_base = data;
    iov[1].iov_len = size_body;

    n = writev(dsocket, iov, 2);

    if (n <= 0) {
        return DCMM_OP_FAILURE;
    }

    if (options == DCMM_OPT_NOWAIT) {
        return n - size_header;
    }
    else if (options == DCMM_OPT_EXPECTREPLY) {
        if ((ret = wait_till_ready(dsocket, &timeout)) == DCMM_SOCKET_READ_READY) {
            return DCMM_OP_SUCCESS;
        }
        else if (ret == DCMM_SOCKET_NOT_READ_READY) {
            return DCMM_OP_NO_REPLY;
        }
        else {
            return DCMM_OP_FAILURE;
        }
    }
    else {
        return loop_check_status(send_id, &timeout, NULL);
    }
}
/*
 * Class:     dcmm_Dcmm
 * Method:    send
 * Signature: (I[BJ)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_send(JNIEnv *env,
        jobject obj, jint dsocket, jbyteArray java_data,
        jlong size_data) {
#ifdef API_DEBUG
    printf("enter dcmm send\n");
#endif
    int options = DCMM_OPT_NOWAIT;
    dcmm_header_t header;
    int n = 0;
    int ret = 0;
    uint32_t send_id = -1;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    struct iovec iov[2];

    size_header = sizeof(dcmm_header_t);
    size_body = size_data;

    int length = (*env)->GetArrayLength(env, java_data);
#ifdef API_DEBUG
    printf("send data length = %d\n", length);
#endif
    char *data = NULL;
    data = (char *)malloc(length);
    (*env)->GetByteArrayRegion(env, java_data, 0, length, data);
#ifdef API_DEBUG
    printf("send msg : %s\n", data);
#endif

    reset_header(&header);
    header.type = DCMM_MSG_SEND;
    header.length = size_header + size_body;
    header.msg_id = get_new_msg_id();
    header.opt = options;

    send_id = header.msg_id;

    network_transfer_header(&header);

    iov[0].iov_base = &header;
    iov[0].iov_len = size_header;
    iov[1].iov_base = data;
    iov[1].iov_len = size_body;

    n = writev(dsocket, iov, 2);

    if (n <= 0) {
        return DCMM_OP_FAILURE;
    }

    return n - size_header;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    recvEx
 * Signature: (I[BJILdcmm/Timeval;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_recvEx(JNIEnv *env,
        jobject obj, jint dsocket, jbyteArray java_data,
        jlong size_data, jint options, jobject obj_timeout){
    assert(options == DCMM_OPT_NOWAIT || options == DCMM_OPT_BLOCKING);

    dcmm_header_t header;
    int n = 0;
    int ret = 0;
    void *data = NULL;
    uint32_t size_header = 0;
    int length = (*env)->GetArrayLength(env, java_data);

    size_header = sizeof(dcmm_header_t);

    data = malloc(size_data);
    reset_header(&header);

    jclass timeval_class = (*env)->GetObjectClass(env, obj_timeout);
    if (timeval_class == NULL) {
        printf("GetObjectClass failed\n");
    }
    jfieldID tv_sec_fieldID = (*env)->GetFieldID(env, timeval_class,
            "tvSec", "J");
    jfieldID tv_usec_fieldID = (*env)->GetFieldID(env, timeval_class,
            "tvUsec", "J");
    jlong tv_sec = (*env)->GetLongField(env, obj_timeout,
            tv_sec_fieldID);
    jlong tv_usec = (*env)->GetLongField(env, obj_timeout,
            tv_usec_fieldID);
    struct timeval timeout;
    timeout.tv_sec = tv_sec;
    timeout.tv_usec = tv_usec;

    if (options == DCMM_OPT_NOWAIT) {
        n = read(dsocket, &header, size_header);
        if (n <= 0) {
            free(data);
            return 0;
        }
        network_retransfer_header(&header);
        n = read(dsocket, data, header.length - size_header);
        (*env)->SetByteArrayRegion(env, java_data, 0, length,
                (jbyte*)data);
        free(data);
        return n;
    }
    else {
        if ((ret = wait_till_ready(dsocket, &timeout)) == DCMM_SOCKET_READ_READY) {
            n = read(dsocket, &header, size_header);
            network_retransfer_header(&header);
            n = read(dsocket, data, header.length - size_header);
            (*env)->SetByteArrayRegion(env, java_data, 0, length,
                    (jbyte*)data);
            free(data);
            return n;
        }
        else if (ret == DCMM_SOCKET_NOT_READ_READY) {
            free(data);
            return 0;
        }
        else {
            free(data);
            return -1;
        }
    }
}
/*
 * Class:     dcmm_Dcmm
 * Method:    recv
 * Signature: (I[BJ)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_recv(JNIEnv *env,
        jobject obj, jint dsocket, jbyteArray java_data,
        jlong size_data) {
    int ret;
    void *data = NULL;
    data = malloc(size_data);
    int length = (*env)->GetArrayLength(env, java_data);

    ret = read(dsocket, data, size_data);
    (*env)->SetByteArrayRegion(env, java_data, 0, length,
            (jbyte*)data);
    free(data);
    return ret;
}


/*
 * Class:     dcmm_Dcmm
 * Method:    status
 * Signature: (ILdcmm/DcmmStatus;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_status(JNIEnv *env,
        jobject obj, jint dsocket, jobject obj_dcmm_status) {
    dcmm_header_t header;
    uint32_t size_header;
    uint32_t op_id;

    jclass dcmm_status_class = (*env)->GetObjectClass(env,
            obj_dcmm_status);
    if (dcmm_status_class == NULL) {
        printf("GetObjectClass failed\n");
    }
    jfieldID status_fieldID = (*env)->GetFieldID(env,
            dcmm_status_class, "status", "I");
    jfieldID num_cached_msgs_fieldID = (*env)->GetFieldID(env,
            dcmm_status_class, "numCachedMsgs", "J");
    jfieldID avg_sending_rate_fieldID = (*env)->GetFieldID(env,
            dcmm_status_class, "avgSendingRate", "F");
    jfieldID cur_allocated_rate_fieldID = (*env)->GetFieldID(env,
            dcmm_status_class, "curAllocatedRate", "F");
    jint status = (*env)->GetIntField(env, obj_dcmm_status,
            status_fieldID);
    jlong num_cached_msgs = (*env)->GetLongField(env, obj_dcmm_status,
            num_cached_msgs_fieldID);
    jfloat avg_sending_rate = (*env)->GetFloatField(env,
            obj_dcmm_status, avg_sending_rate_fieldID);
    jfloat cur_allocated_rate = (*env)->GetFloatField(env,
            obj_dcmm_status, cur_allocated_rate_fieldID);
    dcmm_status_t dcmm_status;
    dcmm_status.status = status;
    dcmm_status.num_cached_msgs = num_cached_msgs;
    dcmm_status.avg_sending_rate = avg_sending_rate;
    dcmm_status.cur_allocated_rate = cur_allocated_rate;

    size_header = sizeof(dcmm_header_t);

    reset_header(&header);
    header.type = DCMM_MSG_STATUS;
    header.length = size_header;
    header.msg_id = get_new_msg_id();

    op_id = header.msg_id;

    network_transfer_header(&header);

    write(dsocket, &header, size_header);
    return loop_check_status(op_id, NULL, &dcmm_status);
}
/*
 * Class:     dcmm_Dcmm
 * Method:    close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_close(JNIEnv *env,
        jobject obj, jint dsocket) {
    int ret = 0;
    if (close(dsocket) < 0) {
        ret = -1;
    }
    dsocket = -1;
    return ret;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    delete
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_delete(JNIEnv *env,
        jobject obj, jint dsocket) {
    dcmm_header_t header;
    uint32_t size_header = sizeof(dcmm_header_t);

    reset_header(&header);
    header.type = DCMM_MSG_DELETE;
    header.length = size_header;

    network_transfer_header(&header);

    if (write(dsocket, &header, size_header) == size_header) {
        return 0;
    }
    return -1;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    tlsSet
 * Signature: (ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_tlsSset(JNIEnv *env,
        jobject obj, jint dsocket, jstring jca_file,
        jstring jca_path, jstring jcert_file, jstring jkey_file) {
    const char *ca_file = (*env)->GetStringUTFChars(env,
            jca_file, NULL);
    const char *ca_path = (*env)->GetStringUTFChars(env,
            jca_path, NULL);
    const char *cert_file = (*env)->GetStringUTFChars(env,
            jcert_file, NULL);
    const char *key_file = (*env)->GetStringUTFChars(env,
            jkey_file, NULL);
#ifdef DEBUG_API
    printf("dcmm_tls_set:\n");
    printf("ca_file: %s\n", (ca_file ? ca_file : "NULL"));
    printf("ca_path: %s\n", (ca_path ? ca_path : "NULL"));
    printf("cert_file: %s\n", (cert_file ? cert_file : "NULL"));
    printf("key_file: %s\n", (key_file ? key_file : "NULL"));
#endif
    if ((! ca_file && ! ca_path) || (cert_file && ! key_file) || (! cert_file && key_file)) {
        return DCMM_OP_FAILURE;
    }

    dcmm_header_t header;
    dcmm_tls_t tls;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    struct iovec iov[2];
    int op_id = -1;
    int n = 0;

    size_header = sizeof(header);
    size_body = sizeof(tls);

    reset_header(&header);
    header.type = DCMM_MSG_TLS;
    header.length = size_header + size_body;
    header.msg_id = get_new_msg_id();
    op_id = header.msg_id;
    network_transfer_header(&header);

    bzero(&tls, size_body);
    if (ca_file != NULL)
        strcpy(tls.ca_file, ca_file);
    else
        tls.ca_file[0] = '\0';

    if (ca_path != NULL)
        strcpy(tls.ca_path, ca_path);
    else
        tls.ca_path[0] = '\0';

    if (cert_file != NULL)
        strcpy(tls.cert_file, cert_file);
    else
        tls.cert_file[0] = '\0';

    if (key_file != NULL)
        strcpy(tls.key_file, key_file);
    else
        tls.key_file[0] = '\0';

    iov[0].iov_base = &header;
    iov[0].iov_len = size_header;
    iov[1].iov_base = &tls;
    iov[1].iov_len = size_body;

    n = writev(dsocket, iov, 2);
    if (n == size_header + size_body) {
        return DCMM_OP_SUCCESS;
    }
    return DCMM_OP_FAILURE;
}
/*
 * Class:     dcmm_Dcmm
 * Method:    httpHttpsGet
 * Signature: (Ljava/lang/String;[BI)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_httpHttpsGet(JNIEnv *env,
        jclass c, jstring jurl, jbyteArray jbuff, jint max_size) {
    printf("http https get\n");
    dsocket_t dsocket = dcmm_socket(0);
    dcmm_header_t header;
    uint32_t size_header = 0;
    uint32_t size_body = 0;
    struct iovec iov[2];
    int len;
    int n;
    char *buff = NULL;
    int length = (*env)->GetArrayLength(env, jbuff);
    const char *url = (*env)->GetStringUTFChars(env, jurl, NULL);

    buff = (char*)malloc(max_size);
    len = strlen(url) + 1;

    size_header = sizeof(header);
    size_body = len;

    reset_header(&header);
    header.type = DCMM_MSG_HTTP_HTTPS;
    header.length = size_header + size_body;
    header.msg_id = get_new_msg_id();
    network_transfer_header(&header);

    iov[0].iov_base = &header;
    iov[0].iov_len = size_header;
    iov[1].iov_base = (void *)url;
    iov[1].iov_len = size_body;

    n = writev(dsocket, iov, 2);

    if(n != size_header + size_body)
        return DCMM_OP_FAILURE;

    int rec_len = 0;
    int rec_all_len = 0;
    int content_len;

    rec_len = read(dsocket, buff, max_size);


    rec_all_len += rec_len;
    content_len = *((int *)(buff+5));

    while(rec_all_len<max_size && rec_all_len<content_len+9)
    {
        rec_len = read(dsocket, buff+rec_all_len, max_size-rec_all_len);
        rec_all_len += rec_len;
    }

    (*env)->SetByteArrayRegion(env, jbuff, 0, length, (jbyte*)buff);
    free(buff);

    return DCMM_OP_SUCCESS;

}

