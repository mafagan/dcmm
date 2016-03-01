#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* include this header file */
#include <mosquitto_dcmm.h>

static int connected = 1;
/* when connecting successfully, this function will be called */
void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
    char *message = "hello";
    char *topic = "test";
    int mid_sent = 0;
    int retain = 0;
    int qos = 1;
    int rc = mosquitto_publish(mosq, &mid_sent, topic, 5,
            message, qos, retain);
}
/* when moquitto_disconnect() is called, and disconnect successfully,
 * this function will be called */
void my_disconnect_callback(struct mosquitto *mosq, void *obj, int rc)
{
    /* we should break the loop in main function now */
    connected = 0;
}
/* when publishing successfully, this function will be called */
void my_publish_callback(struct mosquitto *mosq, void *obj, int mid)
{
    mosquitto_disconnect(mosq);
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
    printf("%s\n", str);
}

int main()
{
    struct mosquitto *mosq = NULL;
    const char *id = "mosq_dcmm";
    const char *host = "localhost";
    short port = 1883;
    int use_dcmm = 0;
    int keepalive = 10;
    unsigned int max_inflight = 20;
    int rc = 0;

    mosquitto_lib_init();

    /* the new `use_dcmm` parameter is one of the changes we made to mosquitto
     * library API, set `use_dcmm` to 0, will turn off the DCMM feature */
    mosq = mosquitto_new(id, true, NULL, use_dcmm);

    /* the main function u should change */
    mosquitto_tls_set(mosq, "/home/ubuntu/ssl/test-root-ca.crt", NULL,
            "/home/ubuntu/ssl/client.crt", "/home/ubuntu/ssl/client.key", NULL);
    mosquitto_connect_callback_set(mosq, my_connect_callback);
    mosquitto_disconnect_callback_set(mosq, my_disconnect_callback);
    mosquitto_publish_callback_set(mosq, my_publish_callback);

    /* log message */
    mosquitto_log_callback_set(mosq, my_log_callback);

    rc = mosquitto_connect_bind(mosq, host, port, keepalive, NULL);
    if (rc) {
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        exit(EXIT_FAILURE);
    }

    do {
        mosquitto_loop(mosq, -1, 1);
    } while (connected);


    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    return 0;
}
