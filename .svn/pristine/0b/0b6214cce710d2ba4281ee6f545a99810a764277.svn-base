#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

/* include this header file */
#include <mosquitto_dcmm.h>

static int connected = 1;
struct mosquitto *mosq = NULL;
pthread_t tid = -1;

void *send_proc(void *p)
{
	long id = 0;
	char message[64];
	char *topic = "test";
	int mid_sent = 0;
	int retain = 0;
	int qos = 0;
	int rc;
	struct timespec ts;
	double t, nextt = 0.0f;

	while (connected) {
		clock_gettime(CLOCK_REALTIME_COARSE, &ts);
		t = ts.tv_nsec;
		t = t / 1000000000.0f;
		t = t + ts.tv_sec;
		if (t < nextt) {
			usleep(100000);
			continue;
		}
		nextt = t + 1.0;
		snprintf(message, sizeof(message), "%ld %.2f", ++id, t);
		rc = mosquitto_publish(mosq, &mid_sent, topic, strlen(message),
				  message, qos, retain);
		printf("publish %s returns %d\n", message, rc);
	}

	return NULL;
}

/* when connecting successfully, this function will be called */
void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	printf("my_connect_callback: %d\n", result);

	if (tid == -1)
		pthread_create(&tid, NULL, send_proc, NULL);
}
/* when moquitto_disconnect() is called, and disconnect successfully,
 * this function will be called */
void my_disconnect_callback(struct mosquitto *mosq, void *obj, int rc)
{
	printf("my_disconnect_callback: %d\n", rc);
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
/*	printf("%s\n", str);	*/
}

void my_sigint(int sig)
{
	printf("Cancel\n");
	connected = 0;
	mosquitto_disconnect(mosq);
}

int main()
{
	const char *id = "mosq_dcmm";
	//const char *host = "lzhu11-vm01.sh.intel.com";
	//short port = 443;
	const char *host = "192.168.199.127";
	short port = 1883;
	int use_dcmm = 1;
	int keepalive = 3600;
	unsigned int max_inflight = 20;
	int rc = 0;

	signal(SIGINT, my_sigint);

	mosquitto_lib_init();

	/* the new `use_dcmm` parameter is one of the changes we made to mosquitto
	* library API, set `use_dcmm` to 0, will turn off the DCMM feature */
	mosq = mosquitto_new(id, true, NULL, use_dcmm);

	/* the main function u should change */
	mosquitto_connect_callback_set(mosq, my_connect_callback);
	mosquitto_disconnect_callback_set(mosq, my_disconnect_callback);

	/* log message */
	mosquitto_log_callback_set(mosq, my_log_callback);

	rc = mosquitto_connect_bind(mosq, host, port, keepalive, NULL);
	if (rc) {
		mosquitto_destroy(mosq);
		mosquitto_lib_cleanup();
		exit(EXIT_FAILURE);
	}

	do {
		rc = mosquitto_loop_forever(mosq, -1, 1);
		printf("loop forever returns %d\n", rc);
	} while (connected);


	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	pthread_join(tid, NULL);

	return 0;
}
