#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <mosquitto_dcmm.h>

static int run = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		mosquitto_disconnect(mosq);
	}
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	run = rc;
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;

	mosquitto_lib_init();

	mosq = mosquitto_new("08-ssl-connect-crt-auth", true, NULL, true);
	mosquitto_tls_opts_set(mosq, 1, "tlsv1", NULL);
	mosquitto_tls_set(mosq, "/home/ubuntu/ssl/test-root-ca.crt",
            "/home/ubuntu/ssl/certs", "/home/ubuntu/ssl/client.crt",
            "/home/ubuntu/ssl/client.key", NULL);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_disconnect_callback_set(mosq, on_disconnect);

	rc = mosquitto_connect(mosq, "localhost", 1888, 60);

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_lib_cleanup();
	return run;
}
