#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto_dcmm.h>

static int run = -1;
int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;

	mosquitto_lib_init();

	mosq = mosquitto_new("01-no-clean-session", false, NULL, true);

	rc = mosquitto_connect(mosq, "localhost", 1888, 60);

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_lib_cleanup();
	return run;
}
