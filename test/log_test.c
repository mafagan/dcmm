#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include "../src/logging.h"

int main(int argc, char** argv)
{
    struct timeval start_time;
    struct timeval now_time;
    user_locinfo_t userloc;
    int looptime = 0;

    /* setup for the extra user location info */
    char hostname[256];
    int  pid = getpid();
    gethostname(hostname,255);
    hostname[255] = '\0';
    userloc.hostname = hostname;
    userloc.pid = pid;

    if (argc < 2)
    {
        printf("usage: %s loop_time_in_seconds\n",argv[0]);
        exit (1);
    }
    if (sscanf(argv[1],"%d",&looptime) != 1)
    {
        printf("could not convert %s to number of seconds to loop\n",argv[1]);
        exit(1);
    }

    log_init();
    printf("log initialize succeed.\n");

    /*
     * Here we add our own userdefined location info, and then pick that up in our formatter
     */
    gettimeofday(&start_time, NULL);
    gettimeofday(&now_time, NULL);

    while ( (now_time.tv_sec - start_time.tv_sec) < looptime)
    {
        log_debug("Debugging test, msg:%s%d!", "hello world", 11);
        syslog_debug("Debugging test, msg:%s%d!", "hello world", 11);

        sleep(3);

        gettimeofday(&now_time, NULL);
    }

    /* Explicitly call the log4c cleanup routine */
    if ( log_destroy()){
        printf("log4c_fini() failed");
    }

    return 0;
}

