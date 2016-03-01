/* linux */
#include <unistd.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>
/* c library */
#include <stdlib.h>
#include <stdio.h>
/* libevent */
#include <event.h>

#include <openssl/ssl.h>

/* other modules */
#include "io_handler.h"
#include "session_manager.h"
#include "mem_cache.h"
#include "connection_manager.h"
#include "scheduler.h"
#include "config_manager.h"
#include "thread_pool.h"
#include "logging.h"
#include "memory_pool.h"
#include "../lib/dcmm_utils.h"

/* call back functions */
static void terminate(int fd, short what, void *arg);
/* defined in `config_manager.c` */
extern config_t config;

struct event_base *ev_base = NULL;//other modules will use it
static struct event *ev_exit[2];
static int signal_exit[2] = {SIGTERM, SIGINT};

int main(int argc, char **argv)
{
    struct sigaction sa = {}, old_sa = {};
    FILE *f;
    uint32_t i;

    SSL_library_init();
    ev_base = event_base_new();

    /* init the config manager module */
    config_init();
    /* init the logging manager module */
    log_init();
    /* init the memory pool module */
    memory_pool_init(config.session_size, config.cache_size);
    /* init the session manager module */
    session_init();
    /* init the mem cache module */
    cache_init();
    /* init the connection manager module */
    connection_init();
    /* init the scheduler module */
    scheduler_init();
    /* set up unix socket to receive app's data */
    io_init();
    /* set up thread pool */
    thread_pool_init();

    /* it seems everything is ok, write down the `pid` */
    f = fopen(DCMM_PID_FILE, "w");
    if (f == NULL) {
        perror("Unable to open pidfile, start failed\n");
        log_error("Unable to open pidfile, start failed");
        syslog_error("Unable to open pidfile, start failed");
        exit(EXIT_FAILURE);
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);

    /* ignore signal SIGPIPE */
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGPIPE, &sa, &old_sa) == -1) {
        perror("Set SIGPIPE action failed\n");
        log_error("Set SIGPIPE action failed");
        syslog_error("Set SIGPIPE action failed");
        exit(EXIT_FAILURE);
    }

    /* set up exit signal events */
    for (i = 0; i < sizeof(signal_exit)/sizeof(int); ++ i) {
        ev_exit[i] = event_new(ev_base, signal_exit[i],
                EV_SIGNAL | EV_PERSIST, terminate, NULL);
        event_add(ev_exit[i], NULL);
    }

    event_base_dispatch(ev_base);

    return 0;
}

static void terminate(int fd, short what, void *arg)
{
    log_warn("Stopping dcmm");
    syslog_warn("Stopping dcmm");
    /* free the events in main thread module */
    uint32_t i;
    for (i = 0; i < sizeof(signal_exit)/sizeof(int); ++ i) {
        event_free(ev_exit[i]);
    }
    /* free other modules
     * note that, all these `*_destroy` should also deal with the events, which
     * are `new` in them */
    io_destroy();
    scheduler_destroy();
    connection_destroy();
    cache_destroy();
    config_destroy();
    session_destroy();
    thread_pool_destroy();
    memory_pool_destroy();
    log_destroy();
    /* break the events loop */
    event_base_loopbreak(ev_base);
    event_base_free(ev_base);
}

