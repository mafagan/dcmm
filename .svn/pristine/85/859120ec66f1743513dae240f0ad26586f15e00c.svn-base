#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stdint.h>

typedef struct config {
    int session_size;
    int cache_size;
    char *log;
    char *syslog;
    int read_threshold;
    int db_cache_size;
    int db_cache_msg_size;
    double rate;
} config_t;

void config_init();
void config_destroy();
void config_read(const char *filename);
void config_write();
void config_reload();

#endif
