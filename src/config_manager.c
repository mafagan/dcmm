#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "config_manager.h"
#include "../lib/dcmm_utils.h"

#define BUFF_LEN 1024

/**
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * Don't use logging module's api here as it need config module to initialize
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
config_t config;

static void config_set(const char *key, const char *value)
{
    if (! strncmp(key, "session_size", 12)) {
        config.session_size = atoi(value);
        assert(config.session_size >= 10);
    }
    else if (! strncmp(key, "cache_size", 10)) {
        config.cache_size = atoi(value);
        assert(config.cache_size >= 100);
    }
    else if (! strncmp(key, "log", 3)) {
        assert(! strncasecmp(value, "trace", 5) ||
                ! strncasecmp(value, "debug", 5) ||
                ! strncasecmp(value, "info", 4) ||
                ! strncasecmp(value, "warn", 4) ||
                ! strncasecmp(value, "error", 5));
        config.log = strdup(value);
    }
    else if (! strncmp(key, "syslog", 6)) {
        assert(! strncasecmp(value, "trace", 5) ||
                ! strncasecmp(value, "debug", 5) ||
                ! strncasecmp(value, "info", 4) ||
                ! strncasecmp(value, "warn", 4) ||
                ! strncasecmp(value, "error", 5));
        config.syslog = strdup(value);
    }
    else if (! strncmp(key, "read_threshold", 14)) {
        config.read_threshold = atoi(value);
        assert(config.read_threshold > 0);
    }
    else if (! strncmp(key, "db_cache_size", 13)) {
        config.db_cache_size = atoi(value);
        assert(config.db_cache_size > 0);
    }
    else if (! strncmp(key, "db_cache_msg_size", 17)) {
        config.db_cache_msg_size = atoi(value);
        assert(config.db_cache_msg_size);
    }
    else if (! strncmp(key, "rate", 4)) {
        config.rate = atof(value);
    }
    else {
        fprintf(stderr, "Config key(%s) error\n", key);
    }
}

void config_init()
{
    config_read(DCMM_CONFIG_FILE);
    printf("Config: session_size(%d), cache_size(%d), log(%s), syslog(%s), "\
            "read_threshold(%d), db_cache_size(%d), db_cache_msg_size(%d), rate(%.1lf)\n",
            config.session_size, config.cache_size, config.log, config.syslog,
            config.read_threshold, config.db_cache_size, config.db_cache_msg_size,
            config.rate);
}

void config_destroy()
{
    free(config.log);
    free(config.syslog);
}

void config_read(const char *filename)
{
    char buffer[BUFF_LEN];
    char key[BUFF_LEN];
    char value[BUFF_LEN];
    uint32_t i = 0;
    FILE *f = fopen(filename, "r");
    if (! f) {
        fprintf(stderr, "Config file(%s) does not exist\n", filename);
        exit(EXIT_FAILURE);
    }
    while (fgets(buffer, BUFF_LEN, f)) {
        i = 0;
        while (i < strlen(buffer) && buffer[i] == ' ')
            ;
        if (buffer[i] == '#' || i == strlen(buffer)) {
            continue;
        }
        sscanf(buffer, "%s%s", key, value);
        config_set(key, value);
    }
    fclose(f);
}

void config_write()
{

}

void config_reload()
{

}
