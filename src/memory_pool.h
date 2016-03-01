#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include "mem_cache.h"
#include "session_manager.h"

#include <sys/queue.h>

struct message;
struct session;

typedef struct db_cache {
    struct message *msgs;
    uint32_t max_size;
    uint32_t size;
    SLIST_ENTRY(db_cache) entries;
} db_cache_t;

void memory_pool_init(uint32_t size_session, uint32_t size_msg);
void memory_pool_destroy();

struct session *get_session_block();
void return_session_block(struct session *session);
uint32_t count_usable_session_block();
void reset_session_id(uint32_t id);

struct message *get_msg_block();
void return_msg_block(struct message *msg);
uint32_t count_usable_msg_block();

struct db_cache *get_db_cache_block();
void return_db_cache_block(struct db_cache *db_cache);

#endif
