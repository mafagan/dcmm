#ifndef MEM_CACHE_H
#define MEM_CACHE_H

#include <sys/queue.h>
#include <stdint.h>

#include "session_manager.h"
#include "../lib/dcmm_utils.h"

#define DCMM_MAX_MSG_SIZE 256

struct session;

typedef struct message {
    uint32_t id;
    uint8_t data[DCMM_MAX_MSG_SIZE];
    uint32_t len;
    int need_reply;
    bool is_final_block;
    struct session *session;//the session of this message
    struct message *cache_msg_next;//next msg of the cache
    struct message *cache_msg_prev;//previous msg of the cache
    struct message *session_msg_next;//next msg of the same session in the cache
    struct message *session_msg_prev;//previous msg of the same session in the cache
    SLIST_ENTRY(message) entries;
} message_t;

void cache_init();
void cache_destroy();
void cache_insert_msg(struct session *session, struct message *msg);
void cache_pop_msg();
void cache_pop_session_msg(struct session *session, struct message *message);
void cache_clear_session_msg(struct session *session);
bool cache_has_file_data();
struct message *cache_first_msg();
struct message *cache_first_session_msg(struct session *session);
bool cache_is_empty();
bool cache_session_has_msg_not_sent(struct session *session);
int cache_count();
struct message *cache_get_curr_msg(struct session *session);
struct message *cache_get_msg_block();
void cache_return_msg_block(struct message *msg);
bool cache_is_db_cache_memory(message_t *msg);
void cache_list();

#endif
