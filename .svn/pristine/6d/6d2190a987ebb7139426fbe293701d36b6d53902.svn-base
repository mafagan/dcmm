#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>

#include "logging.h"
#include "memory_pool.h"
#include "config_manager.h"

/* used for session pool  */
SLIST_HEAD(session_list_head, session);
typedef struct session_list_head session_list_head_t;

/* used for msg pool */
SLIST_HEAD(msg_list_head, message);
typedef struct msg_list_head msg_list_head_t;

SLIST_HEAD(db_cache_list_head, db_cache);
typedef struct db_cache_list_head db_cache_list_head_t;

extern config_t config;

static void *memory_session = NULL;
static session_list_head_t session_pool;
static uint32_t num_session_left = 0;
static uint32_t id_session = 1;

static void *memory_msg = NULL;
static msg_list_head_t msg_pool;
static uint32_t num_msg_left = 0;

static void *memory_db_cache = NULL;
static void *memory_db_cache_msg = NULL;
static db_cache_list_head_t db_cache_pool;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
/**
 * Initialize the `memory_pool` module
 *
 * @param size_session the max number of session
 * @param size_msg the max number of message
 */
void memory_pool_init(uint32_t size_session, uint32_t size_msg)
{
    log_debug("Initialize the 'memory_pool' module: size_session(%u) size_msg(%u)",
            size_session, size_msg);
    syslog_debug("Initialize the 'memory_pool' module: size_session(%u) size_msg(%u)",
            size_session, size_msg);
    uint32_t i = 0;
    uint32_t size_db_cache_msg = 0;
    session_t *session = NULL;
    message_t *msg = NULL;
    db_cache_t *db_cache = NULL;

    memory_session = calloc(size_session, sizeof(session_t));
    if (memory_session == NULL) {
        perror("Malloc sessions' memory failed\n");
        log_error("Malloc sessions' memory failed");
        syslog_error("Malloc sessions' memory failed");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < size_session; ++ i) {
        session = memory_session + i * sizeof(session_t);
        SLIST_INSERT_HEAD(&session_pool, session, entries);
    }
    num_session_left = size_session;

    memory_msg = calloc(size_msg, sizeof(message_t));
    if (memory_msg == NULL) {
        perror("Malloc messages' memory failed\n");
        log_error("Malloc messages' memory failed");
        syslog_error("Malloc messages' memory failed");
        free(memory_session);
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < size_msg; ++ i) {
        msg = memory_msg + i * sizeof(message_t);
        SLIST_INSERT_HEAD(&msg_pool, msg, entries);
    }
    num_msg_left = size_msg;

    size_db_cache_msg = config.db_cache_msg_size;
    memory_db_cache = calloc(config.db_cache_size, sizeof(db_cache_t));
    memory_db_cache_msg = calloc(config.db_cache_size * size_db_cache_msg,
            sizeof(message_t));
    for (i = 0; i < config.db_cache_size; ++ i) {
        db_cache = memory_db_cache + i * sizeof(db_cache_t);
        db_cache->msgs = memory_db_cache_msg +
            i * size_db_cache_msg * sizeof(message_t);
        db_cache->max_size = size_db_cache_msg;
        db_cache->size = 0;
        SLIST_INSERT_HEAD(&db_cache_pool, db_cache, entries);
    }
}
/**
 * Destroy the `memory_pool` module
 */
void memory_pool_destroy()
{
    log_debug("Destroy the 'memory_pool' module");
    syslog_debug("Destroy the 'memory_pool' module");
    while (! SLIST_EMPTY(&session_pool)) {
        SLIST_REMOVE_HEAD(&session_pool, entries);
    }
    free(memory_session);
    memory_session = NULL;
    id_session = 0;
    num_session_left = 0;

    while (! SLIST_EMPTY(&msg_pool)) {
        SLIST_REMOVE_HEAD(&msg_pool, entries);
    }
    free(memory_msg);
    memory_msg = NULL;
    num_msg_left = 0;

    while (! SLIST_EMPTY(&db_cache_pool)) {
        db_cache_t *db_cache = SLIST_FIRST(&db_cache_pool);
        SLIST_REMOVE_HEAD(&db_cache_pool, entries);
    }
    free(memory_db_cache);
    free(memory_db_cache_msg);
}
/**
 * Get a session's memory from the memory pool
 *
 * @return a pointer to a session's memory if ok, or NULL if no enough memory
 */
session_t *get_session_block()
{
    session_t *session = NULL;
    if (! SLIST_EMPTY(&session_pool)) {
        session = SLIST_FIRST(&session_pool);
        SLIST_REMOVE_HEAD(&session_pool, entries);
        bzero(session, sizeof(session_t));
        session->id = id_session ++;
        session->control_sd = -1;
        -- num_session_left;
    }
    return session;
}
/**
 * Return the session's memory to the memory pool
 *
 * @param session the session we will return
 */
void return_session_block(session_t *session)
{
    assert(session);
    bzero(session, sizeof(session_t));
    SLIST_INSERT_HEAD(&session_pool, session, entries);
    ++ num_session_left;
}
void reset_session_id(uint32_t id)
{
    id_session = id;
}
/**
 * Get the number of usable sessions
 *
 * @return the number
 */
uint32_t count_usable_session_block()
{
    return num_session_left;
}
/**
 * Get a message's memory from the memory pool
 *
 * @return a pointer to a message's memory if ok, or NULL if no enough memory
 */
message_t *get_msg_block()
{
    message_t *msg = NULL;
    if (! SLIST_EMPTY(&msg_pool)) {
        msg = SLIST_FIRST(&msg_pool);
        SLIST_REMOVE_HEAD(&msg_pool, entries);
        bzero(msg, sizeof(message_t));
        -- num_msg_left;
    }
    return msg;
}
/**
 * Return the message's memory to the memory pool
 *
 * @param msg the message we will return
 */
void return_msg_block(message_t *msg)
{
    assert(msg);
    bzero(msg, sizeof(message_t));
    SLIST_INSERT_HEAD(&msg_pool, msg, entries);
    ++ num_msg_left;
}
/**
 * Get the number of usable messages
 *
 * @return the number
 */
uint32_t count_usable_msg_block()
{
    return num_msg_left;
}
/**
 * Get a db buffer's memory from the memory pool
 *
 * @return a pointer to a db buffer's memory, if no memory is usable, it will be
 * blocked until ok.
 */
db_cache_t *get_db_cache_block()
{
    db_cache_t *db_cache = NULL;
    while (true) {
        pthread_mutex_lock(&mutex);
        if (! SLIST_EMPTY(&db_cache_pool)) {
            db_cache = SLIST_FIRST(&db_cache_pool);
            SLIST_REMOVE_HEAD(&db_cache_pool, entries);
            pthread_mutex_unlock(&mutex);
            bzero(db_cache->msgs, db_cache->max_size * sizeof(message_t));
            db_cache->size = 0;
            return db_cache;
        }
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}
/**
 * Return the db buffer's memory to the memory pool
 */
void return_db_cache_block(db_cache_t *db_cache)
{
    assert(db_cache);
    db_cache->size = 0;
    bzero(db_cache->msgs, db_cache->max_size * sizeof(message_t));
    pthread_mutex_lock(&mutex);
    SLIST_INSERT_HEAD(&db_cache_pool, db_cache, entries);
    pthread_mutex_unlock(&mutex);
}

