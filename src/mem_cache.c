#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sqlite3.h>
#include <pthread.h>
#include <event.h>

#include "config_manager.h"
#include "thread_pool.h"
#include "logging.h"
#include "mem_cache.h"
#include "io_handler.h"
#include "memory_pool.h"
#include "../lib/dcmm_utils.h"

#define DCMM_DB_FILE "/tmp/dcmm.db"
/* sql commands */
#define DCMM_SQL_TRANS_BEGIN "begin transaction;"
#define DCMM_SQL_TRANS_COMMIT "commit transaction;"
#define DCMM_SQL_TRANS_ROLLBACK "rollback transaction;"
#define DCMM_SQL_SYNC_OFF "pragma synchronous = off;"
/* table messsage */
#define DCMM_SQL_CREATE_MESSAGE "create table if not exists `message`("\
                                    "`id` INTEGER PRIMARY KEY,"\
                                    "`msg_id` INTEGER,"\
                                    "`session_id` INTEGER,"\
                                    "`data` BLOB,"\
                                    "`len` INTEGER,"\
                                    "`need_reply` INTEGER,"\
                                    "`is_final_block` INTEGER);"
#define DCMM_SQL_INSERT_MESSAGE "insert into `message` values (NULL,?,?,?,?,?,?);"
#define DCMM_SQL_DEL_TOP_MESSAGE "delete from `message` where `id` in "\
                                    "(select `id` from `message` limit ?);"
#define DCMM_SQL_GET_TOP_MESSAGE "select * from `message` limit ?;"
#define DCMM_CLS_SESSION_MSG "delete from `message` where `session_id`=?;"
/* table session */
#define DCMM_SQL_CREATE_SESSION "create table if not exists `session`("\
                                    "`id` INTEGER PRIMARY KEY,"\
                                    "`session_id` INTEGER UNIQUE,"\
                                    "`dest_ip` TEXT,"\
                                    "`dest_port` INTEGER,"\
                                    "`priority` INTEGER,"\
                                    "`count_msg` INTEGER,"\
                                    "`protocol` INTEGER,"\
                                    "`tls_cafile` TEXT,"\
                                    "`tls_capath` TEXT,"\
                                    "`tls_certfile` TEXT,"\
                                    "`tls_key_file` TEXT);"
#define DCMM_SQL_INSERT_SESSION "insert into `session` values (NULL,?,?,?,?,?,?,?,?,?,?);"
#define DCMM_SQL_SELECT_SESSION "select * from `session`;"
#define DCMM_SQL_CLS_SESSION "delete from `session`;"

typedef struct msg_cache {
    struct message *msgs_head;//the first message in the cache
    struct message *msgs_tail;//the last message in the cache
    uint32_t count_msg_db;//the number of messages in db including sqlite and db_cache
    uint32_t count_msg_cache;//the number of messages in cache
} msg_cache_t;

/* Defined in `config_manager` */
extern config_t config;
/* Defined in `session_manager` */
extern session_queue_t sessions[PRI_TYPE_SIZE];

static sqlite3 *db = NULL;;
static void *memory = NULL;
static msg_cache_t cache;//the cache of message
/* for sqlite */
static db_cache_t *db_cache_using = NULL;

static void backup();
static void recover();
static void open_database();
static void close_database();
static void write_to_database(void *arg);
static void read_from_database(uint32_t num_msg);
static void move_msg_from_db_cache_to_cache(uint32_t num_msg);
static void clear_session_msg_in_db(session_t *session);
static void write_to_database_from_cache();
static void recover_msg_order_in_database(uint32_t num_msg_db);
static void write_session_to_database();
static void read_session_from_database();
static void insert_msg_into_cache_list(message_t *msg);
static void insert_msg_into_session_list(session_t *session, message_t *msg);
static void remove_msg_from_cache_list(message_t *msg);
static void insert_msg_into_session_list(session_t *session, message_t *msg);
/**
 * Save all unsent message into sqlite
 */
static void backup()
{
    log_debug("Run backup");
    syslog_debug("Run backup");
    /* save the number of messages in db at first for
     * `recover_msg_order_in_database`, as
     * `write_to_database` and `write_to_database_from_cache` may change it*/
    uint32_t num_msg_db = cache.count_msg_db;
    log_debug("Write db_cache's messages into database");
    write_to_database(db_cache_using);
    db_cache_using = get_db_cache_block();
    log_debug("Write cache's messages into database");
    write_to_database_from_cache();
    log_debug("Recover messages' order in database");
    recover_msg_order_in_database(num_msg_db);
    log_debug("Write sessions' information into database");
    write_session_to_database();
}
/**
 * Recover basing on the data in sqlite
 */
static void recover()
{
    log_debug("Recover from %s", DCMM_DB_FILE);
    syslog_debug("Recover from %s", DCMM_DB_FILE);
    uint32_t i = 0;
    cache.count_msg_cache = 0;
    cache.count_msg_db = 0;
    /* cache.count_msg_db is increase in `read_session_from_database` */
    log_debug("Recover sessions from database");
    read_session_from_database();
    /* `read_from_database` will deal with `cache.count_msg_db` and
     * `cache.count_msg_cache` */
    log_debug("Recover messages from database");
    read_from_database(count_usable_msg_block());
}

/**
 * Open sqlite database
 * Note that, we will close the feature synchronous of sqlite for the
 * performance
 */
static void open_database()
{
    log_debug("Open database \"%s\"", DCMM_DB_FILE);
    syslog_debug("Open database \"%s\"", DCMM_DB_FILE);
    int ret = 0;
    char *errmsg = NULL;

    /* open database */
    ret = sqlite3_open(DCMM_DB_FILE, &db);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Open database failed\n");
        log_error("Open database failed");
        syslog_error("Open database failed");
        exit(EXIT_FAILURE);
    }
    /* create tables */
    ret = sqlite3_exec(db, DCMM_SQL_CREATE_MESSAGE, NULL, NULL, &errmsg);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Create table 'message' failed: %s\n", errmsg);
        log_error("Create table 'message' failed: %s", errmsg);
        syslog_error("Create table 'message' failed: %s", errmsg);
        sqlite3_free(errmsg);
        exit(EXIT_FAILURE);
    }
    ret = sqlite3_exec(db, DCMM_SQL_CREATE_SESSION, NULL, NULL, &errmsg);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Create table 'session' failed: %s\n", errmsg);
        log_error("Create table 'session' failed: %s", errmsg);
        syslog_error("Create table 'session' failed: %s", errmsg);
        sqlite3_free(errmsg);
        exit(EXIT_FAILURE);
    }
    /* close synchronous feature */
    ret = sqlite3_exec(db, DCMM_SQL_SYNC_OFF, NULL, NULL, &errmsg);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Close sqlite's synchronous failed: %s\n", errmsg);
        log_error("Close sqlite's synchronous failed: %s", errmsg);
        syslog_error("Close sqlite's synchronous failed: %s", errmsg);
        sqlite3_free(errmsg);
        exit(EXIT_FAILURE);
    }
}
/**
 * Close sqlite database
 */
static void close_database()
{
    log_debug("Close database \"%s\"", DCMM_DB_FILE);
    syslog_debug("Close database \"%s\"", DCMM_DB_FILE);
    int result = 0;
    result = sqlite3_close(db);
    if(result != SQLITE_OK) {
        fprintf(stderr, "Close database failed\n");
        log_error("Close database failed");
        syslog_error("Close database failed");
    }
}
/**
 * Write the db_cache's messages into database
 * Note that, don't use `log` in this function
 *
 * @param arg should be a pointer to db_cache_t, which hold the messages
 */
static void write_to_database(void *arg)
{
    assert(arg);
    db_cache_t *db_cache = (db_cache_t *)arg;
    assert(db_cache->msgs);
    int i = 0;
    int ret = 0;
    message_t *msg = NULL;
    sqlite3_stmt *stmt = NULL;
    char *errmsg;
    ret = sqlite3_exec(db, DCMM_SQL_TRANS_BEGIN, NULL, NULL, &errmsg);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Database open transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
    sqlite3_prepare_v2(db, DCMM_SQL_INSERT_MESSAGE, -1, &stmt, NULL);
    for (i = 0; i < db_cache->size; ++ i) {
        msg = db_cache->msgs + i;
        sqlite3_bind_int(stmt, 1, msg->id);
        sqlite3_bind_int(stmt, 2, msg->session->id);
        sqlite3_bind_blob(stmt, 3, msg->data, msg->len, NULL);
        sqlite3_bind_int(stmt, 4, msg->len);
        sqlite3_bind_int(stmt, 5, msg->need_reply);
        sqlite3_bind_int(stmt, 6, msg->is_final_block);
        ret = sqlite3_step(stmt);
        if (SQLITE_DONE != ret) {
            fprintf(stderr, "Write to database failed\n");
            ret = sqlite3_exec(db, DCMM_SQL_TRANS_ROLLBACK, NULL, NULL, &errmsg);
            if (SQLITE_OK != ret) {
                fprintf(stderr, "Database rollback transaction failed: %s\n", errmsg);
                sqlite3_free(errmsg);
            }
            sqlite3_finalize(stmt);
            /* try again */
            thread_pool_add_task(write_to_database, arg);
            return ;
        }
        sqlite3_reset(stmt);
    }
    ret = sqlite3_exec(db, DCMM_SQL_TRANS_COMMIT, NULL, NULL, &errmsg);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Database commit transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
    sqlite3_finalize(stmt);
    return_db_cache_block(db_cache);
}
/**
 * Read message from database to cache
 *
 * @param num_msg the max number of message u can insert
 * @param num_session the max new session u can create
 */
static void read_from_database(uint32_t num_msg)
{
    log_debug("Begin to read data from database to cache");
    syslog_debug("Begin to read data from database to cache");
    int i = 0;
    int ret = 0;
    int col = 0;
    int type = 0;
    char *errmsg = NULL;
    uint32_t cnt_msg = 0;
    uint32_t cnt_session = 0;
    message_t *msg = NULL;
    session_t *session = NULL;
    sqlite3_stmt *stmt = NULL;
    /* get top `num_msg` messages */
    ret = sqlite3_prepare_v2(db, DCMM_SQL_GET_TOP_MESSAGE, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, num_msg);
    while (cnt_msg < num_msg) {
        ret = sqlite3_step(stmt);
        if (SQLITE_ROW == ret) {
            msg = get_msg_block();
            assert(msg);
            msg->id = sqlite3_column_int(stmt, 1);
            session = session_get(sqlite3_column_int(stmt, 2));
            if (session == NULL) {
                return_msg_block(msg);
                fprintf(stderr, "Client(%d) has been destroyed, ignore its messages",
                        sqlite3_column_int(stmt, 2));
                log_warn("Client(%d) has been destroyed, ignore its messages",
                        sqlite3_column_int(stmt, 2));
                syslog_warn("Client(%d) has been destroyed, ignore its messages",
                        sqlite3_column_int(stmt, 2));
            }
            msg->len = sqlite3_column_int(stmt, 4);
            memcpy(msg->data, sqlite3_column_blob(stmt, 3), msg->len);
            msg->need_reply = sqlite3_column_int(stmt, 5);
            msg->is_final_block = sqlite3_column_int(stmt, 6);
            if (session->count_msg_db > 0)
                -- session->count_msg_db;
            if (cache.count_msg_db > 0)
                -- cache.count_msg_db;
            cache_insert_msg(session, msg);
            ++ cnt_msg;
            if (session->server_write_ev)
                event_add(session->server_write_ev, NULL);
        }
        else {
            break;
        }
    }
    sqlite3_finalize(stmt);
    /* delete messages we have dealed */
    ret = sqlite3_prepare_v2(db, DCMM_SQL_DEL_TOP_MESSAGE, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, cnt_msg);
    ret = sqlite3_step(stmt);
    if (SQLITE_DONE != ret) {
        fprintf(stderr, "Pop messages from database failed\n");
        log_error("Pop messages from database failed");
        syslog_error("Pop messages from database failed");
    }
    sqlite3_finalize(stmt);
    log_debug("Finish reading data from database to cache");
    syslog_debug("Finish reading data from database to cache");
}
/**
 * Read data from db_cache to cache
 *
 * @param num_msg the max messages can be moved
 */
static void move_msg_from_db_cache_to_cache(uint32_t num_msg)
{
    log_debug("Move messages from db_cache to cache as more as possible");
    syslog_debug("Move messages from db_cache to cache as more as possible");
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t size_copy = 0;
    message_t *msg = NULL, *msg_db = NULL;;
    for (i = 0; i < db_cache_using->size && i < num_msg; ++ i) {
        msg_db = db_cache_using->msgs + i;
        -- msg_db->session->count_msg_db;
        msg = get_msg_block();
        assert(msg);
        memcpy(msg, msg_db, sizeof(message_t));
        cache_insert_msg(msg->session, msg);
    }
    size_copy = i;
    j = 0;
    while (i < db_cache_using->size) {
        memcpy(db_cache_using->msgs + j, db_cache_using->msgs + i, sizeof(message_t));
        ++ i;
        ++ j;
    }
    db_cache_using->size -= size_copy;
    cache.count_msg_db -= size_copy;//cache.count_msg_cache is added in `cache_insert_msg`
}
/**
 * Delete a session's all messages
 *
 * @param session the session we will deal with
 */
static void clear_session_msg_in_db(session_t *session)
{
    int ret = 0;
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(db, DCMM_SQL_DEL_TOP_MESSAGE, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, session->id);
    ret = sqlite3_step(stmt);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Clear client(%d)'s messages failed\n", session->id);
        log_error("Clear client(%d)'s messages failed'", session->id);
        syslog_error("Clear client(%d)'s messages failed'", session->id);
    }
    sqlite3_finalize(stmt);
    ret = sqlite3_changes(db);
    session->count_msg_db -= ret;
    cache.count_msg_db -= ret;
}
static void write_to_database_from_cache()
{
    sqlite3_stmt *stmt = NULL;
    char *errmsg = NULL;
    int ret = 0;
    message_t *msg = NULL;
    ret = sqlite3_exec(db, DCMM_SQL_TRANS_BEGIN, NULL, NULL, &errmsg);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Database open transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
    sqlite3_prepare_v2(db, DCMM_SQL_INSERT_MESSAGE, -1, &stmt, NULL);
    while (! cache_is_empty()) {
        msg = cache_first_msg();
        sqlite3_bind_int(stmt, 1, msg->id);
        sqlite3_bind_int(stmt, 2, msg->session->id);
        sqlite3_bind_blob(stmt, 3, msg->data, msg->len, NULL);
        sqlite3_bind_int(stmt, 4, msg->len);
        sqlite3_bind_int(stmt, 5, msg->need_reply);
        sqlite3_bind_int(stmt, 6, msg->is_final_block);
        ret = sqlite3_step(stmt);
        sqlite3_reset(stmt);
        ++ cache.count_msg_db;
        ++ msg->session->count_msg_db;
        cache_pop_msg();
    }
    ret = sqlite3_exec(db, DCMM_SQL_TRANS_COMMIT, NULL, NULL, &errmsg);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Database commit transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
    sqlite3_finalize(stmt);
}
static void recover_msg_order_in_database(uint32_t num_msg_db)
{
    uint32_t num = 0;
    while (num_msg_db > 0 && count_usable_msg_block() > 0) {
        if (num_msg_db <= count_usable_msg_block()) {
            num = num_msg_db;
        }
        else {
            num = count_usable_msg_block();
        }
        num_msg_db -= num;
        read_from_database(num);
        write_to_database_from_cache();
    }
}
static void write_session_to_database()
{
    uint32_t i = 0;
    uint32_t pri = 0;
    session_t *session = NULL;
    sqlite3_stmt *stmt = NULL;
    char *errmsg = NULL;
    int ret = 0;

    ret = sqlite3_exec(db, DCMM_SQL_TRANS_BEGIN, NULL, NULL, &errmsg);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Database open transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
        exit(EXIT_FAILURE);
    }

    ret = sqlite3_prepare_v2(db, DCMM_SQL_INSERT_SESSION, -1, &stmt, NULL);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "write_session_to_database: prepare\n");
        exit(EXIT_FAILURE);
    }
    for (pri = 0; pri < PRI_TYPE_SIZE; ++ pri) {
        session = sessions[pri].sessions_head;
        while (session != NULL) {
            session->count_msg_db += session->count_msg_cache;
            sqlite3_bind_int(stmt, 1, session->id);
            sqlite3_bind_text(stmt, 2, session->dest_ip,
                    session->dest_ip ? strlen(session->dest_ip) : 0, NULL);
            sqlite3_bind_int(stmt, 3, session->dest_port);
            sqlite3_bind_int(stmt, 4, session->priority);
            sqlite3_bind_int(stmt, 5, session->count_msg_db);
            sqlite3_bind_int(stmt, 6, session->protocol);
            sqlite3_bind_text(stmt, 7, session->tls_cafile,
                    session->tls_cafile ? strlen(session->tls_cafile) : 0, NULL);
            sqlite3_bind_text(stmt, 8, session->tls_capath,
                    session->tls_capath ? strlen(session->tls_capath) : 0, NULL);
            sqlite3_bind_text(stmt, 9, session->tls_certfile,
                    session->tls_certfile ? strlen(session->tls_certfile) : 0, NULL);
            sqlite3_bind_text(stmt, 10, session->tls_keyfile,
                    session->tls_keyfile ? strlen(session->tls_keyfile) : 0, NULL);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
            session = session->session_next;
        }
    }
    ret = sqlite3_exec(db, DCMM_SQL_TRANS_COMMIT, NULL, NULL, &errmsg);
    if (SQLITE_OK != ret) {
        fprintf(stderr, "Database commit transaction failed: %s\n", errmsg);
        sqlite3_free(errmsg);
        exit(EXIT_FAILURE);
    }

    sqlite3_finalize(stmt);
}
/*
 *    "`id` INTEGER PRIMARY KEY,"\
      "`session_id` INTEGER UNIQUE,"\
      "`dest_ip` TEXT,"\
      "`dest_port` INTEGER,"\
      "`priority` INTEGER,"\
      "`count_msg` INTEGER,"\
      "`protocol` INTEGER,"\
      "`tls_cafile` TEXT,"\
      "`tls_capath` TEXT,"\
      "`tls_certfile` TEXT,"\
      "`tls_key_file` TEXT);"
 * */
static void read_session_from_database()
{
    int ret = 0;
    sqlite3_stmt *stmt = NULL;
    session_t *session = NULL;

    ret = sqlite3_prepare_v2(db, DCMM_SQL_SELECT_SESSION, -1, &stmt, NULL);
    while (true) {
        ret = sqlite3_step(stmt);
        if (SQLITE_ROW == ret) {
            session = get_session_block();
            if (session == NULL) {
                fprintf(stderr, "No enough session size to set up\n");
                exit(EXIT_FAILURE);
            }
            session->id = sqlite3_column_int(stmt, 1);
            strcpy(session->dest_ip, sqlite3_column_text(stmt, 2));
            session->dest_port = sqlite3_column_int(stmt, 3);
            session->priority = sqlite3_column_int(stmt, 4);
            session->count_msg_db = sqlite3_column_int(stmt, 5);
            session->protocol = sqlite3_column_int(stmt, 6);
            session->tls_cafile = sqlite3_column_text(stmt, 7) ?
                        strdup(sqlite3_column_text(stmt, 7)) : NULL;
            session->tls_capath = sqlite3_column_text(stmt, 8) ?
                        strdup(sqlite3_column_text(stmt, 8)) : NULL;
            session->tls_certfile = sqlite3_column_text(stmt, 9) ?
                        strdup(sqlite3_column_text(stmt, 9)) : NULL;
            session->tls_keyfile = sqlite3_column_text(stmt, 10) ?
                        strdup(sqlite3_column_text(stmt, 10)) : NULL;
            session_add(session);
            if (strlen(session->dest_ip) > 0) {
                try_to_connect(session);
            }
            cache.count_msg_db += session->count_msg_db;
            reset_session_id(session->id + 1);
        }
        else {
            break;
        }
    }
    sqlite3_finalize(stmt);

    ret = sqlite3_prepare_v2(db, DCMM_SQL_CLS_SESSION, -1, &stmt, NULL);
    ret = sqlite3_step(stmt);
    if (SQLITE_DONE != ret) {
        fprintf(stderr, "read_from_database: DCMM_SQL_CLS_SESSION step\n");
        exit(EXIT_FAILURE);
    }
    sqlite3_finalize(stmt);
}
/**
 * Initialize the cache of dcmm
 *
 */
void cache_init()
{
    log_debug("Initialize the `mem_cache` module");
    syslog_debug("Initialize the `mem_cache` module");
    bzero(&cache, sizeof(msg_cache_t));
    db_cache_using = get_db_cache_block();
    open_database();
    recover();
}
/**
 * Destroy the cache
 * Return all messages back to the pool
 * Destroy the pool
 */
void cache_destroy()
{
    log_debug("Destroy the `mem_cache` module");
    syslog_debug("Destroy the `mem_cache` module");
    /* always try to backup */
    backup();
    assert(cache_is_empty());
    return_db_cache_block(db_cache_using);
    close_database();
}
/**
 * Insert a new message at the back of the cache's list
 *
 * Note that, it only deals with the pointers that are related to the cache
 *
 * @param msg the message we will deal with
 */
static void insert_msg_into_cache_list(message_t *msg)
{
    if (cache.msgs_head == NULL) {
        msg->cache_msg_next = msg->cache_msg_prev = NULL;
        cache.msgs_head = cache.msgs_tail = msg;
    }
    else {
        msg->cache_msg_next = NULL;
        msg->cache_msg_prev = cache.msgs_tail;
        cache.msgs_tail->cache_msg_next = msg;
        cache.msgs_tail = msg;
    }
}
/*
 * Insert a new message at the back of a session's msg list
 *
 * Note that, it only deal with the pointers that are related to the session's
 * msgs
 *
 * @param session the session which the new message belongs to
 * @param msg the new message we will add
 */
static void insert_msg_into_session_list(session_t *session, message_t *msg)
{
    assert(session == msg->session);
    if (session->msgs_head == NULL) {
        msg->session_msg_next = msg->session_msg_prev = NULL;
        session->msgs_head = session->msgs_tail = msg;
        session->curr_msg = msg;
    }
    else {
        msg->session_msg_next = NULL;
        msg->session_msg_prev = session->msgs_tail;
        session->msgs_tail->session_msg_next = msg;
        session->msgs_tail = msg;
    }
}
/**
 * Insert a new message into the cache
 *
 * @param session the session which the message belongs to
 * @param msg the new message we will insert
 */
void cache_insert_msg(session_t *session, message_t *msg)
{
    log_debug("Client(%d): insert message into cache", session->id);
    syslog_debug("Client(%d): insert message into cache", session->id);
    assert(session && msg);
    msg->session = session;
    if (cache_is_db_cache_memory(msg)) {
        ++ cache.count_msg_db;
        ++ session->count_msg_db;
        ++ db_cache_using->size;

        if (db_cache_using->size == db_cache_using->max_size) {
            log_debug("Create task");
            thread_pool_add_task(write_to_database, db_cache_using);
            db_cache_using = get_db_cache_block();
        }
    }
    else {
        insert_msg_into_session_list(session, msg);
        insert_msg_into_cache_list(msg);
        ++ cache.count_msg_cache;
        ++ session->count_msg_cache;
    }
}
/*
 * Pop the message, it can be at any place of the cache
 *
 * Note that, it only deals with the cache_msg_* pointers
 *
 * @param msg the message we will deal with
 */
static void remove_msg_from_cache_list(message_t *msg)
{
    /* msg -> msg_del -> msg -> ... -> NULL */
    if (msg->cache_msg_prev != NULL && msg->cache_msg_next != NULL) {
        msg->cache_msg_prev->cache_msg_next = msg->cache_msg_next;
        msg->cache_msg_next->cache_msg_prev = msg->cache_msg_prev;
    }
    /* msg -> msg_del -> NULL*/
    else if (msg->cache_msg_prev != NULL && msg->cache_msg_next == NULL) {
        msg->cache_msg_prev->cache_msg_next = NULL;
        cache.msgs_tail = msg->cache_msg_prev;
    }
    /* msg_del -> msg -> ... -> NULL*/
    else if (msg->cache_msg_prev == NULL && msg->cache_msg_next != NULL) {
        msg->cache_msg_next->cache_msg_prev = NULL;
        cache.msgs_head = msg->cache_msg_next;
    }
    /* msg_del -> NULL*/
    else {
        cache.msgs_head = cache.msgs_tail = NULL;
    }
    msg->cache_msg_prev = msg->cache_msg_next = NULL;
}

/*
 * Remove a message from the session's msgs list
 *
 * Note that, this operation will only deal with the session_msg_* pointers
 *
 * @param msg the message we will remove
 */
static void remove_msg_from_session_list(message_t *msg)
{
    session_t *session = msg->session;
    /* msg -> msg_del -> msg -> ... -> NULL */
    if (msg->session_msg_prev != NULL && msg->session_msg_next != NULL) {
        msg->session_msg_prev->session_msg_next = msg->session_msg_next;
        msg->session_msg_next->session_msg_prev = msg->session_msg_prev;
    }
    /* msg -> msg_del -> NULL*/
    else if (msg->session_msg_prev != NULL && msg->session_msg_next == NULL) {
        msg->session_msg_prev->session_msg_next = NULL;
        session->msgs_tail = msg->session_msg_prev;
    }
    /* msg_del -> msg -> ... -> NULL*/
    else if (msg->session_msg_prev == NULL && msg->session_msg_next != NULL) {
        msg->session_msg_next->session_msg_prev = NULL;
        session->msgs_head = msg->session_msg_next;
    }
    /* msg_del -> NULL*/
    else {
        session->msgs_head = session->msgs_tail = NULL;
    }
    msg->session_msg_prev = msg->session_msg_next = NULL;
}
/**
 * Pop the top message of the cache
 *
 * @return the top message if the cache isn't empty, or NULL if empty
 */
void cache_pop_msg()
{
    assert(! cache_is_empty());
    log_debug("Pop message from cache");
    syslog_debug("Pop message from cache");

    message_t *msg = cache_first_msg();
    remove_msg_from_session_list(msg);
    remove_msg_from_cache_list(msg);

    if (cache.count_msg_cache > 0)
        -- cache.count_msg_cache;
    if (msg->session->count_msg_cache > 0)
        -- msg->session->count_msg_cache;
    return_msg_block(msg);
}
/**
 * Pop a message of the session
 *
 * @param session
 * @param msg the message we will pop
 */
void cache_pop_session_msg(session_t *session, message_t *msg)
{
    assert(session && msg);
    assert(session == msg->session);
    assert(! cache_is_db_cache_memory(msg));

    remove_msg_from_session_list(msg);
    remove_msg_from_cache_list(msg);

    if (cache.count_msg_cache > 0)
        -- cache.count_msg_cache;
    if (session->count_msg_cache > 0)
        -- session->count_msg_cache;
    return_msg_block(msg);

    if (count_usable_msg_block() >= config.read_threshold) {
        if (cache.count_msg_db > 0) {
            if (db_cache_using->size == cache.count_msg_db) {
                move_msg_from_db_cache_to_cache(count_usable_msg_block());
            }
            else {
                read_from_database(count_usable_msg_block());
            }
        }
    }
}
/**
 * Delete all data of a session
 *
 * @param session the session we will deal
 */
void cache_clear_session_msg(session_t *session)
{
    log_debug("Clear client(%d)'s data", session->id);
    syslog_debug("Clear client(%d)'s data", session->id);
    while (session->msgs_head != NULL) {
        cache_pop_session_msg(session, session->msgs_head);
    }
    clear_session_msg_in_db(session);
}
/**
 * Check if some data is in the database
 *
 * @return true if yes, or false if no
 */
bool cache_has_file_data()
{
    return cache.count_msg_db > 0;
}

/**
 * Get the first message of the cache
 *
 * @return the first message of the cache on success, or NULL on failure
 */
message_t *cache_first_msg()
{
    return cache.msgs_head;
}
/**
 * Get the first message of a session
 *
 * @param session the session we will deal with
 * @return the first message of this session, or NULL if no message in it
 */
message_t *cache_first_session_msg(session_t *session)
{
    return session->msgs_head;
}
/**
 * Judge if the cache is empty
 *
 * @return true if the cache is empty, or false if the cache isn't
 */
bool cache_is_empty()
{
    if (cache.msgs_head == NULL) {
        return true;
    }
    return false;
}
/**
 * Judge if a session has no message
 *
 * @param session the session we will judge
 * @return 1 if the session is empty, or 0 if not
 */
bool cache_session_has_msg_not_sent(session_t *session)
{
    if (cache_get_curr_msg(session) == NULL && session->count_msg_db <= 0) {
        return false;
    }
    return true;
}
/**
 * Get the number of messages in the cache
 *
 * @return the number of messages
 */
int cache_count()
{
    return cache.count_msg_cache;
}

message_t *cache_get_curr_msg(session_t *session)
{
    return session->curr_msg;
}
/**
 * Get a usable message's memory
 * Note that, this memory may be in the `db_cache`, use `is_db_cache_memory`
 * to check it if need
 *
 * @return a pointer to the message's memory
 */
message_t *cache_get_msg_block()
{
    message_t *msg = get_msg_block();
    /* when `msg` == NULL, it means that, the cache is full,
     * when `db_cache_using->size` > 0, even though the cache is not full,
     * the new msg should insert into the `db_cache`
     * */
    if (msg == NULL || cache.count_msg_db > 0) {
        if (msg)
            return_msg_block(msg);
        /* we will call `write_to_database` and switch db_cache to standby
         * when size == max_size
         * so size >= max_size normally will not occur */
        assert(db_cache_using->size < db_cache_using->max_size);
        msg = db_cache_using->msgs + db_cache_using->size;
    }
    return msg;
}
/**
 * Return the message's memory to the memory pool
 *
 * @param msg the message we will return
 */
void cache_return_msg_block(message_t *msg)
{
    assert(! cache_is_db_cache_memory(msg));
    return_msg_block(msg);
}
/**
 * Check if this message's memory is in the db_cache
 *
 * @param msg the message we will check
 * @reutrn true if yes, or false if no
 */
bool cache_is_db_cache_memory(message_t *msg)
{
    if ((msg >= db_cache_using->msgs &&
                msg < (db_cache_using->msgs + db_cache_using->max_size))) {
        return true;
    }
    return false;
}
//for test
void cache_list()
{
    message_t *msg = NULL;
    msg = cache.msgs_head;
    while(msg != NULL)
    {
        msg->data[msg->len] = '\0';
        printf("msg:id=%u data=%s\n", msg->id, msg->data);
        msg = msg->cache_msg_next;
    }
    printf("\n");
}

