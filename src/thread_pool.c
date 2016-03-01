#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>

#include "logging.h"
#include "../lib/dcmm_utils.h"
#include "thread_pool.h"

#define THREAD_SIZE 1

typedef struct task {
    void (*func)(void *);
    void *arg;
    struct task *next;
} task_t;

typedef struct thread_pool {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    task_t *task_queue_head;
    task_t *task_queue_tail;
    bool is_destroyed;
    pthread_t *threads;
} thread_pool_t;

static thread_pool_t pool;

static task_t *thread_pool_pop_task();
static void *thread_routine(void *arg);
/**
 * Pop the first task from the queue
 * Note that, the function is not thread safe
 *
 * @return the first task in the queue
 */
static task_t *thread_pool_pop_task()
{
    assert(pool.task_queue_head != NULL);
    task_t *task = NULL;

    task = pool.task_queue_head;
    pool.task_queue_head = task->next;
    if (pool.task_queue_head == NULL) {
        pool.task_queue_tail = NULL;
    }

    return task;
}
/**
 * The thread's routine function
 *
 * @param arg
 */
static void *thread_routine(void *arg)
{
    task_t *task = NULL;
    while (true) {
        pthread_mutex_lock(&(pool.mutex));
        while (pool.task_queue_head == NULL && ! pool.is_destroyed) {
            pthread_cond_wait(&(pool.cond), &(pool.mutex));
        }
        if (pool.is_destroyed) {
            log_debug("Stop thread %lu", pthread_self());
            syslog_debug("Stop thread %lu", pthread_self());
            pthread_mutex_unlock(&(pool.mutex));
            pthread_exit(NULL);
        }
        log_debug("Thread %lu starts to work", pthread_self());
        syslog_debug("Thread %lu starts to work", pthread_self());
        task = thread_pool_pop_task();
        pthread_mutex_unlock(&(pool.mutex));

        assert(task != NULL && task->func != NULL);
        task->func(task->arg);
        free(task);
        task = NULL;
    }
}
/**
 * Initialize the `thread_pool` module
 */
void thread_pool_init()
{
    log_debug("Initialize the `thread_pool` module");
    syslog_debug("Initialize the `thread_pool` module");
    uint32_t i = 0;
    pthread_mutex_init(&(pool.mutex), NULL);
    pthread_cond_init(&(pool.cond), NULL);
    pool.task_queue_head = pool.task_queue_tail = NULL;
    pool.is_destroyed = false;
    pool.threads = (pthread_t *)calloc(THREAD_SIZE, sizeof(pthread_t));
    for (i = 0; i < THREAD_SIZE; ++ i) {
        pthread_create(&(pool.threads[i]), NULL, thread_routine, NULL);
    }
}
/**
 * Destroy the `thread_pool` module
 */
void thread_pool_destroy()
{
    log_debug("Destroy the `thread_pool` module");
    syslog_debug("Destroy the `thread_pool` module");
    uint32_t i = 0;
    task_t *tmp = NULL;
    if (! pool.is_destroyed) {
        pool.is_destroyed = true;
        pthread_cond_broadcast(&(pool.cond));

        for (i = 0; i < THREAD_SIZE; ++ i) {
            pthread_join(pool.threads[i], NULL);
        }
        free(pool.threads);
        pool.threads = NULL;

        while (pool.task_queue_head != NULL) {
            tmp = pool.task_queue_head;
            pool.task_queue_head = pool.task_queue_head->next;
            free(tmp);
        }
        pool.task_queue_head = pool.task_queue_tail = NULL;

        pthread_mutex_destroy(&(pool.mutex));
        pthread_cond_destroy(&(pool.cond));
    }
}
/**
 * Add task to the task queue
 * Note that, this function is thread safe
 *
 * @param func the function of the task
 * @param arg the argument of the function
 */
void thread_pool_add_task(void (*func)(void *), void *arg)
{
    assert(func != NULL);
    task_t *task = (task_t *)malloc(sizeof(task_t));
    task->func = func;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&(pool.mutex));
    if (pool.task_queue_tail == NULL) {
        pool.task_queue_head = pool.task_queue_tail = task;
    }
    else {
        pool.task_queue_tail->next = task;
        pool.task_queue_tail = task;
    }
    pthread_mutex_unlock(&(pool.mutex));
    pthread_cond_signal(&(pool.cond));
}

