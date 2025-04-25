#ifndef TXT_QUERY_THREAD_H
#define TXT_QUERY_THREAD_H

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_DOMAIN_LEN 256
#define MAX_TASK_QUEUE 1024

typedef struct {
    char domain[MAX_DOMAIN_LEN];
} txt_query_task_t;

static txt_query_task_t task_queue[MAX_TASK_QUEUE];
static int queue_head = 0;
static int queue_tail = 0;

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_not_empty = PTHREAD_COND_INITIALIZER;

void enqueue_txt_query(const char *domain);
void *txt_query_worker(void *arg) ;

#endif // TXT_QUERY_THREAD_H