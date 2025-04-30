#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "txt_query.thread.h"
#include "dns_utils.h"
void enqueue_txt_query(const char *domain) {
    pthread_mutex_lock(&queue_lock);

    int next_tail = (queue_tail + 1) % MAX_TASK_QUEUE;
    if (next_tail == queue_head) {
        // 队列已满，直接忽略或日志记录
        fprintf(stderr, "TXT query queue full, dropping task for %s\n", domain);
        pthread_mutex_unlock(&queue_lock);
        return;
    }

    strncpy(task_queue[queue_tail].domain, domain, MAX_DOMAIN_LEN - 1);
    task_queue[queue_tail].domain[MAX_DOMAIN_LEN - 1] = '\0';
    queue_tail = next_tail;

    pthread_cond_signal(&queue_not_empty);
    pthread_mutex_unlock(&queue_lock);
}

void *txt_query_worker(void *arg) {
    (void)arg;

    while (1) {
        pthread_mutex_lock(&queue_lock);

        while (queue_head == queue_tail) {
            pthread_cond_wait(&queue_not_empty, &queue_lock);
        }

        txt_query_task_t task = task_queue[queue_head];
        queue_head = (queue_head + 1) % MAX_TASK_QUEUE;

        pthread_mutex_unlock(&queue_lock);

        // 发送 TXT 查询（你已有的函数）
        // send_txt_query(task.domain);

        // 可加入 sleep 避免风暴
        usleep(1000); // 假设每个任务需要 1ms
    }

    return NULL;
}
