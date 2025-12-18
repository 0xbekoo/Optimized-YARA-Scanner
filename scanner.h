#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <yara.h>
#include <time.h>
#include <errno.h>

/* Simple Helper */
double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

/* GLOBALS */
typedef struct {
    long files_scanned;
    long threats_found;
    long long bytes_scanned;
    long errors;
    pthread_mutex_t lock;
} Stats;

Stats g_stats = {0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER};
pthread_mutex_t g_print_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct TaskNode {
    char *filepath;
    struct TaskNode *next;
} TaskNode;

typedef struct {
    TaskNode *head;
    TaskNode *tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int finished_loading;
} TaskQueue;

TaskQueue g_queue = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0};

YR_RULES *g_rules = NULL;