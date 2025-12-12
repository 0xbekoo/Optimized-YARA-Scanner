/*
    Developer: 0xbekoo
    Blog: 0xbekoo.github.io
    Updated: 2025-12-12
    Project: YARA Scanner developed in C language for optimization 

    Note: For better result, run with this code:  gcc -O3 -march=native -flto scanner.c -o yara_scanner -lyara -lpthread
*/

#include "scanner.h"

int YARACallBack(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        char* filepath = (char*)user_data;

        pthread_mutex_lock(&g_stats.lock);
        g_stats.threats_found++;
        pthread_mutex_unlock(&g_stats.lock);

        pthread_mutex_lock(&g_print_lock);
        printf("\n[!!] FOUND: %s\n -> Rule: %s\n", filepath, rule->identifier);
        pthread_mutex_unlock(&g_print_lock);
    }
    return CALLBACK_CONTINUE;
}

void* WorkerThread(void* arg) {
    while (1) {
        char *filepath = NULL;

        // Get the file from the queue
        pthread_mutex_lock(&g_queue.lock);
        while (g_queue.head == NULL && !g_queue.finished_loading) {
            pthread_cond_wait(&g_queue.cond, &g_queue.lock);
        }

        if (g_queue.head == NULL && g_queue.finished_loading) {
            pthread_mutex_unlock(&g_queue.lock);
            break; // Done
        }

        TaskNode *node = g_queue.head;
        filepath = node->filepath;
        g_queue.head = node->next;
        if (g_queue.head == NULL) g_queue.tail = NULL;
        free(node);
        pthread_mutex_unlock(&g_queue.lock);

        /* Each thread will perform the scan using mmap */
        int fd = open(filepath, O_RDONLY);
        if (fd != -1) {
            struct stat st;
            if (fstat(fd, &st) == 0 && st.st_size > 0) {
                // Map the file into memory with mmap
                void *mapped_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (mapped_data != MAP_FAILED) {
                    madvise(mapped_data, st.st_size, MADV_WILLNEED);
                    int result = yr_rules_scan_mem(g_rules, (uint8_t*)mapped_data, st.st_size, 0, YARACallBack, filepath, 0);
                    munmap(mapped_data, st.st_size);

                    // Update the statistics 
                    pthread_mutex_lock(&g_stats.lock);
                    g_stats.files_scanned++;
                    g_stats.bytes_scanned += st.st_size;
                    pthread_mutex_unlock(&g_stats.lock);
                } else {
                     // mmap Error
                     pthread_mutex_lock(&g_stats.lock);
                     g_stats.errors++;
                     pthread_mutex_unlock(&g_stats.lock);
                }
            } else {
                 if (st.st_size != 0) { 
                     // Count if there's a just error
                     pthread_mutex_lock(&g_stats.lock);
                     g_stats.errors++;
                     pthread_mutex_unlock(&g_stats.lock);
                 }
            }
            close(fd);
        } else {
            // The file was not opened
            pthread_mutex_lock(&g_stats.lock);
            g_stats.errors++;
            pthread_mutex_unlock(&g_stats.lock);
        }

        free(filepath);
    }
    return NULL;
}

void TraverseDirectory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) return;

    struct dirent *entry;
    char path[1024];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        struct stat statbuf;
        if (stat(path, &statbuf) == 0) {
            if (S_ISDIR(statbuf.st_mode)) {
                TraverseDirectory(path);
            } else if (S_ISREG(statbuf.st_mode)) {
                // Add the file to the queue
                TaskNode *new_node = malloc(sizeof(TaskNode));
                new_node->filepath = strdup(path);
                new_node->next = NULL;

                pthread_mutex_lock(&g_queue.lock);
                if (g_queue.tail) {
                    g_queue.tail->next = new_node;
                } else {
                    g_queue.head = new_node;
                }
                g_queue.tail = new_node;
                pthread_cond_signal(&g_queue.cond); // Wake up the Worker
                pthread_mutex_unlock(&g_queue.lock);
            }
        }
    }
    closedir(dir);
}

int CheckRuleValidity(const char *filepath) {
    YR_COMPILER *temp_compiler = NULL;
    if (yr_compiler_create(&temp_compiler) != ERROR_SUCCESS) return 0;

    FILE *f = fopen(filepath, "r");
    if (!f) {
        yr_compiler_destroy(temp_compiler);
        return 0;
    }

    // Add the file to temporary compiler
    // If the rule is incorrect, it returns errors > 0
    int errors = yr_compiler_add_file(temp_compiler, f, NULL, filepath);
    
    fclose(f);
    yr_compiler_destroy(temp_compiler); // Destroy the Temporary Compıler

    return (errors == 0);
}

int CompileRules(const char *rules_dir) {
    YR_COMPILER *compiler = NULL;
    int result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) return -1;

    DIR *dir = opendir(rules_dir);
    if (!dir) {
        yr_compiler_destroy(compiler);
        return -1;
    }

    printf("[*] The Rules are being compiled: %s\n", rules_dir);
    struct dirent *entry;
    char path[1024];
    int count = 0;

    while ((entry = readdir(dir)) != NULL) {
        // Check the .yar extension of the file 
        if (strstr(entry->d_name, ".yar")) {
            snprintf(path, sizeof(path), "%s/%s", rules_dir, entry->d_name);
            
            // Check the validity of the file 
            if (CheckRuleValidity(path)) {
                FILE *f = fopen(path, "r");
                if (f) {
                    // Add the file to compiler
                    if (yr_compiler_add_file(compiler, f, NULL, path) == 0) {
                        count++;
                    }
                    fclose(f);
                }
            } else {
                /*
                    Print the broken files. This may reduce the performance. 
                    You can delete the printf
                */
                printf(" [!] Rule Error (Skipping): %s\n", entry->d_name);
            }
        }
    }
    closedir(dir);

    if (count == 0) {
        yr_compiler_destroy(compiler);
        return 0;
    }

    printf("[+] The number of %d has been determined\n", count);
    printf("[*] Rules are being compiled...\n");
    
    if (yr_compiler_get_rules(compiler, &g_rules) != ERROR_SUCCESS) {
        printf("[-] Compiler Error...\n");
        yr_compiler_destroy(compiler);
        return -1;
    }

    yr_compiler_destroy(compiler);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: ./yara_scanner <rules_dir> <scan_dir>\n");
        return 1;
    }
    // Start YARA
    yr_initialize();

    // 1. Load the Rules from the target directory
    if (CompileRules(argv[1]) <= 0) {
        printf("[-] Failed to load the Rule\n");
        yr_finalize();
        return 1;
    }
    printf("[+] The scan is starting...\n");

    /* Get the time for the stats */
    clock_t start_time = clock();

    // Create Thread Pool
    int NumberThreads = sysconf(_SC_NPROCESSORS_ONLN);
    printf("[*] Threads: %d\n", NumberThreads);

    pthread_t *Threads = malloc(sizeof(pthread_t) * NumberThreads);
    for (int i = 0; i < NumberThreads; i++) {
        pthread_create(&Threads[i], NULL, WorkerThread, NULL);
    }

    /*
        The operations to be performed here are executed by the Main Thread. 
        The preparations made by the Main Thread will be processed by other threads.
    */

    // Add the files to the queue
    TraverseDirectory(argv[2]);

    // Report that the work is finished 
    pthread_mutex_lock(&g_queue.lock);
    g_queue.finished_loading = 1;
    pthread_cond_broadcast(&g_queue.cond); // Wake up all sleeping threads
    pthread_mutex_unlock(&g_queue.lock);

    // Wait for the threads 
    for (int i = 0; i < NumberThreads; i++) {
        pthread_join(Threads[i], NULL);
    }

    /* Now we will print the results */
    clock_t end_time = clock();
    double duration = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    double total_mb = g_stats.bytes_scanned / (1024.0 * 1024.0);
    double speed_mb = (duration > 0) ? total_mb / duration : 0;
    double speed_files = (duration > 0) ? g_stats.files_scanned / duration : 0;

    printf("\n==============================\n");
    printf("           Statistics\n");
    printf("==============================\n");
    printf("Scanned File    : %ld\n", g_stats.files_scanned);
    printf("Broken Files    : %ld\n", g_stats.errors);
    printf("Detected Threat : %ld\n", g_stats.threats_found);
    printf("Total Data      : %.2f MB\n", total_mb);
    printf("Time            : %.4f sn\n", duration);
    printf("File Speed      : %.2f dosya/sn\n", speed_files);
    printf("Data Speed      : %.2f MB/sn\n", speed_mb);
    printf("==============================\n");

    if (g_rules) {
        yr_rules_destroy(g_rules);
    }
    yr_finalize();
    free(Threads);
    return 0;
}