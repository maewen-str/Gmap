#include "../include/scanner.h"
#include <bits/pthreadtypes.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <pthread.h>

#define MAX_THREADS 256

pthread_mutex_t console_mutex = PTHREAD_MUTEX_INITIALIZER;

void *scan_worker(void *arg) {
    ThreadArgs *args = (ThreadArgs *) arg; // Deference the argument pointer into our threadarg  type
    int port = args->port;

    // With this protocol argument  both type of scan cannot be executed by the same thread
    // This unreadable output and UDP scan for a port that drags the TCP scan.
    if (args->protocol == 1) {
        if (scan_tcp(args->target_addr, port) == 0) {
            // We are force  to put a mutex here since each thread is reading /etc/services
            // this could create race condition.
            pthread_mutex_lock(&console_mutex);
            struct servent  *service = getservbyport(htons(port),"tcp"); // Uses /etc/services
            const char *service_name = (service != NULL) ? service->s_name : "unknown";
            printf("PORT %d is OPEN (%s) | (TCP)\n", port, service_name);
            pthread_mutex_unlock(&console_mutex);
        }
    }

    if (args->protocol == 2) {
        int udp_status = scan_udp(args->target_addr, port);
        if (udp_status == 0 || udp_status == 1){

            pthread_mutex_lock(&console_mutex);
            struct servent *service = getservbyport(htons(port),"udp");
            const char *service_name = (service != NULL) ? service->s_name : "unknown";

            if (udp_status == 0) {
                printf("PORT %d is OPEN (%s) | (UDP)\n",port, service_name);
            } else if (udp_status == 1) {
                printf("PORT %d is OPEN|FILTERED (%s) | (UDP)\n",port, service_name);
            }
            pthread_mutex_unlock(&console_mutex);
        }
    }
    return NULL;
}

int run_scanner(ScanConfig *config) {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;


    // Resolve the IP once
    if (inet_pton(AF_INET, config->target_ip, &target_addr.sin_addr) <= 0) {
        printf("Invalid IP address.\n");
        return -1;
    }

    printf("Scanning %s from port %d to %d... \n",config->target_ip,config->start_port, config->end_port);

    pthread_t threads[MAX_THREADS];
    ThreadArgs args_array[MAX_THREADS];
    int thread_count = 0;

    //Run TCP scan first
    if (config->is_tcp) {
        printf("\n--- Starting TCP Scan ---\n");
        for (int port = config->start_port; port <= config->end_port; port++) {
            // Instead of doing a dynamic malloc for every port which is really slow.
            // It is better to manage a preallocated array of value to pass to thread.
            args_array[thread_count].target_addr = target_addr;
            args_array[thread_count].port = port;
            args_array[thread_count].protocol = 1; // TCP

            pthread_create(&threads[thread_count], NULL, scan_worker, &args_array[thread_count]);
            thread_count++;

            if(thread_count == MAX_THREADS || port == config->end_port ) {
                for (int i = 0; i < thread_count; i++) {
                    pthread_join(threads[i], NULL);
                }
                thread_count = 0;
            }
        }
    }
    // Then run UDP
    if (config->is_udp) {
        printf("\n--- Starting UDP Scan ---\n");
        for (int port = config->start_port; port <= config->end_port; port++) {

            args_array[thread_count].target_addr = target_addr;
            args_array[thread_count].port = port;
            args_array[thread_count].protocol = 2; // UDP

            pthread_create(&threads[thread_count], NULL, scan_worker, &args_array[thread_count]);
            thread_count++;
            if(thread_count == MAX_THREADS || port == config->end_port ) {
                for (int i = 0; i < thread_count; i++) {
                    pthread_join(threads[i], NULL);
                }
                thread_count = 0;
            }
        }
    }

    return 0;

}
