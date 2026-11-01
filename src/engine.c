#include "../include/scanner.h"
#include <bits/pthreadtypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

#define MAX_THREADS 256

pthread_mutex_t console_mutex = PTHREAD_MUTEX_INITIALIZER;

void *scan_worker(void *arg) {
    ThreadArgs *args = (ThreadArgs *) arg; // Deference the argument pointer into our threadarg  type
    int port = args->port;
    args->status = 0;
    // With this protocol argument  both type of scan cannot be executed by the same thread
    // This unreadable output and UDP scan for a port that drags the TCP scan.
    if (args->protocol == 1) {
        if (scan_tcp(args->target_addr, port) == 0) {
            args->status = 1;
            // We are force  to put a mutex here since each thread is reading /etc/services
            // this could create race condition.
            pthread_mutex_lock(&console_mutex);
            struct servent  *service = getservbyport(htons(port),"tcp"); // Uses /etc/services
            strncpy(args->service_name, (service != NULL) ? service->s_name : "unknown", 31);
            // Safeguard in case service name is too long
            args->service_name[31] = '\0';
            pthread_mutex_unlock(&console_mutex);
        }
    }

    if (args->protocol == 2) {
        int udp_status = scan_udp(args->target_addr, port);
        if (udp_status == 0 || udp_status == 1){
            args->status = (udp_status == 0) ? 1 : 2; // 1 = Open ; 2 = Open | Filtered

            pthread_mutex_lock(&console_mutex);
            struct servent *service = getservbyport(htons(port),"udp");
            strncpy(args->service_name,(service != NULL) ? service->s_name : "unknown",31);
            // Safeguard in case service name is too long
            args->service_name[31] = '\0';
            pthread_mutex_unlock(&console_mutex);
        }
    }
    return NULL;
}

void run_protocol_scan(ScanConfig *config, struct sockaddr_in target_addr, int protocol) {
    pthread_t threads[MAX_THREADS];
    ThreadArgs args_array[MAX_THREADS];
    int thread_count = 0;
    const char *proto_name = (protocol == 1) ? "TCP" : "UDP";

    printf("\n--- Starting %s Scan ---\n", proto_name);

    for (int port = config->start_port; port <= config->end_port; port++) {
        // Instead of doing a dynamic malloc for every port which is really slow.
        // It is better to manage a preallocated array of value to pass to thread.

        memset(&args_array[thread_count], 0, sizeof(ThreadArgs));
        args_array[thread_count].target_addr = target_addr;
        args_array[thread_count].port = port;
        args_array[thread_count].protocol = protocol;
        args_array[thread_count].status = 0; // Default to closed

        pthread_create(&threads[thread_count], NULL, scan_worker, &args_array[thread_count]);
        thread_count++;

        if (thread_count == MAX_THREADS || port == config->end_port) {
            for (int i = 0; i < thread_count; i++){
                pthread_join(threads[i],NULL);
            }

            for (int i = 0; i < thread_count; i++){
                if (args_array[i].status == 1) {
                    printf("PORT %d is OPEN (%s) | (%s)\n",args_array[i].port,args_array[i].service_name,proto_name); // Shared case between TCP and UDP
                } else if (args_array[i].status == 2 && protocol == 2) {
                    printf("PORT %d is OPEN|FILTERED (%s) | (UDP)\n",args_array[i].port,args_array[i].service_name);
                }
            }
            thread_count = 0;
        }
    }
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

    // Run TCP first
    if(config->is_tcp) run_protocol_scan(config, target_addr, 1);
    //Then UDP scan
    if(config->is_udp) run_protocol_scan(config, target_addr, 2);

    return 0;

}
