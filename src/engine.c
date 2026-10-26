#include "../include/scanner.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>


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

    for (int port = config->start_port; port <= config->end_port; port++){
         if (config->is_tcp) {
             if (scan_tcp(target_addr, port) == 0) {
                struct servent  *service = getservbyport(htons(port),"tcp"); // Uses /etc/services

                if (service != NULL) {
                    printf("PORT %d is OPEN (%s) | (TCP)\n",port,service->s_name);
                } else {
                    printf("PORT %d is OPEN (unknown) | (TCP)\n",port);
                }

             }
         }
    }

}
