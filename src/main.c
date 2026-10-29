#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "../include/scanner.h"

void print_usage(const char *prog_name) {
    printf("Usage: %s [-t] [-u] [-p start-end] <IP_ADDRESS>\n", prog_name);
    printf("Options:\n");
    printf("  -t           Enable TCP scan\n");
    printf("  -u           Enable UDP scan\n");
    printf("  -p ports     Port range (e.g., 80 or 20-100)\n");
}


int main(int argc, char* argv[]){
    // Safe default  config if none provided
    ScanConfig config;
    memset(&config, 0, sizeof(ScanConfig));
    config.start_port = 1;
    config.end_port = 1024;
    config.is_tcp = 1; // Default TCP scan


    int opt;
    // We use getopt to parse the input with POSIX norm
    // "tup:" means t and u are standalone flags while "p:" means that the p flag requires a port argument after it
    while ((opt = getopt(argc, argv, "tup:")) != -1) {
        switch (opt) {
            case 't':
                config.is_tcp = 1;
                break;
            case 'u':
                config.is_udp = 1;
                break;
            case 'p':
                // If statement handle the case where only one port  "-p 80" is given
                if (sscanf(optarg, "%d-%d", &config.start_port, &config.end_port) == 1) {
                    config.end_port = config.start_port;
                }

                if (config.start_port > config.end_port) {
                    printf("Error: Start port cannot be greater than end port.\n");
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Default to TCP if no protocol were provided
    if (!config.is_tcp && !config.is_udp) {
        config.is_tcp = 1;
    }

    //
    if (optind >= argc) {
         printf("Error : Missing target IP address.\n");
         print_usage(argv[0]);
         return 1;
    }

    strncpy(config.target_ip, argv[optind], sizeof(config.target_ip) - 1);

    run_scanner(&config);

    return 0;
}
