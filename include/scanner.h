#ifndef SCAN_H
#define SCAN_H

#include <netinet/in.h>

typedef struct {
    char target_ip[64];
    int start_port;
    int end_port;
    int is_udp;     // Flag for udp scan (-u)
    int is_tcp;     // Flag for tcp scan (-t)
    int num_threads;  // Flag for threads (-n)
} ScanConfig;

// Main engine controller
int run_scanner(ScanConfig *config);


// Protocol-specific functions
int scan_tcp(struct sockaddr_in target_addr, int port);
int scan_udp(struct sockaddr_in target_addr, int port);
#endif
