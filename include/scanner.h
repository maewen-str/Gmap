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

// Structure to pass argument to thread
typedef struct {
    struct sockaddr_in target_addr;
    int port;
    int protocol; // 1 for TCP , 2 for UDP
    int status; // 0 = Closed, 1 = Open, 2 = Open|Filtered
    char service_name[32];
} ThreadArgs;




// Main engine controller
int run_scanner(ScanConfig *config);


// Protocol-specific functions
int scan_tcp(struct sockaddr_in target_addr, int port);
int scan_udp(struct sockaddr_in target_addr, int port);
#endif
