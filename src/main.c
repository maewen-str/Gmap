#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../include/scanner.h"

//  Main logic  would be in main file to parse and process all different flag supplied
int main(int argc, char* argv[]){
    ScanConfig config;
    memset(&config, 0, sizeof(ScanConfig));

    strncpy(config.target_ip, "127.0.0.1", sizeof(config.target_ip) - 1);
    config.start_port = 1;
    config.end_port = 1024;
    config.is_tcp = 1; // Default TCP scan

    run_scanner(&config);

    return 0;
}
