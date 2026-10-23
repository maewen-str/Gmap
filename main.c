#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>


#include "scan.h"

//  Main logic  would be in main file to parse and process all different flag supplied
int main(int argc, char* argv[]){
    struct sockaddr_in target_addr;
    memset(&target_addr,0,sizeof(target_addr)); // Clean the garbage value
    target_addr.sin_family = AF_INET; // IPV4

    //DNS resolution
    //For IP we use inet_pton  while we should use getaddrinfo() for hostnames once the parsing will be done
    inet_pton(AF_INET, "127.0.0.1", &target_addr.sin_addr);

    // Let's scan a range of specified port
    int start_port = 1;
    int end_port =  1024;

    int open_port_counter = 0;
    for(int port = start_port; port < end_port+1;  port++) {
        if(scan_port(target_addr,port) == 0) {
            printf("PORT %d is OPEN\n",port);
            open_port_counter++;
        }

    }
    printf("%d PORT were OPEN\n",open_port_counter);

    return 0;
}
