#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>


#include "scan.h"



int  scan_port(struct sockaddr_in target_addr ,int port){
    // For performance cost we want to proceed the DNS lookup outside of this function
    // target_addr already dispose of port slot (sin_port) which  will be set using htons. This way the target_addr port remains  untouched during the procedure because we manipule a copy of it.

    target_addr.sin_port =  htons(port); // cast our int into in_port_t


    // Create the socket
    int sock = socket(AF_INET, SOCK_STREAM, 0); // AF_INET is the class of IPV4 (AF_INET6 for IPV6)
    if (sock < 0) {
        return 1; // Failed to intialize the sokcet
    }


    // Attempt connection
    int status =  connect(sock, (struct sockaddr *)&target_addr, sizeof(target_addr));
    close(sock);

    return (status == 0) ? 0 : -1;
}
