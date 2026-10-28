#include <asm-generic/errno.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/scanner.h"


int scan_udp(struct sockaddr_in target_addr ,int port) {
    target_addr.sin_port = htons(port);

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0); // Socket connection is treated as  a file so the socket function returns a file descriptor
    if (sock < 0) {
        perror("Socket failed");
        return -1;
    }

    //Set a 1-second recieve timeout so recvfrom() does not block forever
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0; // Microseconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    //Send an empty UDP packet to the targeted port
    //Here we do not try to set up a connection  through complex process (3-way handshake).
    //This make the scan way faster than a normal tcp scan.
    sendto(sock, "\n", 1, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));

    //Wait for a response
    char buffer[1024];
    socklen_t addr_len = sizeof(target_addr);
    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&target_addr, &addr_len);
    // Netcat test are not that good bc they can drop the data piped into their buffer.
    // Instead we will use python socket to test out now.
    close(sock);

    if (bytes > 0) {
        return 0; // Data was recieved back. Port is OPEN
    } else if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
         return 1; // Timeout. The packet was silently dropped (OPEN or FILTERED)
    }

    return -1;  // ICMP error recieved (CLOSED) or other failure
}
