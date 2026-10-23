#ifndef SCAN_H
#define SCAN_H

#include <netinet/in.h>
int scan_port(struct sockaddr_in target_addr,  int port);

#endif
