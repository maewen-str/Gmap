#  Port Scanner (find a better name later)


## Usage 




## Main logic


The Logic: How a Port Scanner Works

A standard port scanner (specifically a "TCP Connect" scanner, which is the best starting point) operates by attempting to complete a full TCP 3-way handshake with a target IP address on a specific range of ports.

    Argument Parsing: Your program should take a target IP address or hostname and a range of ports (e.g., 1 to 1024) via command-line arguments.

    DNS Resolution (Optional but useful): If the user inputs a hostname (like google.com), use getaddrinfo() to resolve it to an IP address.

    The Scanning Loop: Iterate through your desired port range. For each port:

        Create a Socket: Use the socket() system call to create a TCP socket (using AF_INET for IPv4 and SOCK_STREAM for TCP).

        Define the Target: Populate a sockaddr_in structure with the target's IP address and the current port number. You will need functions like htons() to convert the port number to network byte order, and inet_pton() to convert the IP string to a binary format.

        Attempt Connection: Call connect().

            If it returns 0, the 3-way handshake was successful—the port is open.

            If it returns -1, the connection failed (e.g., connection refused or timeout)—the port is closed or filtered.

        Close the Socket: Always close() the socket before moving to the next port to avoid exhausting your system's file descriptors.

    Service Mapping (The "Mapper" part): If a port is open, you can map it to its standard service (e.g., port 80 = HTTP). The C standard library provides getservbyport() which looks up the standard service name for a given port.
