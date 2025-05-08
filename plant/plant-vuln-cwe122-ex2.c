#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Example 2: Heap overflow using recvmsg()
void vulnerable_heap_overflow2(int socket_fd) {
    char *buffer = malloc(10);  // Small heap allocation
    char *destination = malloc(10);  // Another heap allocation
    struct msghdr msg;
    struct iovec iov;
    char control[BUFFER_SIZE];
    
    printf("Initial heap state:\n");
    printf("Buffer address: %p\n", (void*)buffer);
    printf("Destination address: %p\n", (void*)destination);
    
    // Setup message structure
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = 100;  // Vulnerable: allowing more than buffer size
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    
    // SOURCE: Reading user input from socket using recvmsg
    ssize_t bytes_received = recvmsg(socket_fd, &msg, 0);
    
    printf("\nReceived %zd bytes\n", bytes_received);
    
    // SINK: Vulnerable to heap overflow - no size validation
    memcpy(destination, buffer, bytes_received);  // Vulnerable to heap overflow
    
    printf("\nAfter overflow:\n");
    printf("Buffer content: %s\n", buffer);
    printf("Destination content: %s\n", destination);
    
    // Cleanup
    free(buffer);
    free(destination);
}

int main(int argc, char const* argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while(1) {
        printf("\nWaiting for connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Test the vulnerable function
        vulnerable_heap_overflow2(new_socket);
        close(new_socket);
    }

    // closing the listening socket
    close(server_fd);
    return 0;
}

/*
To test:
1. Create a Dockerfile in the same directory with the following content:
   FROM ubuntu:latest
   RUN apt update && apt install -y \
       build-essential \
       netcat-openbsd \
       vim \
       && rm -rf /var/lib/apt/lists/*
   WORKDIR /app
   COPY . /app
   CMD ["/bin/bash"]

2. Build the Docker image:
   docker build -t cwe122-test .

3. Start the container and mount your code:
   docker run -it --name cwe122-container -v "$PWD":/app cwe122-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe122-ex2 plant-vuln-cwe122-ex2.c

5. Run the server (in first terminal):
   ./vuln-cwe122-ex2

6. Open a second terminal and access the container:
   docker exec -it cwe122-container /bin/bash

7. Test the vulnerability:
   - Send a large string to trigger heap overflow:
     python3 -c "print('B'*100)" | nc localhost 8080

Expected behavior:
- The program will show the initial heap addresses
- It will receive the large string
- The memcpy will overflow the destination buffer
- You may see memory corruption or program crash
- The output will show the corrupted memory state

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Heap corruption
- Memory leaks
- Potential system compromise
*/ 