#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Sensitive data that we want to protect
char admin_password[32] = "SUPER_SECRET_ADMIN_PASS";
int admin_flag = 0xdeadbeef;

// Function to handle user input
void handle_input(int socket_fd) {
    char buffer[BUFFER_SIZE] = { 0 };
    char username[32] = { 0 };
    char input[BUFFER_SIZE] = { 0 };
    
    printf("Connection received, reading data...\n");
    
    // Read all data at once
    ssize_t bytes_read = read(socket_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        printf("Failed to read data\n");
        return;
    }
    buffer[bytes_read] = '\0';  // Null terminate
    
    // Split the input into username and input
    char *newline = strchr(buffer, '\n');
    if (newline) {
        *newline = '\0';  // Split at newline
        strncpy(username, buffer, sizeof(username) - 1);
        strncpy(input, newline + 1, sizeof(input) - 1);
    } else {
        strncpy(username, buffer, sizeof(username) - 1);
    }
    
    printf("Username received: %s\n", username);
    printf("Input received (%zd bytes): %s\n", strlen(input), input);
    
    // Print debug info
    printf("\nDebug info - Addresses:\n");
    printf("admin_password: %p\n", (void*)admin_password);
    printf("admin_flag: %p\n", (void*)&admin_flag);
    printf("input buffer: %p\n", (void*)input);
    printf("Initial admin_flag value: 0x%x\n", admin_flag);
    
    // SINK: Vulnerable to format string - no format string validation
    printf("\nUser input: ");
    printf(input);  // Vulnerable to format string attack
    printf("\n");
    
    // Print final state
    printf("\nFinal state:\n");
    printf("admin_flag: 0x%x\n", admin_flag);
    printf("admin_password: %s\n", admin_password);
    
    // Send response back to client
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Processed input: %s", input);
    write(socket_fd, response, strlen(response));
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
    printf("Initial values:\n");
    printf("admin_flag: 0x%x\n", admin_flag);
    printf("admin_password: %s\n", admin_password);

    while(1) {
        printf("\nWaiting for connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Handle the input
        handle_input(new_socket);
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
       python3 \
       vim \
       && rm -rf /var/lib/apt/lists/*
   WORKDIR /app
   COPY . /app
   CMD ["/bin/bash"]

2. Build the Docker image:
   docker build -t cwe134-test .

3. Start the container and mount your code:
   docker run -it --name cwe134-container -v "$PWD":/app cwe134-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe134-ex1 plant-vuln-cwe134-ex1.c

5. Run the server (in first terminal):
   ./vuln-cwe134-ex1

6. Open a second terminal and access the container:
   docker exec -it cwe134-container /bin/bash

7. Test the vulnerability:
   - Normal input:
     (echo -e "admin\nHello World") | nc localhost 8080
   
   - Format string attack to leak memory:
     (echo -e "admin\n%p %p %p %p %p") | nc localhost 8080
   
   - Format string attack to leak admin flag:
     (echo -e "admin\n%x %x %x %x %x") | nc localhost 8080
   
   - Format string attack to modify memory:
     (echo -e "admin\n%n %n %n %n %n") | nc localhost 8080

Expected behavior:
- The program will show addresses of sensitive data
- The format string vulnerability will be visible in the output
- You can see memory leaks or program crashes
- The output will show the effects of the format string attack

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Memory leaks
- Information disclosure
- Memory corruption
- Potential system compromise
*/ 