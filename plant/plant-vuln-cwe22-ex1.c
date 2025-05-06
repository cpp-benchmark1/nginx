#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define BASE_DIR "/app/files"

// Function to handle file requests
void handle_request(int socket_fd) {
    char buffer[BUFFER_SIZE] = { 0 };
    char filepath[BUFFER_SIZE] = { 0 };
    char response[BUFFER_SIZE] = { 0 };
    
    printf("Connection received, reading request...\n");
    
    // Read the request
    ssize_t bytes_read = read(socket_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        printf("Failed to read request\n");
        return;
    }
    buffer[bytes_read] = '\0';  // Null terminate
    
    printf("Request received: %s\n", buffer);
    
    // Extract the requested file path
    if (sscanf(buffer, "GET %s", filepath) != 1) {
        snprintf(response, sizeof(response), "Invalid request format\n");
        write(socket_fd, response, strlen(response));
        return;
    }
    
    // SINK: Vulnerable to path traversal - no path validation
    char fullpath[BUFFER_SIZE];
    snprintf(fullpath, sizeof(fullpath), "%s%s", BASE_DIR, filepath);
    printf("Attempting to access file: %s\n", fullpath);
    
    // Try to open the file
    int fd = open(fullpath, O_RDONLY);
    if (fd < 0) {
        snprintf(response, sizeof(response), "Error opening file: %s\n", strerror(errno));
        write(socket_fd, response, strlen(response));
        return;
    }
    
    // Read and send file contents
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes_read] = '\0';
        write(socket_fd, buffer, bytes_read);
    }
    
    close(fd);
}

int main(int argc, char const* argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // Create base directory if it doesn't exist
    mkdir(BASE_DIR, 0755);
    
    // Create a test file
    char test_file[BUFFER_SIZE];
    snprintf(test_file, sizeof(test_file), "%s/test.txt", BASE_DIR);
    int fd = open(test_file, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        write(fd, "This is a test file\n", 20);
        close(fd);
    }

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
    printf("Base directory: %s\n", BASE_DIR);
    printf("Test file created at: %s\n", test_file);

    while(1) {
        printf("\nWaiting for connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Handle the request
        handle_request(new_socket);
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
   docker build -t cwe22-test .

3. Start the container and mount your code:
   docker run -it --name cwe22-container -v "$PWD":/app cwe22-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe22-ex1 plant-vuln-cwe22-ex1.c

5. Run the server (in first terminal):
   ./vuln-cwe22-ex1

6. Open a second terminal and access the container:
   docker exec -it cwe22-container /bin/bash

7. Test the vulnerability:
   - Normal request:
     echo "GET /test.txt" | nc localhost 8080
   
   - Path traversal attack to read /etc/passwd:
     echo "GET /../../../etc/passwd" | nc localhost 8080
   
   - Path traversal attack to read /etc/shadow:
     echo "GET /../../../etc/shadow" | nc localhost 8080
   
   - Path traversal attack to read /proc/self/environ:
     echo "GET /../../../proc/self/environ" | nc localhost 8080

Expected behavior:
- The program will show the requested file path
- The path traversal vulnerability will allow reading files outside the base directory
- You can see the contents of sensitive system files
- The server will show the full path being accessed

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Unauthorized file access
- Information disclosure
- System file exposure
- Potential system compromise
*/ 