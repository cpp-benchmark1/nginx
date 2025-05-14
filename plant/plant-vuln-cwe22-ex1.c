#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define BASE_DIR "/app/files"

// Function to handle file requests
void handle_request(int client_fd) {
    char buffer[BUFFER_SIZE] = { 0 };
    char response[BUFFER_SIZE] = { 0 };
    
    printf("\n=== New Request ===\n");
    printf("Waiting for request...\n");
    
    // SOURCE: Vulnerable to path traversal - receiving untrusted input from socket
    ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        printf("Failed to read request\n");
        return;
    }
    buffer[bytes_read] = '\0';
    
    // Remove newline if present
    if (buffer[bytes_read-1] == '\n') {
        buffer[bytes_read-1] = '\0';
    }
    
    printf("Received request: '%s'\n", buffer);
    
    // SINK: Vulnerable to path traversal - no path validation
    char fullpath[BUFFER_SIZE];
    snprintf(fullpath, sizeof(fullpath), "%s%s", BASE_DIR, buffer);
    printf("Attempting to access: %s\n", fullpath);
    
    // Try to open the file
    int fd = open(fullpath, O_RDONLY);
    if (fd < 0) {
        printf("Error opening file: %s\n", strerror(errno));
        snprintf(response, sizeof(response), "ERROR: %s\n", strerror(errno));
        write(client_fd, response, strlen(response));
        return;
    }
    
    // Read file contents
    bytes_read = read(fd, response, BUFFER_SIZE - 1);
    if (bytes_read > 0) {
        response[bytes_read] = '\0';
        printf("File contents (%zd bytes):\n%s\n", bytes_read, response);
        printf("Sending response to client...\n");
        write(client_fd, response, bytes_read);
        printf("Response sent successfully\n");
    } else {
        printf("File is empty\n");
        write(client_fd, "File is empty\n", 13);
    }
    
    close(fd);
    printf("=== Request Handled ===\n");
}

int main(int argc, char const* argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    printf("=== Starting Server ===\n");
    
    // Create base directory
    if (mkdir(BASE_DIR, 0755) < 0) {
        if (errno != EEXIST) {
            perror("mkdir failed");
            exit(EXIT_FAILURE);
        }
        printf("Base directory already exists\n");
    } else {
        printf("Base directory created: %s\n", BASE_DIR);
    }
    
    // Create test files
    char test_file[BUFFER_SIZE];
    snprintf(test_file, sizeof(test_file), "%s/test.txt", BASE_DIR);
    
    // Create test file with proper permissions
    int fd = open(test_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *test_content = "This is a test file\n";
        if (write(fd, test_content, strlen(test_content)) == -1) {
            perror("write failed");
            exit(EXIT_FAILURE);
        }
        close(fd);
        printf("Created test file: %s\n", test_file);
        printf("Test file contents: %s", test_content);
    } else {
        perror("Failed to create test file");
        exit(EXIT_FAILURE);
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created successfully\n");

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    printf("Socket options set\n");

    // Bind socket
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket bound to port %d\n", PORT);

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server listening for connections\n");

    printf("\n=== Server Ready ===\n");
    printf("Server running on port %d\n", PORT);
    printf("Base directory: %s\n", BASE_DIR);
    printf("Test file: %s\n", test_file);
    printf("\nTo test:\n");
    printf("1. Normal request: echo '/test.txt' | nc localhost 8080\n");
    printf("2. Path traversal: echo '/../../../etc/passwd' | nc localhost 8080\n");
    printf("\nWaiting for connections...\n");

    while(1) {
        // Accept new connection
        if ((client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }
        
        printf("New connection from %s:%d\n", 
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        
        // Handle the request
        handle_request(client_fd);
        
        // Close the connection
        close(client_fd);
    }

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
     echo "GET /test.txt" | nc -u localhost 8080
   
   - Path traversal attack to read /etc/passwd:
     echo "GET /../../../etc/passwd" | nc -u localhost 8080
   
   - Path traversal attack to read /etc/shadow:
     echo "GET /../../../etc/shadow" | nc -u localhost 8080
   
   - Path traversal attack to read /proc/self/environ:
     echo "GET /../../../proc/self/environ" | nc -u localhost 8080

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