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
#define UPLOAD_DIR "/app/uploads"

// Function to handle file uploads
void handle_upload(int client_fd) {
    char buffer[BUFFER_SIZE] = { 0 };
    char filename[BUFFER_SIZE] = { 0 };
    char response[BUFFER_SIZE] = { 0 };
    
    printf("\n=== New Upload Request ===\n");
    fflush(stdout);
    
    // SOURCE: Vulnerable to path traversal - receiving untrusted input from socket
    printf("Waiting for data...\n");
    fflush(stdout);
    
    ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    
    if (bytes_read <= 0) {
        printf("Failed to read request: %s\n", strerror(errno));
        fflush(stdout);
        return;
    }
    
    buffer[bytes_read] = '\0';  // Null terminate
    
    printf("Received %zd bytes\n", bytes_read);
    fflush(stdout);
    
    printf("Raw data:\n%s\n", buffer);
    fflush(stdout);
    
    // Find the newline that separates filename from content
    char *newline = strchr(buffer, '\n');
    if (!newline) {
        printf("Invalid request format - missing newline\n");
        fflush(stdout);
        strcpy(response, "Invalid request format - missing newline\n");
        write(client_fd, response, strlen(response));
        return;
    }
    
    // Split the request into filename and content
    *newline = '\0';  // Split at newline
    char *content = newline + 1;
    
    // Extract the filename from the first line
    if (sscanf(buffer, "UPLOAD %s", filename) != 1) {
        printf("Invalid request format - missing filename\n");
        fflush(stdout);
        strcpy(response, "Invalid request format - missing filename\n");
        write(client_fd, response, strlen(response));
        return;
    }
    
    printf("Filename: %s\n", filename);
    fflush(stdout);
    printf("Content: %s\n", content);
    fflush(stdout);
    
    // SINK: Vulnerable to path traversal - no path validation
    char fullpath[BUFFER_SIZE];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", UPLOAD_DIR, filename);
    printf("Attempting to create file: %s\n", fullpath);
    fflush(stdout);
    
    // Create the file
    int fd = open(fullpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("Error creating file: %s\n", strerror(errno));
        fflush(stdout);
        snprintf(response, sizeof(response), "Error creating file: %s\n", strerror(errno));
        write(client_fd, response, strlen(response));
        return;
    }
    
    // Write the content to the file
    ssize_t bytes_written = write(fd, content, strlen(content));
    if (bytes_written != strlen(content)) {
        printf("Error writing to file: %s\n", strerror(errno));
        fflush(stdout);
        strcpy(response, "Error writing to file\n");
        write(client_fd, response, strlen(response));
        close(fd);
        return;
    }
    
    close(fd);
    printf("File created successfully (%zd bytes written)\n", bytes_written);
    fflush(stdout);
    
    // Read back the file to verify
    fd = open(fullpath, O_RDONLY);
    if (fd >= 0) {
        char verify_buffer[BUFFER_SIZE] = {0};
        ssize_t verify_read = read(fd, verify_buffer, BUFFER_SIZE - 1);
        if (verify_read > 0) {
            verify_buffer[verify_read] = '\0';
            printf("\n=== File Contents ===\n");
            printf("Path: %s\n", fullpath);
            printf("Size: %zd bytes\n", verify_read);
            printf("Content:\n%s\n", verify_buffer);
            printf("===================\n");
        }
        close(fd);
    }
    
    strcpy(response, "File uploaded successfully\n");
    write(client_fd, response, strlen(response));
    printf("=== Upload Request Handled ===\n");
    fflush(stdout);
}

int main(int argc, char const* argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    printf("=== Starting Upload Server ===\n");
    fflush(stdout);
    
    // Create upload directory if it doesn't exist
    if (mkdir(UPLOAD_DIR, 0755) < 0) {
        if (errno != EEXIST) {
            perror("mkdir failed");
            exit(EXIT_FAILURE);
        }
        printf("Upload directory already exists\n");
    } else {
        printf("Upload directory created\n");
    }
    printf("Upload directory: %s\n", UPLOAD_DIR);
    fflush(stdout);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created successfully\n");
    fflush(stdout);

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    printf("Socket options set\n");
    fflush(stdout);

    // Bind socket
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket bound to port %d\n", PORT);
    fflush(stdout);

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d...\n", PORT);
    fflush(stdout);

    printf("\n=== Server Ready ===\n");
    printf("Server listening on port %d...\n", PORT);
    printf("Upload directory: %s\n", UPLOAD_DIR);
    printf("\nTo test:\n");
    printf("1. Normal upload: (echo -e \"UPLOAD test.txt\\nHello World\"; sleep 1) | nc localhost 8080\n");
    printf("2. Path traversal: (echo -e \"UPLOAD ../../../etc/passwd\\nroot:x:0:0:root:/root:/bin/bash\"; sleep 1) | nc localhost 8080\n");
    printf("\nWaiting for uploads...\n");
    fflush(stdout);

    while(1) {
        if ((client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept");
            continue;
        }
        
        printf("New connection from %s:%d\n", 
               inet_ntoa(address.sin_addr), 
               ntohs(address.sin_port));
        fflush(stdout);
        
        handle_upload(client_fd);
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
   gcc -o vuln-cwe22-ex2 plant-vuln-cwe22-ex2.c

5. Run the server (in first terminal):
   ./vuln-cwe22-ex2

6. Open a second terminal and access the container:
   docker exec -it cwe22-container /bin/bash

7. Test the vulnerability:
   - Normal upload:
     (echo -e "UPLOAD test.txt\nHello World"; sleep 1) | nc localhost 8080
   
   - Path traversal attack to write to /etc/passwd:
     (echo -e "UPLOAD ../../../etc/passwd\nroot:x:0:0:root:/root:/bin/bash"; sleep 1) | nc localhost 8080
   
   - Path traversal attack to write to /etc/shadow:
     (echo -e "UPLOAD ../../../etc/shadow\nroot:$6$salt$hash:18000:0:99999:7:::"; sleep 1) | nc localhost 8080
   
   - Path traversal attack to write to /proc/self/environ:
     (echo -e "UPLOAD ../../../proc/self/environ\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; sleep 1) | nc localhost 8080

Expected behavior:
- The program will show the requested file path
- The path traversal vulnerability will allow writing files outside the upload directory
- You can see the full path being accessed
- The server will attempt to write to system files

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Unauthorized file access
- File system corruption
- System file modification
- Potential system compromise
*/ 