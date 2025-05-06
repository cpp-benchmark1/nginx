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
#define UPLOAD_DIR "/app/uploads"

// Function to handle file uploads
void handle_upload(int socket_fd) {
    char buffer[BUFFER_SIZE] = { 0 };
    char filename[BUFFER_SIZE] = { 0 };
    char response[BUFFER_SIZE] = { 0 };
    char *content = NULL;
    
    printf("Connection received, reading upload request...\n");
    
    // Read the entire request
    ssize_t bytes_read = read(socket_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        printf("Failed to read request\n");
        return;
    }
    buffer[bytes_read] = '\0';  // Null terminate
    
    printf("Request received: %s\n", buffer);
    
    // Find the newline that separates filename from content
    char *newline = strchr(buffer, '\n');
    if (!newline) {
        snprintf(response, sizeof(response), "Invalid request format - missing newline\n");
        write(socket_fd, response, strlen(response));
        return;
    }
    
    // Split the request into filename and content
    *newline = '\0';  // Split at newline
    content = newline + 1;
    
    // Extract the filename from the first line
    if (sscanf(buffer, "UPLOAD %s", filename) != 1) {
        snprintf(response, sizeof(response), "Invalid request format - missing filename\n");
        write(socket_fd, response, strlen(response));
        return;
    }
    
    printf("Filename: %s\n", filename);
    printf("Content: %s\n", content);
    
    // SINK: Vulnerable to path traversal - no path validation
    char fullpath[BUFFER_SIZE];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", UPLOAD_DIR, filename);
    printf("Attempting to create file: %s\n", fullpath);
    
    // Create the file
    int fd = open(fullpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        snprintf(response, sizeof(response), "Error creating file: %s\n", strerror(errno));
        write(socket_fd, response, strlen(response));
        return;
    }
    
    // Write the content to the file
    if (write(fd, content, strlen(content)) != strlen(content)) {
        snprintf(response, sizeof(response), "Error writing to file\n");
        write(socket_fd, response, strlen(response));
        close(fd);
        return;
    }
    
    close(fd);
    snprintf(response, sizeof(response), "File uploaded successfully\n");
    write(socket_fd, response, strlen(response));
}

int main(int argc, char const* argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // Create upload directory if it doesn't exist
    mkdir(UPLOAD_DIR, 0755);

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
    printf("Upload directory: %s\n", UPLOAD_DIR);

    while(1) {
        printf("\nWaiting for connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Handle the upload
        handle_upload(new_socket);
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