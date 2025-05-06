#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_REQUESTS 1000
#define MAX_HEADERS 20

typedef struct {
    char method[16];
    char path[256];
    char version[16];
    char headers[MAX_HEADERS][2][256];  // [header_name][header_value]
    int header_count;
    char body[BUFFER_SIZE];
} HttpRequest;

typedef struct {
    int status_code;
    char status_message[64];
    char headers[MAX_HEADERS][2][256];
    int header_count;
    char body[BUFFER_SIZE];
} HttpResponse;

// Global variables (simulating a real application state)
int request_count = 0;
time_t server_start_time;
char server_secret[32] = "SUPER_SECRET_KEY_123";
int admin_flag = 0xdeadbeef;  // Sensitive data to leak

// Function to parse HTTP request
int parse_http_request(int socket_fd, HttpRequest *req) {
    char buffer[BUFFER_SIZE] = { 0 };
    char *line;
    int body_start = 0;
    
    // Read request line
    if (read(socket_fd, buffer, BUFFER_SIZE - 1) <= 0) {
        return -1;
    }
    
    // Parse request line
    line = strtok(buffer, "\r\n");
    if (line) {
        sscanf(line, "%s %s %s", req->method, req->path, req->version);
    }
    
    // Parse headers
    req->header_count = 0;
    while ((line = strtok(NULL, "\r\n")) && line[0] != '\0') {
        if (req->header_count < MAX_HEADERS) {
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                strncpy(req->headers[req->header_count][0], line, 255);
                strncpy(req->headers[req->header_count][1], colon + 1, 255);
                req->header_count++;
            }
        }
    }
    
    return 0;
}

// Function to log HTTP request
void log_request(const HttpRequest *req) {
    char log_buffer[BUFFER_SIZE];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    // SOURCE: User input in log message
    snprintf(log_buffer, BUFFER_SIZE, 
             "[%04d-%02d-%02d %02d:%02d:%02d] %s %s %s - Headers: %d",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             req->method, req->path, req->version, req->header_count);
    
    // SINK: Vulnerable to format string - no format string validation
    printf("Log entry: ");  // Vulnerable to format string attack
    printf(log_buffer);     // This is where the vulnerability is
    printf("\n");
    
    // Print sensitive data addresses for demonstration
    printf("Debug info - Addresses:\n");
    printf("admin_flag: %p\n", (void*)&admin_flag);
    printf("server_secret: %p\n", (void*)server_secret);
    printf("log_buffer: %p\n", (void*)log_buffer);
}

// Function to handle HTTP request
void handle_request(int socket_fd) {
    HttpRequest req = { 0 };
    HttpResponse resp = { 0 };
    
    // Parse the request
    if (parse_http_request(socket_fd, &req) < 0) {
        return;
    }
    
    // Log the request
    log_request(&req);
    
    // Prepare response
    resp.status_code = 200;
    strcpy(resp.status_message, "OK");
    
    // Add response headers
    strcpy(resp.headers[0][0], "Content-Type");
    strcpy(resp.headers[0][1], "text/html");
    resp.header_count = 1;
    
    // Generate response body
    snprintf(resp.body, BUFFER_SIZE,
             "<html><body>"
             "<h1>Welcome to the Server</h1>"
             "<p>Request: %s %s</p>"
             "<p>Server Uptime: %ld seconds</p>"
             "</body></html>",
             req.method, req.path, time(NULL) - server_start_time);
    
    // Send response
    char response[BUFFER_SIZE];
    snprintf(response, BUFFER_SIZE,
             "HTTP/1.1 %d %s\r\n"
             "Content-Length: %zu\r\n"
             "%s: %s\r\n"
             "\r\n"
             "%s",
             resp.status_code, resp.status_message,
             strlen(resp.body),
             resp.headers[0][0], resp.headers[0][1],
             resp.body);
    
    write(socket_fd, response, strlen(response));
}

int main(int argc, char const* argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // Initialize server start time
    server_start_time = time(NULL);

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

    printf("Web server listening on port %d...\n", PORT);
    printf("Debug info - Initial values:\n");
    printf("admin_flag: 0x%x\n", admin_flag);
    printf("server_secret: %s\n", server_secret);

    while(1) {
        printf("\nWaiting for connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Handle the HTTP request
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
   docker build -t cwe134-test .

3. Start the container and mount your code:
   docker run -it --name cwe134-container -v "$PWD":/app cwe134-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe134-ex2 plant-vuln-cwe134-ex2.c

5. Run the server (in first terminal):
   ./vuln-cwe134-ex2

6. Open a second terminal and access the container:
   docker exec -it cwe134-container /bin/bash

7. Test the vulnerability:
   - Normal request:
     echo -e "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 8080
   
   - Format string attack to leak memory:
     echo -e "GET /%p%p%p%p%p HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 8080
   
   - Format string attack to leak admin flag:
     echo -e "GET /%x%x%x%x%x HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 8080
   
   - Format string attack to modify memory:
     echo -e "GET /%n%n%n%n%n HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 8080

Expected behavior:
- The program will show debug information with addresses
- The format string vulnerability will be visible in the log output
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