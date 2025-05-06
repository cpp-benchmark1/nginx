#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define LOG_FILE "/var/log/command_server.log"
#define PID_FILE "/var/run/command_server.pid"

// Global variables for signal handling
volatile sig_atomic_t running = 1;

// Function to handle signals
void signal_handler(int signum) {
    if (signum == SIGTERM || signum == SIGINT) {
        printf("\nReceived signal %d, shutting down...\n", signum);
        running = 0;
    }
}

// Function to write PID file
void write_pid_file() {
    FILE* pid_fp = fopen(PID_FILE, "w");
    if (pid_fp) {
        fprintf(pid_fp, "%d\n", getpid());
        fclose(pid_fp);
    }
}

// Function to log command execution
void log_command(const char* command, const char* client_ip, int status) {
    FILE* log_fp = fopen(LOG_FILE, "a");
    if (log_fp) {
        time_t now = time(NULL);
        char timestamp[26];
        ctime_r(&now, timestamp);
        timestamp[24] = '\0';  // Remove newline
        
        fprintf(log_fp, "[%s] Client: %s | Command: %s | Status: %d\n",
                timestamp, client_ip, command, status);
        fclose(log_fp);
    }
}

// Function to validate command (simplified for demonstration)
int is_allowed_command(const char* command) {
    // In a real system, this would have proper validation
    // For demonstration, we'll just check if it's not empty
    return strlen(command) > 0;
}

// Function to handle command execution
void handle_command(int socket_fd, const char* client_ip) {
    char buffer[BUFFER_SIZE] = {0};
    char response[BUFFER_SIZE] = {0};
    int command_status = 0;
    
    printf("\n=== New Command Request ===\n");
    printf("Client IP: %s\n", client_ip);
    fflush(stdout);
    
    // SOURCE: Vulnerable to command injection - receiving untrusted input from socket using read
    printf("Waiting for command...\n");
    fflush(stdout);
    
    ssize_t bytes_read = read(socket_fd, buffer, BUFFER_SIZE - 1);
    
    if (bytes_read <= 0) {
        printf("Failed to read command: %s\n", strerror(errno));
        log_command("ERROR", client_ip, -1);
        return;
    }
    
    buffer[bytes_read] = '\0';  // Null terminate
    
    printf("Received %zd bytes\n", bytes_read);
    printf("Raw received data: %s\n", buffer);
    fflush(stdout);
    
    // Basic command validation (simplified)
    if (!is_allowed_command(buffer)) {
        printf("Invalid command format\n");
        strcpy(response, "Error: Invalid command format\n");
        write(socket_fd, response, strlen(response));
        log_command(buffer, client_ip, -1);
        return;
    }
    
    // SINK: Vulnerable to command injection - no input validation before execution
    char exec_command[BUFFER_SIZE];
    snprintf(exec_command, sizeof(exec_command), "echo 'Executing: %s' && %s", buffer, buffer);
    printf("Executing command: %s\n", exec_command);
    fflush(stdout);
    
    /* Execute the command */
    FILE* fp = popen(exec_command, "r");
    if (fp == NULL) {
        printf("Failed to execute command\n");
        fflush(stdout);
        strcpy(response, "Failed to execute command\n");
        write(socket_fd, response, strlen(response));
        log_command(buffer, client_ip, -1);
        return;
    }
    
    /* Read command output */
    char output[BUFFER_SIZE] = { 0 };
    size_t output_size = 0;
    char temp[BUFFER_SIZE];
    
    while (fgets(temp, sizeof(temp), fp) != NULL) {
        if (output_size + strlen(temp) < BUFFER_SIZE) {
            strcat(output, temp);
            output_size += strlen(temp);
        }
    }
    
    command_status = pclose(fp);
    
    printf("Command output:\n%s\n", output);
    printf("Command status: %d\n", command_status);
    fflush(stdout);
    
    /* Send response back to client */
    if (write(socket_fd, output, strlen(output)) < 0) {
        printf("Failed to send response: %s\n", strerror(errno));
        fflush(stdout);
    }
    
    // Log successful command execution
    log_command(buffer, client_ip, command_status);
    
    printf("=== Command Request Handled ===\n");
    fflush(stdout);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;
    char client_ip[INET_ADDRSTRLEN];

    // Set up signal handling
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Initialize syslog
    openlog("command_server", LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Command server starting");

    // Write PID file
    write_pid_file();

    printf("=== Starting Command Server ===\n");
    fflush(stdout);

    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        return 1;
    }
    printf("Socket created successfully\n");
    fflush(stdout);

    /* Set socket options */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        syslog(LOG_ERR, "setsockopt failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("Socket options set\n");
    fflush(stdout);

    /* Configure server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    /* Bind socket */
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
        close(server_fd);
        return 1;
    }
    printf("Socket bound to port %d\n", PORT);
    fflush(stdout);

    /* Listen for connections */
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
        close(server_fd);
        return 1;
    }
    printf("Server listening on port %d...\n", PORT);
    fflush(stdout);

    printf("\n=== Server Ready ===\n");
    printf("\nTo test:\n");
    printf("1. Normal command: echo \"ls -l\" | nc localhost 8080\n");
    printf("2. Command injection: echo \"ls -l; cat /etc/passwd\" | nc localhost 8080\n");
    printf("3. Command injection with &&: echo \"ls -l && cat /etc/shadow\" | nc localhost 8080\n");
    printf("4. Command injection with |: echo \"ls -l | cat /etc/passwd\" | nc localhost 8080\n");
    printf("\nWaiting for commands...\n");
    fflush(stdout);

    while(running) {
        /* Accept client connection */
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (running) {  // Only log if we're not shutting down
                perror("Accept failed");
                syslog(LOG_ERR, "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("Client connected: %s\n", client_ip);
        syslog(LOG_INFO, "Client connected: %s", client_ip);
        fflush(stdout);
        
        handle_command(client_fd, client_ip);
        close(client_fd);
    }

    // Cleanup
    printf("\nShutting down server...\n");
    unlink(PID_FILE);
    closelog();
    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe78-ex2 plant-vuln-cwe78-ex2.c
2. Run: ./vuln-cwe78-ex2
3. In another terminal, test with:
   - Normal command:
     echo "ls -l" | nc localhost 8080
   
   - Command injection with semicolon:
     echo "ls -l; cat /etc/passwd" | nc localhost 8080
   
   - Command injection with &&:
     echo "ls -l && cat /etc/shadow" | nc localhost 8080
   
   - Command injection with |:
     echo "ls -l | cat /etc/passwd" | nc localhost 8080

Expected behavior:
- The program will execute any command sent to it
- Command injection is possible using ;, &&, or |
- The server will show the command being executed
- The output will be sent back to the client

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Unauthorized command execution
- System compromise
- Data theft
- System damage
*/ 