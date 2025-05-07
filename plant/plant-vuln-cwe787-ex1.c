#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#define PORT 8080
#define MAX_QUEUE_SIZE 100
#define MAX_MESSAGE_SIZE 10
#define MAX_PROCESSORS 5

typedef struct {
    char message[MAX_MESSAGE_SIZE];
    int priority;
    time_t timestamp;
} Message;

typedef struct {
    Message* messages[MAX_QUEUE_SIZE];
    int front;
    int rear;
    int size;
} MessageQueue;

// Global message queue
MessageQueue messageQueue = {0};

// Function to initialize message queue
void init_queue() {
    messageQueue.front = 0;
    messageQueue.rear = -1;
    messageQueue.size = 0;
}

// Function to add message to queue
void enqueue_message(Message* msg) {
    if (messageQueue.size >= MAX_QUEUE_SIZE) {
        printf("🚫 Queue Overflow: Maximum capacity reached!\n");
        return;
    }
    
    messageQueue.rear = (messageQueue.rear + 1) % MAX_QUEUE_SIZE;
    messageQueue.messages[messageQueue.rear] = msg;
    messageQueue.size++;
}

// Function to process messages
void process_messages() {
    while (messageQueue.size > 0) {
        Message* msg = messageQueue.messages[messageQueue.front];
        messageQueue.front = (messageQueue.front + 1) % MAX_QUEUE_SIZE;
        messageQueue.size--;
        
        printf("📨 Processing Message:\n");
        printf("   Content: %s\n", msg->message);
        printf("   Priority: %d\n", msg->priority);
        printf("   Timestamp: %ld\n", msg->timestamp);
        printf("   Status: ✅ Processed\n\n");
        
        free(msg);
    }
}

// Function to handle client connection
void handle_client(int socket_fd) {
    Message* new_msg = malloc(sizeof(Message));
    if (!new_msg) {
        printf("💥 Memory Allocation Failed!\n");
        return;
    }
    
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        printf("⏰ Socket Timeout Configuration Failed!\n");
        free(new_msg);
        return;
    }
    
    // Receive message size
    int msg_size;
    ssize_t bytes_read = recv(socket_fd, &msg_size, sizeof(msg_size), 0);
    
    if (bytes_read <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("⌛ Connection Timeout: No data received\n");
        } else {
            printf("❌ Connection Error: %s\n", strerror(errno));
        }
        free(new_msg);
        return;
    }
    
    printf("\n📥 New Message Received:\n");
    printf("   Size: %d bytes\n", msg_size);
    
    // VULNERABILITY: Out-of-bounds write - no size validation
    // Copy message data without bounds checking
    char temp_buffer[msg_size];  // VULNERABILITY: Variable length array
    memset(temp_buffer, 'A', msg_size);
    strncpy(new_msg->message, temp_buffer, msg_size);  // VULNERABILITY: No bounds check
    
    new_msg->priority = msg_size % 5;  // Simple priority based on size
    new_msg->timestamp = time(NULL);
    
    printf("   Content: %s\n", new_msg->message);
    printf("   Priority Level: %d\n", new_msg->priority);
    printf("   Queue Status: %d/%d messages\n", messageQueue.size + 1, MAX_QUEUE_SIZE);
    
    enqueue_message(new_msg);
    
    // Send acknowledgment
    const char* ack = "Message queued successfully\n";
    send(socket_fd, ack, strlen(ack), 0);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    printf("\n🚀 Message Processing System v1.0\n");
    printf("================================\n");
    printf("Initializing system components...\n");
    
    init_queue();
    
    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("💥 System Error: Socket creation failed\n");
        return 1;
    }
    
    /* Set socket options */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        printf("💥 System Error: Socket configuration failed\n");
        exit(EXIT_FAILURE);
    }
    
    /* Configure server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    /* Bind socket */
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("💥 System Error: Port binding failed\n");
        close(server_fd);
        return 1;
    }
    
    /* Listen for connections */
    if (listen(server_fd, MAX_PROCESSORS) < 0) {
        printf("💥 System Error: Server initialization failed\n");
        close(server_fd);
        return 1;
    }
    
    printf("\n✅ System Ready\n");
    printf("==============\n");
    printf("\n📝 Test Commands:\n");
    printf("1. Small Message: echo -e \"\\x05\\x00\\x00\\x00\" | nc localhost 8080\n");
    printf("2. Medium Message: echo -e \"\\x0f\\x00\\x00\\x00\" | nc localhost 8080\n");
    printf("3. Large Message: echo -e \"\\x1f\\x00\\x00\\x00\" | nc localhost 8080\n");
    printf("\n👂 Listening for incoming messages...\n");
    
    while(1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            printf("❌ Connection Error: Accept failed\n");
            continue;
        }
        
        printf("\n🔌 New Connection: %s\n", inet_ntoa(client_addr.sin_addr));
        handle_client(client_fd);
        close(client_fd);
        
        // Process messages after each client
        process_messages();
    }
    
    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe787-ex1 plant-vuln-cwe787-ex1.c
2. Run: ./vuln-cwe787-ex1
3. In another terminal, test with:

   # Tests that cause buffer overflow:
   # Test 1: Normal key with very large value
   (echo -n "key1"; echo -e "\x64\x00\x00\x00") | nc localhost 8080

   # Test 2: Very long key with normal value
   (echo -n "key12345678901234567890"; echo -e "\x05\x00\x00\x00") | nc localhost 8080

   # Test 3: Very large key and value
   (echo -n "key12345678901234567890"; echo -e "\x64\x00\x00\x00") | nc localhost 8080

   # Test 4: Maximum possible value
   (echo -n "key1"; echo -e "\xff\xff\xff\xff") | nc localhost 8080

   # Test 5: Negative value
   (echo -n "key1"; echo -e "\xff\xff\xff\xff") | nc localhost 8080

   # Test 6: Sequence of malicious requests
   (echo -n "key1"; echo -e "\x14\x00\x00\x00") | nc localhost 8080
   (echo -n "key1"; echo -e "\x28\x00\x00\x00") | nc localhost 8080
   (echo -n "key1"; echo -e "\x64\x00\x00\x00") | nc localhost 8080

   # Additional tests that cause segmentation fault:
   # Test 7: Very large size (100 bytes)
   echo -e "\x64\x00\x00\x00" | nc localhost 8080

   # Test 8: Maximum possible size (2^32-1)
   echo -e "\xff\xff\xff\xff" | nc localhost 8080

   # Test 9: Negative size
   echo -e "\xff\xff\xff\xff" | nc localhost 8080

   # Test 10: Zero size
   echo -e "\x00\x00\x00\x00" | nc localhost 8080

   # Test 11: Size that exceeds stack (1MB)
   echo -e "\x00\x10\x00\x00" | nc localhost 8080

   # Additional crash tests:
   # Test 12: Large size (1MB)
   echo -e "\x00\x00\x10\x00" | nc localhost 8080

   # Test 13: Very large size (16MB)
   echo -e "\x00\x00\x00\x10" | nc localhost 8080

   # Test 14: Maximum possible size (4GB)
   echo -e "\xff\xff\xff\xff" | nc localhost 8080

Expected behavior:
- The system will receive message sizes
- Messages will be queued for processing
- Buffer overflow is possible when message size is larger than MAX_MESSAGE_SIZE
- You can observe memory corruption in action
- Some tests will cause segmentation fault
- The program will crash when trying to allocate very large buffers

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Buffer overflow
- Memory corruption
- Program crashes
- Potential code execution
*/ 