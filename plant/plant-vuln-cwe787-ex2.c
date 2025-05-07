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
#define MAX_CACHE_SIZE 100
#define MAX_KEY_SIZE 10
#define MAX_VALUE_SIZE 10
#define MAX_ENTRIES 50

typedef struct {
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
    time_t last_access;
    int hits;
} CacheEntry;

typedef struct {
    CacheEntry* entries[MAX_ENTRIES];
    int size;
    int capacity;
} Cache;

// Global cache
Cache cache = {0};

// Function to initialize cache
void init_cache() {
    cache.size = 0;
    cache.capacity = MAX_ENTRIES;
    printf("💾 Cache initialized with capacity: %d entries\n", MAX_ENTRIES);
}

// Function to find cache entry
CacheEntry* find_entry(const char* key) {
    for (int i = 0; i < cache.size; i++) {
        if (strcmp(cache.entries[i]->key, key) == 0) {
            cache.entries[i]->hits++;
            cache.entries[i]->last_access = time(NULL);
            return cache.entries[i];
        }
    }
    return NULL;
}

// Function to add cache entry
void add_entry(const char* key, const char* value) {
    if (cache.size >= cache.capacity) {
        printf("🚫 Cache Storage Full: Maximum entries reached!\n");
        return;
    }
    
    CacheEntry* new_entry = malloc(sizeof(CacheEntry));
    if (!new_entry) {
        printf("💥 Memory Allocation Failed!\n");
        return;
    }
    
    strncpy(new_entry->key, key, MAX_KEY_SIZE);
    strncpy(new_entry->value, value, MAX_VALUE_SIZE);
    new_entry->last_access = time(NULL);
    new_entry->hits = 0;
    
    cache.entries[cache.size++] = new_entry;
    printf("✅ New entry added to cache\n");
}

// Function to handle client request
void handle_request(int socket_fd) {
    char buffer[1024] = {0};  // Buffer to receive all data
    // SOURCE: Vulnerable to buffer overflow - receiving untrusted input from socket
    ssize_t bytes_read = recv(socket_fd, buffer, sizeof(buffer), 0);
    if (bytes_read <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("⌛ Connection Timeout: No data received\n");
        } else {
            printf("❌ Connection Error: %s\n", strerror(errno));
        }
        return;
    }
    
    // Extract key and value size
    char key[MAX_KEY_SIZE] = {0};
    int value_size;
    
    // Copy key (first 4 bytes)
    strncpy(key, buffer, 4);
    key[4] = '\0';
    
    // Get value size (next 4 bytes)
    memcpy(&value_size, buffer + 4, sizeof(int));
    
    printf("\n🔍 Cache Request:\n");
    printf("   Key: %s\n", key);
    printf("   Value Size: %d bytes\n", value_size);
    printf("   Raw Buffer: ");
    for(int i = 0; i < bytes_read; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");
    
    // Check if key exists in cache
    CacheEntry* entry = find_entry(key);
    if (entry) {
        printf("   Status: Cache Hit! 🎯\n");
        printf("   Value: %s\n", entry->value);
        printf("   Hit Count: %d\n", entry->hits);
        printf("   Last Access: %ld\n", entry->last_access);
        send(socket_fd, entry->value, strlen(entry->value), 0);
        return;
    }
    
    printf("   Status: Cache Miss! ❌\n");
    
    // SINK: Vulnerable to buffer overflow - no size validation before allocation
    char temp_value[value_size];  // VULNERABILITY: Variable length array
    memset(temp_value, 'B', value_size);
    
    // VULNERABILITY: Copy value without bounds checking
    char new_value[MAX_VALUE_SIZE];
    strncpy(new_value, temp_value, value_size);  // VULNERABILITY: No bounds check
    
    printf("   Action: Adding new entry to cache\n");
    add_entry(key, new_value);
    
    // Send acknowledgment
    const char* ack = "Entry added to cache\n";
    send(socket_fd, ack, strlen(ack), 0);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    printf("\n🏪 Data Cache System v1.0\n");
    printf("========================\n");
    printf("Initializing cache system...\n");
    
    init_cache();
    
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
    if (listen(server_fd, 3) < 0) {
        printf("💥 System Error: Server initialization failed\n");
        close(server_fd);
        return 1;
    }
    
    printf("\n✅ Cache System Ready\n");
    printf("===================\n");
    printf("\n📝 Test Commands:\n");
    printf("1. First Request: printf \"key1\\x05\\x00\\x00\\x00\" | nc localhost 8080\n");
    printf("2. Second Request: printf \"key1\\x14\\x00\\x00\\x00\" | nc localhost 8080\n");
    printf("3. Third Request: printf \"key2\\x28\\x00\\x00\\x00\" | nc localhost 8080\n");
    printf("\n👂 Listening for cache requests...\n");
    
    while(1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            printf("❌ Connection Error: Accept failed\n");
            continue;
        }
        
        printf("\n🔌 New Connection: %s\n", inet_ntoa(client_addr.sin_addr));
        handle_request(client_fd);
        close(client_fd);
    }
    
    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe787-ex2 plant-vuln-cwe787-ex2.c
2. Run: ./vuln-cwe787-ex2
3. In another terminal, test with:

   # Tests that cause buffer overflow:
   # Test 1: Normal request (should work)
   printf "key1\x05\x00\x00\x00" | nc localhost 8080

   # Test 2: Request with larger value (should cause overflow)
   printf "key1\x14\x00\x00\x00" | nc localhost 8080

   # Test 3: Request with much larger value (should cause crash)
   printf "key2\x28\x00\x00\x00" | nc localhost 8080

   # Test 4: Sequence of malicious requests
   printf "key1\x64\x00\x00\x00" | nc localhost 8080
   printf "key2\xff\xff\xff\xff" | nc localhost 8080
   printf "key3\x00\x10\x00\x00" | nc localhost 8080

   # Test 5: Program crash (10000 bytes)
   printf "key4\x10\x27\x00\x00" | nc localhost 8080

Expected behavior:
- The system will receive key-value pairs
- Values will be cached for future requests
- Buffer overflow is possible when value size is larger than MAX_VALUE_SIZE
- You can observe memory corruption in action
- The program will crash when trying to allocate a very large buffer (10000 bytes)

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Buffer overflow
- Memory corruption
- Program crashes
- Potential code execution
*/ 
