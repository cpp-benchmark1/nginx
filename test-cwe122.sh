#!/bin/bash

# Build the Docker image
docker stop nginx-vuln && docker rm nginx-vuln
echo "[*] Building Docker image..."
docker build -t nginx-vuln .

# Run the container
echo "[*] Starting Nginx container..."
docker run -d --name nginx-vuln -p 80:80 nginx-vuln

# Wait for Nginx to start
echo "[*] Waiting for Nginx to start..."
sleep 5

# Make the Python script executable
chmod +x test-cwe122.py

# Run the exploit
echo "[*] Running exploit..."
./test-cwe122.py

# Check for core dumps
echo "[*] Checking for core dumps..."
docker exec nginx-vuln ls -l /var/cache/nginx/core*

# Show Nginx logs
echo "[*] Nginx logs:"
docker logs nginx-vuln

# Cleanup
#echo "[*] Cleaning up..."
#docker stop nginx-vuln
#docker rm nginx-vuln 