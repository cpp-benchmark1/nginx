#!/bin/bash

# Build the Docker image
echo "[*] Building Docker image..."
docker build -t nginx-vuln .

# Run the container
echo "[*] Starting Nginx container..."
docker run -d --name nginx-vuln -p 80:80 nginx-vuln

# Wait for Nginx to start
echo "[*] Waiting for Nginx to start..."
sleep 5

# Make the Python scripts executable
chmod +x heap_overflow_get.py heap_overflow_post.py

# Test first CWE-122 example (GET)
echo -e "\n[*] Testing first CWE-122 example (GET)..."
./heap_overflow_get.py

# Check for core dumps
echo -e "\n[*] Checking for core dumps after first test..."
docker exec nginx-vuln ls -l /var/cache/nginx/core*

# Show Nginx logs
echo -e "\n[*] Nginx logs after first test:"
docker logs nginx-vuln

# Restart Nginx for second test
echo -e "\n[*] Restarting Nginx for second test..."
docker restart nginx-vuln
sleep 5

# Test second CWE-122 example (POST)
echo -e "\n[*] Testing second CWE-122 example (POST)..."
./heap_overflow_post.py

# Check for core dumps
echo -e "\n[*] Checking for core dumps after second test..."
docker exec nginx-vuln ls -l /var/cache/nginx/core*

# Show Nginx logs
echo -e "\n[*] Nginx logs after second test:"
docker logs nginx-vuln

# Cleanup
echo -e "\n[*] Cleaning up..."
docker stop nginx-vuln
docker rm nginx-vuln 