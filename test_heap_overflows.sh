#!/bin/bash

# Build the Docker image
echo "[*] Building Docker image..."
docker build -t nginx-vuln .

# Run the container
echo "[*] Starting Nginx container..."
docker run -d --name nginx-vuln -p 80:80 nginx-vuln

echo "[*] Waiting for Nginx to start..."
sleep 5

# Make the Python scripts executable
chmod +x heap_overflow_example1.py heap_overflow_example2.py

# Test first CWE-122 example (GET)
echo -e "\n[*] Testing first CWE-122 example (GET)..."
./heap_overflow_example1.py

# Check for core dumps
echo -e "\n[*] Checking for core dumps after first test..."
docker exec nginx-vuln ls -l /var/cache/nginx/core*

# Show Nginx logs
echo -e "\n[*] Nginx logs after first test:"
docker logs nginx-vuln

# Cleanup first container
echo -e "\n[*] Cleaning up first container..."
docker stop nginx-vuln
docker rm nginx-vuln

# Rebuild and run container for second test
echo -e "\n[*] Rebuilding and starting container for second test..."
docker build -t nginx-vuln .
docker run -d --name nginx-vuln -p 80:80 nginx-vuln
sleep 5

# Test second CWE-122 example (GET)
echo -e "\n[*] Testing second CWE-122 example (GET)..."
./heap_overflow_example2.py

# Check for core dumps
echo -e "\n[*] Checking for core dumps after second test..."
docker exec nginx-vuln ls -l /var/cache/nginx/core*

# Show Nginx logs
echo -e "\n[*] Nginx logs after second test:"
docker logs nginx-vuln

# Final cleanup
echo -e "\n[*] Final cleanup..."
docker stop nginx-vuln
docker rm nginx-vuln 