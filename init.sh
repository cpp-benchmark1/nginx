#!/bin/bash

echo "Starting initialization..."

# Check if nginx binary exists
if [ ! -f /usr/local/nginx/sbin/nginx ]; then
    echo "Error: nginx binary not found!"
    exit 1
fi

# Check if nginx.conf exists
if [ ! -f /usr/local/nginx/conf/nginx.conf ]; then
    echo "Error: nginx.conf not found!"
    exit 1
fi

# Create necessary directories
mkdir -p /usr/local/nginx/logs
mkdir -p /usr/local/nginx/html

# Test nginx configuration
echo "Testing nginx configuration..."
/usr/local/nginx/sbin/nginx -t

# Start nginx in foreground mode with debug output
echo "Starting nginx..."
exec /usr/local/nginx/sbin/nginx -g 'daemon off;' -e /dev/stderr

# Keep container running
tail -f /usr/local/nginx/logs/error.log
