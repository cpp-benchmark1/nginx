#!/bin/bash

# Start Nginx
/usr/local/nginx/sbin/nginx

# Keep container running
tail -f /usr/local/nginx/logs/error.log