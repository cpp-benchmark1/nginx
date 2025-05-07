#!/bin/bash

# Start Nginx in foreground mode
exec /usr/local/nginx/sbin/nginx -g 'daemon off;' 