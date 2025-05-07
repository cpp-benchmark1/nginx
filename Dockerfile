# Use Ubuntu 24.04 as base image to match the GitHub Actions environment
FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libpcre3-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /nginx

# Copy the nginx source code
COPY . .

# Configure and build nginx (following the GitHub Actions workflow)
RUN auto/configure && make

# Create all necessary directories
RUN mkdir -p /usr/local/nginx/conf \
    /usr/local/nginx/html \
    /usr/local/nginx/logs \
    /usr/local/nginx/sbin \
    /var/log/nginx

# Copy nginx binary to the correct location
RUN cp objs/nginx /usr/local/nginx/sbin/nginx

# Create configuration files
RUN echo 'worker_processes  1;\n\
events {\n\
    worker_connections  1024;\n\
}\n\
http {\n\
    include       mime.types;\n\
    default_type  application/octet-stream;\n\
    sendfile        on;\n\
    keepalive_timeout  65;\n\
    server {\n\
        listen       80;\n\
        server_name  localhost;\n\
        location / {\n\
            root   html;\n\
            index  index.html index.htm;\n\
        }\n\
        error_page   500 502 503 504  /50x.html;\n\
        location = /50x.html {\n\
            root   html;\n\
        }\n\
    }\n\
}' > /usr/local/nginx/conf/nginx.conf

# Create mime.types
RUN echo 'types {\n\
    text/html                             html htm shtml;\n\
    text/css                              css;\n\
    text/xml                              xml;\n\
    image/gif                             gif;\n\
    image/jpeg                            jpeg jpg;\n\
    application/javascript                 js;\n\
}' > /usr/local/nginx/conf/mime.types

# Create a basic index.html
RUN echo '<html><body><h1>Nginx Vulnerable Server</h1></body></html>' > /usr/local/nginx/html/index.html

# Create test file
RUN dd if=/dev/zero of=/usr/local/nginx/html/test_file bs=1M count=2

# Copy and set up initialization script
COPY init.sh /init.sh
RUN chmod +x /init.sh

# Expose ports
EXPOSE 80 443

# Set the entrypoint
ENTRYPOINT ["/init.sh"] 