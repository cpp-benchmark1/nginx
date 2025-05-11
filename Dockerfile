# Use Ubuntu 22.04 as base image to match the GitHub Actions environment
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/nginx/sbin:${PATH}"

# Install required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/local/src

# Download and extract Nginx
RUN wget http://nginx.org/download/nginx-1.27.4.tar.gz \
    && tar -xzvf nginx-1.27.4.tar.gz \
    && rm nginx-1.27.4.tar.gz

# Copy our vulnerable source code
COPY src/os/unix/ngx_recv.c /usr/local/src/nginx-1.27.4/src/os/unix/

# Configure and build Nginx with debug flags and security checks disabled
WORKDIR /usr/local/src/nginx-1.27.4
RUN ./configure --prefix=/usr/local/nginx \
    --with-http_ssl_module \
    --with-debug \
    --with-cc-opt='-g -O0 -Wno-error -fno-stack-protector -D_FORTIFY_SOURCE=0' \
    && make \
    && make install \
    && chmod +x /usr/local/nginx/sbin/nginx

# Create test HTML file
RUN echo "<html><body><h1>Nginx CWE-122 Test Server</h1></body></html>" > /usr/local/nginx/html/index.html

# Create necessary directories
RUN mkdir -p /usr/local/nginx/logs \
    && touch /usr/local/nginx/logs/error.log \
    && touch /usr/local/nginx/logs/access.log \
    && chmod 777 /usr/local/nginx/logs/error.log \
    && chmod 777 /usr/local/nginx/logs/access.log

# Copy our custom nginx.conf
COPY conf/nginx.conf /usr/local/nginx/conf/nginx.conf

# Create mime.types
RUN echo 'types {\n\
    text/html                             html htm shtml;\n\
    text/css                              css;\n\
    text/xml                              xml;\n\
    image/gif                             gif;\n\
    image/jpeg                            jpeg jpg;\n\
    application/javascript                 js;\n\
}' > /usr/local/nginx/conf/mime.types

# Copy init script
COPY init.sh /init.sh
RUN chmod +x /init.sh

# Create test script
RUN echo '#!/bin/bash\n\
echo "Creating test file..."\n\
dd if=/dev/urandom of=/tmp/large_file bs=1M count=2\n\
echo "Sending request..."\n\
curl -X POST -H "Content-Type: application/octet-stream" --data-binary @/tmp/large_file http://localhost/\n\
echo "Done!"' > /test.sh \
    && chmod +x /test.sh

# Verify Nginx installation and permissions
RUN ls -l /usr/local/nginx/sbin/nginx && \
    /usr/local/nginx/sbin/nginx -v

# Expose ports
EXPOSE 80 443

# Start Nginx
CMD ["/init.sh"]