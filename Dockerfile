# Use Ubuntu 24.04 as base image
FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    wget \
    build-essential \
    curl \
    python3 \
    python3-pip \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/local/src

# Download and extract Nginx
RUN wget http://nginx.org/download/nginx-1.27.4.tar.gz \
    && tar -zxvf nginx-1.27.4.tar.gz \
    && rm nginx-1.27.4.tar.gz

# Copy our vulnerable source code
COPY src/os/unix/ngx_recv.c /usr/local/src/nginx-1.27.4/src/os/unix/

# Configure and build Nginx with security checks disabled
WORKDIR /usr/local/src/nginx-1.27.4
RUN ./configure --prefix=/usr/local/nginx \
    --with-http_ssl_module \
    --with-debug \
    --with-cc-opt='-g -O0 -w' \
    && make \
    && make install

# Create test HTML file
RUN echo "<html><body><h1>Nginx CWE-787 Test Server</h1></body></html>" > /usr/local/nginx/html/index.html

# Create necessary directories
RUN mkdir -p /usr/local/nginx/logs \
    && mkdir -p /usr/local/nginx/client_body_temp

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

# Copy test script
COPY cwe787test.py /usr/local/nginx/cwe787test.py
RUN chmod +x /usr/local/nginx/cwe787test.py

# Copy init script and fix line endings
COPY init.sh /init.sh
RUN dos2unix /init.sh && chmod +x /init.sh

# Expose ports
EXPOSE 80 443

# Start Nginx
CMD ["/init.sh"]