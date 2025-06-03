# Use Ubuntu 22.04 as base image to match the GitHub Actions environment
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/nginx/sbin:${PATH}"

# Install required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
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
# Extract Nginx source archive
RUN tar -xzvf nginx-1.27.4.tar.gz \
    && rm nginx-1.27.4.tar.gz \
    && mv nginx-1.27.4 nginx

# Copy vulnerable source code
COPY src/http/ngx_http_request.c nginx/src/http/

# Configure and build Nginx with custom flags
WORKDIR /usr/local/src/nginx
RUN CFLAGS="-Wno-error=format-security -Wno-format-security" ./configure --with-debug --prefix=/usr/local/nginx \
    && make -j$(nproc) \
    && make install

# Create test HTML file
RUN mkdir -p /usr/local/nginx/html
RUN echo "<html><body><h1>Nginx Format String Vulnerability Test</h1></body></html>" > /usr/local/nginx/html/index.html

# Create necessary directories for logs
RUN mkdir -p /usr/local/nginx/logs

# Copy configuration files
COPY conf/nginx.conf /usr/local/nginx/conf/nginx.conf
COPY conf/mime.types /usr/local/nginx/conf/mime.types

# Expose Nginx default port
EXPOSE 80

# Start Nginx and keep the container running
CMD ["/bin/bash", "-c", "/usr/local/nginx/sbin/nginx && tail -f /usr/local/nginx/logs/error.log"]


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
