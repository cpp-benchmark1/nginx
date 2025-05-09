FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    wget \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/local/src

# Download and extract Nginx
RUN wget http://nginx.org/download/nginx-1.27.4.tar.gz \
    && tar -xzvf nginx-1.27.4.tar.gz \
    && rm nginx-1.27.4.tar.gz \
    && mv nginx-1.27.4 nginx

# Copy vulnerable source code
COPY src/http/ngx_http_request.c nginx/src/http/

# Configure and build Nginx
WORKDIR /usr/local/src/nginx
RUN CFLAGS="-Wno-error=format-security -Wno-format-security" ./configure --with-debug --prefix=/usr/local/nginx \
    && make -j$(nproc) \
    && make install

# Create test HTML file
RUN mkdir -p /usr/local/nginx/html
RUN echo "<html><body><h1>Nginx Format String Vulnerability Test</h1></body></html>" > /usr/local/nginx/html/index.html

# Create necessary directories
RUN mkdir -p /usr/local/nginx/logs

# Copy nginx.conf
COPY conf/nginx.conf /usr/local/nginx/conf/nginx.conf

# Copy mime.types
COPY conf/mime.types /usr/local/nginx/conf/mime.types

# Expose port 80
EXPOSE 80

# Start Nginx and tail logs
CMD ["/bin/bash", "-c", "/usr/local/nginx/sbin/nginx && tail -f /usr/local/nginx/logs/error.log"]