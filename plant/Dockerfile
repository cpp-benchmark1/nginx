FROM ubuntu:latest

# Install compiler, netcat, Python, and tools
RUN apt update && apt install -y \
    build-essential \
    netcat-openbsd \
    python3 \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy local files into container
COPY . /app

# Create log directory and set permissions
RUN mkdir -p /var/log && \
    touch /var/log/buffer_server.log && \
    chmod 666 /var/log/buffer_server.log

# Start bash when the container runs
CMD ["/bin/bash"] 