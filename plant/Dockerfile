FROM ubuntu:latest

# Install compiler, netcat, and tools
RUN apt update && apt install -y \
    build-essential \
    netcat-openbsd \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy local files into container
COPY . /app

# Start bash when the container runs
CMD ["/bin/bash"] 