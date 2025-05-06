FROM ubuntu:latest

# Install compiler, netcat, python and tools
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

# Start bash when the container runs
CMD ["/bin/bash"] 