# test_attack.py
import socket
import time

target = "google.com"
port = 80

print("Simulating rapid connections...")
for i in range(50):
    try:
        s = socket.socket()
        s.settimeout(0.1)
        s.connect((target, port))
        s.close()
        print(f"Connection {i+1}")
        time.sleep(0.05)  # Very fast connections
    except:
        pass