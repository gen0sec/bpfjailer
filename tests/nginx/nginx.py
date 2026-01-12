#!/usr/bin/env python3
import socket, json, os, sys

NGINX_BIN = os.environ.get("NGINX_BIN", "/usr/sbin/nginx")

# Get config file from args
config_file = sys.argv[1] if len(sys.argv) > 1 else None
role_id = int(sys.argv[2]) if len(sys.argv) > 2 else 3

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/bpfjailer/enrollment.sock")

# Enroll with specified role (default: webserver role ID 3)
request = {"Enroll": {"pod_id": 1, "role_id": role_id}}
sock.send((json.dumps(request) + "\n").encode())
response = sock.recv(4096).decode()
sock.close()
print(f"Enrollment: {response}")

# Build nginx args
args = ["nginx", "-g", "daemon off;"]
if config_file:
    args = ["nginx", "-c", config_file, "-g", "daemon off;"]

os.execv(NGINX_BIN, args)
