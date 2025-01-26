import socket
import struct
import json

def send_json():
    # Server address
    SERVER_IP = '192.168.10.61'
    SERVER_PORT = 8091

    # JSON data
    data = {
        "msg_tp": 1,
        "msg_num": 1000,
    }
    json_string = json.dumps(data)
    json_bytes = json_string.encode('utf-8')

    # Length of JSON string
    json_length = len(json_bytes)

    # Create a socket and connect to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))
    
    # Send length as uint64_t (8 bytes)
    sock.sendall(struct.pack('!Q', json_length))
    
    # Send JSON string bytes
    sock.sendall(json_bytes)
    print("JSON sent to server.")

if __name__ == "__main__":
    send_json()

