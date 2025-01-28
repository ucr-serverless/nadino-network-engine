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
        "test": 20,
    }
    json_string = json.dumps(data)
    json_bytes = json_string.encode('ascii')

    # Length of JSON string
    json_length = len(json_bytes)

    # Create a socket and connect to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))
    
    print(json_length)

    while(True):
        pass
    # Send length as uint32_t (4 bytes)
    sock.send(struct.pack('!I', 10000))
    
    sock.close()

if __name__ == "__main__":
    send_json()

