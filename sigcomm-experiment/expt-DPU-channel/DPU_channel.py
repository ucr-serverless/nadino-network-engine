import socket
import subprocess
import argparse
import importlib
import time

retry = 3

result = []
# Server Code
def server(host, port, command_generator, parser):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server is listening on {host}:{port}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")

            for command in command_generator():
                # Start a subprocess in a new shell to run a command
                print(f"Server: Starting subprocess with command: {command}")
                process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


                # Notify the client that the subprocess started
                conn.sendall(b"STARTED")
                data = conn.recv(1024)
                if data.decode() == "ERR":
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                else:
                    stdout, _ = process.communicate()
                    print(stdout)
                    if stdout:
                        for i in stdout:
                            if k := parser(i):
                                result.append(k)



                # Wait for the client to start its subprocess
                # data = conn.recv(1024)
                # if data.decode() == "STARTED":
                #     print("Server: Client subprocess started.")

            conn.sendall(b"TERMINATE")
            print("Server: Sent terminate signal. Exiting...")

# Client Code
def client(host, port, command_generator, parser):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Client connected to the server at {host}:{port}.")
        gen = command_generator()
        while(True):
            data = client_socket.recv(1024)
            if data.decode() == "STARTED":
                command = next(gen)
                print("Client: Server subprocess started.")

                # Start a subprocess in a new shell to run a command
                print(f"Client: Starting subprocess with command: {command}")
                process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, _ = process.communicate()

                # retry
                if process.returncode != 0:
                    time.sleep(3)
                    process = subprocess.Popen(command.split())
                    stdout, _ = process.communicate()

                if process.returncode != 0:
                    client_socket.sendall(b"ERR")
                    continue
                print(stdout)
                if stdout:
                    for i in stdout:
                        if k := parser(i):
                            result.append(k)
                client_socket.sendall(b"SUCC")

                continue

                # Notify the server
            elif data.decode() == "TERMINATE":
                print("Client: Received terminate signal. Exiting...")
                break


# Main Execution Entry Point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run as server or client with specified IP and port.")
    parser.add_argument("-H", "--host", help="IP address to bind or connect to.")
    parser.add_argument("-p", "--port", type=int, help="Port number to bind or connect to.")
    parser.add_argument("-c", "--command_module", help="Module name containing the command generator.")
    parser.add_argument("-P", "--local_pcie", type=str, help="The local DOCA PCIe address")
    parser.add_argument("-R", "--remote_pcie", type=str, help="The remote DOCA PCIe address(only DPU need this)")

    args = parser.parse_args()


    try:
        module = importlib.import_module(args.command_module)
    except (ImportError, AttributeError) as e:
        print(f"Error loading command generator from module '{args.command_module}': {e}")
        exit(1)
    parser = module.parse_log

    if args.remote_pcie:
        command_generator = module.server_command_generator(args.local_pcie, args.remote_pcie)
        if not command_generator:
            print("Failed to load command generator. Exiting.")
            exit(1)
        server("0.0.0.0", args.port, command_generator, parser)
    else:
        command_generator = module.client_command_generator(args.local_pcie)
        if not command_generator:
            print("Failed to load command generator. Exiting.")
            exit(1)
        client(args.host, args.port, command_generator, parser)
    module.aggregate(result)

