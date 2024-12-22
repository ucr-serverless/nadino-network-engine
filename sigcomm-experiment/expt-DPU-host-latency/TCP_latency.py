import argparse
import subprocess
import statistics

command = "netperf -H {} -L {} -p {} -t TCP_RR -P 0 -- -r {},{}"

def run(server_ip, client_ip, server_port, msg_size):
    # Run commands in each pane
    run_cmd = command.format(server_ip, client_ip, server_port, msg_size, msg_size)
    results = []
    for i in range(5):
        result = subprocess.run(run_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        lines = result.stdout.split("\n")
        results.append(1e6/2/float(lines[0].strip().split(" ")[-1]))
    mean = statistics.mean(results)
    std = statistics.stdev(results)
    return mean, std

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="get RTT latency for TCP send-receive")
    parser.add_argument("-H", "--server_ip", type=str, help="IP address of the server.")
    parser.add_argument("-L", "--client_ip", type=str, help="IP address of the client.")
    parser.add_argument("-p", "--port", type=str, help="port of the server")
    args = parser.parse_args()

    msg_size = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
    with open("result.csv", "w") as f:
        f.write("msg_size,single_trip_mean,single_trip_std\n")
        for s in msg_size:
            mean, std = run(args.server_ip, args.client_ip, args.port, s)
            f.write(f"{s},{mean:.2f},{std:.2f}\n")



if __name__ == "__main__":
    main()

