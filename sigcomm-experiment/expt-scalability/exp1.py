import argparse
import time
import glob
import json
import subprocess

command = "taskset -c {} ib_send_bw -F --rate_limit=100 --out_json -D 10 --out_json_file=perftest_bw_{}_{}_{}.json -d mlx5_0 -i 1 -x 3 --disable_pcie_relaxed -s 1024 -l 128 --recv_post_list 128 -q {} --burst_size 16 -p 1000{} --mr_per_qp {} "

def create_tmux_session(session_name, n_core, n_qp, n_mr_per_qp, server_ip):
    # kill old session
    subprocess.run(["tmux", "kill-session", "-t", session_name], check=False)
    # Create a new tmux session

    subprocess.run(["tmux", "new-session", "-d", "-s", session_name], check=True)

    # Split the tmux session into panes
    for i in range(0, n_core+1):
        subprocess.run(["tmux", "split-window", "-t", session_name, "-h"], check=True)
        subprocess.run(["tmux", "select-layout", "-t", session_name, "tiled"], check=True)

    # Run commands in each pane
    for i in range(0, n_core):
        pane_command = command.format(i, n_core, n_qp, i, n_qp, i, n_mr_per_qp)
        if server_ip:
            pane_command += f" {server_ip}"
        subprocess.run(["tmux", "send-keys", "-t", f"{session_name}.{i+1}", pane_command, "C-m"], check=True)

    # # Attach to the session
    # subprocess.run(["tmux", "attach-session", "-t", session_name])
def aggregate(n_core, n_qp):
    # Find all files matching the pattern "perftest_{number}.json" in the current directory
    json_files = glob.glob(f"perftest_bw_{n_core}_{n_qp}_*.json")
    print(json_files)


    bw_result = 0.0
    msg_result = 0.0
    for file_path in json_files:
        try:
            with open(file_path, "r") as f:
                content = json.load(f)
                bw_result += content["results"]["BW_average"]
                msg_result += content["results"]["MsgRate"]
        except (json.JSONDecodeError, OSError) as e:
            print(f"error read {file_path}: {e}")
    return (bw_result, msg_result)


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Create a tmux session with multiple panes.")
    parser.add_argument("--n_core", type=int, help="Number of processes to run.")
    parser.add_argument("--n_qp", type=int, help="Command to run in each tmux pane.")
    parser.add_argument("--server_ip", default="", help="Optional IP address of the server.")
    parser.add_argument("--n_mr_per_qp", type=int, help="Number of MR per QP")
    args = parser.parse_args()

    # Validate inputs
    if args.n_core <= 0:
        print("Error: num_core must be a positive integer.")
        return


    # Create tmux session

    session_name = "exp1"
    is_client = False
    if args.server_ip:
        is_client = True
    create_tmux_session(session_name, args.n_core, args.n_qp, args.n_mr_per_qp, args.server_ip)

    if is_client:
        time.sleep(15)
        result = aggregate(args.n_core, args.n_qp)
        print(f"aggregated throuput of {args.n_core * args.n_qp} QPs with {args.n_mr_per_qp} MRs is {result[0]} MiB/s, the msg rate is {result[1]} Mpps")


if __name__ == "__main__":
    main()

