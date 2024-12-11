import argparse
import subprocess

command = "taskset -c {} ib_send_bw -F --out_json -D 10 --out_json_file=perftest_bw_{}_{}_{}.json -d mlx5_2 -i 1 -x 3 --disable_pcie_relaxed -s 1 -q {} -p 1000{}"

def create_tmux_session(session_name, n_core, n_qp, server_ip):
    # Create a new tmux session
    subprocess.run(["tmux", "new-session", "-d", "-s", session_name], check=True)

    # Split the tmux session into panes
    for i in range(0, n_core+1):
        subprocess.run(["tmux", "split-window", "-t", session_name, "-h"], check=True)
        subprocess.run(["tmux", "select-layout", "-t", session_name, "tiled"], check=True)

    # Run commands in each pane
    for i in range(0, n_core+1):
        pane_command = command.format(i, n_core, n_qp, i, n_qp, i)
        if server_ip:
            pane_command += server_ip
        subprocess.run(["tmux", "send-keys", "-t", f"{session_name}.{i+1}", pane_command, "C-m"], check=True)

    # # Attach to the session
    # subprocess.run(["tmux", "attach-session", "-t", session_name])


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Create a tmux session with multiple panes.")
    parser.add_argument("--n_core", type=int, help="Number of processes to run.")
    parser.add_argument("--n_qp", type=int, help="Command to run in each tmux pane.")
    parser.add_argument("--server_ip", default="", help="Optional IP address of the server.")
    args = parser.parse_args()

    breakpoint()
    # Validate inputs
    if args.n_core <= 0:
        print("Error: num_core must be a positive integer.")
        return


    # Create tmux session
    session_name = "exp1"
    create_tmux_session(session_name, args.n_core, args.n_qp, args.server_ip)


if __name__ == "__main__":
    main()

