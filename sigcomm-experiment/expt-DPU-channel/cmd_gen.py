import glob
import os
import json
import statistics
from functools import partial
sz_list = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]

repeat = 5
def construct_cmd(core_command, repeat):
    port = 10005
    commands = [
        "ib_send_bw {} --cpu_util --out_json --out_json_file=perftest_send_bw_{}_{}.json -s {} -p {}",
        "ib_write_bw {} --cpu_util --out_json --out_json_file=perftest_write_bw_{}_{}.json -s {} --write_with_imm -p {}",
        "ib_send_lat {} --cpu_util --out_json --out_json_file=perftest_send_lat_{}_{}.json -s {} -p {}",
        "ib_write_lat {} --cpu_util --out_json --out_json_file=perftest_write_lat_{}_{}.json -s {} --write_with_imm -p {}",
    ]
    for command in commands:
        for sz in sz_list:
            for i in range(repeat):
                port += 1
                yield command.format(core_command, sz, i, sz, port)

def server_command_generator(device_idx, ib_port, sgid_idx):
    core_command = f" -d mlx5_{device_idx} -x {sgid_idx} -i {ib_port} -D 10 "
    return partial(construct_cmd, core_command=core_command, repeat=repeat)

def client_command_generator(device_idx, ib_port, sgid_idx, address):
    core_command = f" -d mlx5_{device_idx} -x {sgid_idx} -i {ib_port} {address} -D 10 "
    return partial(construct_cmd, core_command=core_command, repeat=repeat)

def aggregate():
    send_re = {}
    write_re = {}
    send_json = glob.glob("perftest_send_*.json")
    write_json = glob.glob("perftest_write_*.json")
    cpu_sz = os.cpu_count()
    for sz in sz_list:
        send_re[sz] = {"lat": {"value": []}, "bw": {"value": []}, "cpu": {"value": []}, "msg_rate": {"value": []}}
        write_re[sz] = {"lat": {"value": []}, "bw": {"value": []}, "cpu": {"value": []}, "msg_rate": {"value": []}}


    for file_path in send_json:
        try:
            with open(file_path, "r") as f:
                content = json.load(f)
                re = content["results"]
                if "lat" in file_path:
                    send_re[re["MsgSize"]]["lat"]["value"].append(re["t_avg"])

                if "bw" in file_path:
                    send_re[re["MsgSize"]]["bw"]["value"].append(re["BW_average"])
                    send_re[re["MsgSize"]]["cpu"]["value"].append(re["CPU_util"])
                    send_re[re["MsgSize"]]["msg_rate"]["value"].append(re["MsgRate"])
        except (json.JSONDecodeError, OSError) as e:
            print(f"error read {file_path}: {e}")
    for file_path in write_json:
        try:
            with open(file_path, "r") as f:
                content = json.load(f)
                re = content["results"]
                if "lat" in file_path:
                    write_re[re["MsgSize"]]["lat"]["value"].append(re["t_avg"])
                if "bw" in file_path:
                    write_re[re["MsgSize"]]["bw"]["value"].append(re["BW_average"])
                    write_re[re["MsgSize"]]["cpu"]["value"].append(re["CPU_util"])
                    write_re[re["MsgSize"]]["msg_rate"]["value"].append(re["MsgRate"])
        except (json.JSONDecodeError, OSError) as e:
            print(f"error read {file_path}: {e}")

    for re in [send_re, write_re]:
        for sz in sz_list:
            for me in ["lat", "bw", "cpu", "msg_rate"]:
                re[sz][me]["mean"] = statistics.mean(re[sz][me]["value"])
                re[sz][me]["std"] = statistics.stdev(re[sz][me]["value"])
    with open("send.csv", "w") as f:
        f.write("msg_size,single_trip_lat_mean(usec),lat_std,throughput_mean(MB/s),thpt_std,CPU_mean(%),CPU_std,msg_rate_mean(Mpps),msg_rt_std,n_core\n")
        for sz, v in send_re.items():
            f.write(f"{sz},{v["lat"]["mean"]:.4f},{v["lat"]["std"]:.4f},{v["bw"]["mean"]:.4f},{v["bw"]["std"]:.4f},{v["cpu"]["mean"]:.4f},{v["cpu"]["std"]:.4f},{v["msg_rate"]["mean"]:.4f},{v["msg_rate"]["std"]:.4f},{cpu_sz}\n")

    with open("write.csv", "w") as f:
        f.write("msg_size,single_trip_lat_mean(usec),lat_std,throughput_mean(MB/s),thpt_std,CPU_mean(%),CPU_std,msg_rate_mean(Mpps),msg_rt_std,n_core\n")
        for sz, v in write_re.items():
            f.write(f"{sz},{v["lat"]["mean"]:.4f},{v["lat"]["std"]:.4f},{v["bw"]["mean"]:.4f},{v["bw"]["std"]:.4f},{v["cpu"]["mean"]:.4f},{v["cpu"]["std"]:.4f},{v["msg_rate"]["mean"]:.4f},{v["msg_rate"]["std"]:.4f},{cpu_sz}\n")


if __name__ == "__main__":
    for i in server_command_generator(2, 1, 3)():
        print(i)
    for i in client_command_generator(2, 1, 3, "10.10.1.1")():
        print(i)
    aggregate()





