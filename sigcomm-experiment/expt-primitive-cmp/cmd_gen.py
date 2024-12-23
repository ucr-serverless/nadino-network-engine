import glob
import os
import json
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
        send_re[sz] = {"lat": 0, "bw": 0, "cpu": 0, "msg_rate": 0, "lat_cnt": 0, "bw_cnt": 0}
        write_re[sz] = {"lat": 0, "bw": 0, "cpu": 0, "msg_rate": 0, "lat_cnt": 0, "bw_cnt": 0}


    for file_path in send_json:
        try:
            with open(file_path, "r") as f:
                content = json.load(f)
                re = content["results"]
                if "lat" in file_path:
                    send_re[re["MsgSize"]]["lat"] += re["t_avg"]
                    send_re[re["MsgSize"]]["lat_cnt"] += 1

                if "bw" in file_path:
                    send_re[re["MsgSize"]]["bw"] += re["BW_average"]
                    send_re[re["MsgSize"]]["cpu"] += re["CPU_util"]
                    send_re[re["MsgSize"]]["msg_rate"] += re["MsgRate"]
                    send_re[re["MsgSize"]]["bw_cnt"] += 1
        except (json.JSONDecodeError, OSError) as e:
            print(f"error read {file_path}: {e}")
    for file_path in write_json:
        try:
            with open(file_path, "r") as f:
                content = json.load(f)
                re = content["results"]
                if "lat" in file_path:
                    write_re[re["MsgSize"]]["lat"] += re["t_avg"]
                    write_re[re["MsgSize"]]["lat_cnt"] += 1
                if "bw" in file_path:
                    write_re[re["MsgSize"]]["bw"] += re["BW_average"]
                    write_re[re["MsgSize"]]["cpu"] += re["CPU_util"]
                    write_re[re["MsgSize"]]["msg_rate"] += re["MsgRate"]
                    write_re[re["MsgSize"]]["bw_cnt"] += 1
        except (json.JSONDecodeError, OSError) as e:
            print(f"error read {file_path}: {e}")

    for sz in sz_list:
        if send_re[sz]["lat_cnt"] != 0:
            send_re[sz]["lat"] /= send_re[sz]["lat_cnt"]
        if send_re[sz]["bw_cnt"] != 0:
            send_re[sz]["bw"] /= send_re[sz]["bw_cnt"]
            send_re[sz]["cpu"] /= send_re[sz]["bw_cnt"]
            send_re[sz]["msg_rate"] /= send_re[sz]["bw_cnt"]
        if write_re[sz]["lat_cnt"] != 0:
            write_re[sz]["lat"] /= write_re[sz]["lat_cnt"]
        if write_re[sz]["bw_cnt"] != 0:
            write_re[sz]["bw"] /= write_re[sz]["bw_cnt"]
            write_re[sz]["cpu"] /= write_re[sz]["bw_cnt"]
            write_re[sz]["msg_rate"] /= write_re[sz]["bw_cnt"]
    with open("send.csv", "w") as f:
        f.write("msg_size,single_trip_lat(usec),throughput(MB/s),CPU(%),n_core,msg_rate(Mpps)\n")
        for sz, v in send_re.items():
            f.write(f"{sz},{v["lat"]},{v["bw"]},{v["cpu"]},{cpu_sz},{v["msg_rate"]}\n")

    with open("write.csv", "w") as f:
        f.write("msg_size,single_trip_lat(usec),throughput(MB/s),CPU(%),n_core,msg_rate(Mpps)\n")
        for sz, v in write_re.items():
            f.write(f"{sz},{v["lat"]},{v["bw"]},{v["cpu"]},{cpu_sz},{v["msg_rate"]}\n")


if __name__ == "__main__":
    for i in server_command_generator(2, 1, 3)():
        print(i)
    for i in client_command_generator(2, 1, 3, "10.10.1.1")():
        print(i)
    aggregate()





