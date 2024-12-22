import glob
import os
import json
sz_list = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]

def server_command_generator(device_idx, ib_port, sgid_idx):
    core_command = f" -d mlx5_{device_idx} -x {sgid_idx} -i {ib_port} -D 10 "
    def inner():
        port = 10005
        command = "ib_send_bw {} --cpu_util --out_json --out_json_file=perftest_send_bw_{}.json -s {} -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz, port)
        command = "ib_write_bw {} --cpu_util --out_json --out_json_file=perftest_write_bw_{}.json -s {} --write_with_imm -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz, port)
        command = "ib_send_lat {} --cpu_util --out_json --out_json_file=perftest_send_lat_{}.json -s {} -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz, port)
        command = "ib_write_lat {} --cpu_util --out_json --out_json_file=perftest_write_lat_{}.json -s {} --write_with_imm -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz, port)
    return inner

def client_command_generator(device_idx, ib_port, sgid_idx, address):
    core_command = f" -d mlx5_{device_idx} -x {sgid_idx} -i {ib_port} {address} -D 10 "
    def inner():
        port = 10005
        command = "ib_send_bw {} --cpu_util --out_json --out_json_file=perftest_send_bw_{}.json -s {} -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz, port)
        command = "ib_write_bw {} --cpu_util --out_json --out_json_file=perftest_write_bw_{}.json -s {} --write_with_imm -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz)
        command = "ib_send_lat {} --cpu_util --out_json --out_json_file=perftest_send_lat_{}.json -s {} -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz)
        command = "ib_write_lat {} --cpu_util --out_json --out_json_file=perftest_write_lat_{}.json -s {} --write_with_imm -p {}"
        for sz in sz_list:
            port += 1
            yield command.format(core_command, sz, sz)
    return inner

def aggregate():
    send_re = {}
    write_re = {}
    send_json = glob.glob("perftest_send_*.json")
    write_json = glob.glob("perftest_write_*.json")
    cpu_sz = os.cpu_count()
    for sz in sz_list:
        send_re[sz] = {"lat": None, "bw": None, "cpu": None}

    for file_path in send_json:
        try:
            with open(file_path, "r") as f:
                content = json.load(f)
                re = content["results"]
                if "lat" in file_path:
                    send_re[re["MsgSize"]]["lat"] = re["t_avg"]
                if "bw" in file_path:
                    send_re[re["MsgSize"]]["bw"] = re["BW_average"]
                    send_re[re["MsgSize"]]["cpu"] = re["CPU_util"]
        except (json.JSONDecodeError, OSError) as e:
            print(f"error read {file_path}: {e}")
    for file_path in write_json:
        try:
            with open(file_path, "r") as f:
                re = content["results"]
                content = json.load(f)
                if "lat" in file_path:
                    write_re[re["MsgSize"]]["lat"] = re["t_avg"]
                if "bw" in file_path:
                    write_re[re["MsgSize"]]["bw"] = re["BW_average"]
                    write_re[re["MsgSize"]]["cpu"] = re["CPU_util"]
        except (json.JSONDecodeError, OSError) as e:
            print(f"error read {file_path}: {e}")
    with open("send.csv", "w") as f:
        f.write("msg_size,single_trip_lat(usec),throughput(MB/s),CPU(%)")
        for sz, v in send_re.items():
            f.write(f"{sz},{v["lat"]},{v["bw"]},{v["cpu"]}")

    with open("write.csv", "w") as f:
        f.write("msg_size,single_trip_lat(usec),throughput(MB/s),CPU(%)")
        for sz, v in write_re.items():
            f.write(f"{sz},{v["lat"]},{v["bw"]},{v["cpu"]}")







