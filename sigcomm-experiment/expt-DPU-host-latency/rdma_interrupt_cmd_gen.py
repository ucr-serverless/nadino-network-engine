import statistics
import json
from functools import partial

sz_list = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
REPEAT = 1000000
#REPEAT = 100
cmd_repeat = 5
#sz_list = [2]


name = "rdma_interrupt"


# [['1000000', '4', '708.9807']]
# type, repeat_cnt, msg_sz, time(milliseconds)
def parse_log(log: str):
    if "cnt" not in log:
        return None
    info = log.split()[5]
    file = info.split(',')
    return file




def construct_cmd(core_command, repeat):
    command = "{} -s {} -n {}"
    for sz in sz_list:
        for _ in range(repeat):
            yield command.format(core_command, sz, REPEAT)

def server_command_generator(device, gid_index, ib_port):
    core_command = f"../../build/rdma_interrupt_lat -p 10010 -d {device} -i {ib_port} -x {gid_index} -L 0.0.0.0"
    return partial(construct_cmd, core_command=core_command, repeat=cmd_repeat)

def client_command_generator(device, gid_index, ib_port, host_ip):
    core_command = f"../../build/rdma_interrupt_lat -p 10010 -d {device} -i {ib_port} -x {gid_index} -H {host_ip}"
    return partial(construct_cmd, core_command=core_command, repeat=cmd_repeat)

# [['type', '1000000', '4', '708.9807']]
# type, repeat_cnt, msg_sz, time(milliseconds)
def aggregate(re_lst):
    print(re_lst)
    result = {} # first for send, second for recv
    for sz in sz_list:
        result[sz] = []
    for record in re_lst:
        # remember to convert milliseconds to usec
        result[int(record[2])].append(float(record[3])/float(record[1])*1000)
    with open("rdma_interrupt_latency_result.csv", "w") as f:
        f.write("msg_sz,lat_mean(usec),lat_std(usec)\n")
        for sz in sz_list:
            if not result[sz]:
                continue
            mean = statistics.mean(result[sz])
            std = statistics.stdev(result[sz])
            f.write(f"{sz},{mean:.4f},{std:.4f}\n")








if __name__ == "__main__":
    for i in server_command_generator(10001, 2, 3, 1)():
        print(i)
    for i in client_command_generator(10001, 2, 3, 1, "192.168.10.42")():
        print(i)
    # aggregate()
    test_log = '''
08:09:40 INFO  ../sigcomm-experiment/expt-DPU-host-latency/rdma_interrupt_lat.c:362: [main()]   rdma_interrupt_lat_server,100000,2,3360.3566 (type,cnt,msg_sz,milliseconds)
    '''
    for i in test_log.split('\n'):
        print(parse_log(i))
    with open(f'{name}_result.json', 'r') as f:
        data = json.load(f)
        aggregate(data)





