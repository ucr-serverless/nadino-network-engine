import statistics
import json
from functools import partial
sz_list = [2, 4]#, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]

# [['P', '1000000', '4', '708.9807']]
# type, repeat_cnt, msg_sz, time(milliseconds)
def parse_log(log: str):
    if "type,cnt" not in log:
        return None
    info = log.split()[1]
    file = info.split(',')
    return file



cmd_repeat = 5

REPEAT = 1000000
def construct_cmd(core_command, repeat):
    command = "./build/DPU_channel -s {} -n {} {}"
    for sz in sz_list:
        for _ in range(repeat):
            yield command.format(sz, REPEAT, core_command)

def server_command_generator(local_addr, remote_addr):
    core_command = f" -p {local_addr} -r {remote_addr}"
    return partial(construct_cmd, core_command=core_command, repeat=cmd_repeat)

def client_command_generator(local_addr):
    core_command = f" -p {local_addr}"
    return partial(construct_cmd, core_command=core_command, repeat=cmd_repeat)

# [['P', '1000000', '4', '708.9807']]
# type, repeat_cnt, msg_sz, time(milliseconds)
def aggregate(re_lst):
    result = [{}, {}] # first for send, second for recv
    for re in result:
        for sz in sz_list:
            re[sz] = []
    for record in re_lst:
        index = 0
        if record[0] == 'C':
            index = 1
        # remember to convert milliseconds to usec
        result[index][int(record[2])].append(float(record[3])/float(record[1])*1000)
    with open("produce.csv", "w") as f:
        f.write("msg_sz,lat_mean(usec),lat_std(usec)\n")
        for sz in sz_list:
            if not result[0][sz]:
                continue
            mean = statistics.mean(result[0][sz])
            std = statistics.stdev(result[0][sz])
            f.write(f"{sz},{mean:.4f},{std:.4f}\n")
    with open("consume.csv", "w") as f:
        f.write("msg_sz,lat_mean(usec),lat_std(usec)\n")
        for sz in sz_list:
            if not result[1][sz]:
                continue
            mean = statistics.mean(result[1][sz])
            std = statistics.stdev(result[1][sz])
            f.write(f"{sz},{mean:.4f},{std:.4f}\n")








if __name__ == "__main__":
    for i in server_command_generator('0000:03:00.0', '0000:d8:00.0')():
        print(i)
    for i in client_command_generator('0000:03:00.0')():
        print(i)
    # aggregate()
    test_log = '''
[00:43:14:172660][462848][DOCA][INF][secure_channel_core.c:1012][sc_start] P,1000000,4,708.9807 (type,cnt,msg_sz,milliseconds)
[00:43:14:172680][462848][DOCA][INF][secure_channel_core.c:1016][sc_start] C,1000000,4,709.9952 (type,cnt,msg_sz,milliseconds)
    '''
    for i in test_log.split('\n'):
        print(parse_log(i))
    with open('result.json', 'r') as f:
        data = json.load(f)
        aggregate(data)





