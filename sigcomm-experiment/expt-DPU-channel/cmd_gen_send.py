import statistics
import json
from functools import partial
sz_list = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]


name = "send"

# [['1000000', '4', '708.9807']]
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
    command = "{} -s {} -n {}"
    for sz in sz_list:
        for _ in range(repeat):
            yield command.format(core_command, sz, REPEAT)

def server_command_generator(local_addr, remote_addr):
    core_command = f"./build/comch_ctrl_path_server/doca_comch_ctrl_path_server -p {local_addr} -r {remote_addr}"
    return partial(construct_cmd, core_command=core_command, repeat=cmd_repeat)

def client_command_generator(local_addr):
    core_command = f"./build/comch_ctrl_path_client/doca_comch_ctrl_path_client -p {local_addr}"
    return partial(construct_cmd, core_command=core_command, repeat=cmd_repeat)

# [['1000000', '4', '708.9807']]
# type, repeat_cnt, msg_sz, time(milliseconds)
def aggregate(re_lst):
    result = {} # first for send, second for recv
    for re in result:
        for sz in sz_list:
            re[sz] = []
    for record in re_lst:
        # remember to convert milliseconds to usec
        result[int(record[1])].append(float(record[2])/float(record[0])*1000)
    with open("send.csv", "w") as f:
        f.write("msg_sz,lat_mean(usec),lat_std(usec)\n")
        for sz in sz_list:
            if not result[sz]:
                continue
            mean = statistics.mean(result[sz])
            std = statistics.stdev(result[sz])
            f.write(f"{sz},{mean:.4f},{std:.4f}\n")








if __name__ == "__main__":
    for i in server_command_generator('0000:03:00.0', '0000:d8:00.0')():
        print(i)
    for i in client_command_generator('0000:03:00.0')():
        print(i)
    # aggregate()
    test_log = '''
[22:44:44:324766][796554][DOCA][INF][comch_ctrl_path_client_sample.c:415][start_comch_ctrl_path_client_sample] 1000000,2,84163.7828 (cnt,msg_sz,milliseconds)
    '''
    for i in test_log.split('\n'):
        print(parse_log(i))
    with open('send_result.json', 'r') as f:
        data = json.load(f)
        aggregate(data)





