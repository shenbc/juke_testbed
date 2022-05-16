import argparse
import json
import socket
import sys
import os
from multiprocessing import Process, Manager, Array
from operator import mod

import paramiko

from config import work_dir_of_host, script_path_of_host

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT_PATH = os.path.join(BASE_DIR, '../')
print(PROJECT_ROOT_PATH)
sys.path.append(PROJECT_ROOT_PATH)

from utils.NGAPacket import *
from utils.comm_utils import *

parser = argparse.ArgumentParser(description='Packet Sender')
parser.add_argument('--config_file', type=str, default='server_config.json')
parser.add_argument('--gradient_file', type=str, default='resnet50')
parser.add_argument('--nic_ip', type=str, default='172.16.170.3')

args = parser.parse_args()


def start_worker(config):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=config['ssh_ip'], port=int(config['ssh_port']),
                    username=config['user'], password=config['pwd'])
    except Exception as e:
        print("FAILED connect to worker {}: ssh ip is {}".format(config['id'], config['ssh_ip']))
        print(e)
        ssh.close()
    else:
        cmd = ' cd ' + work_dir_of_host[config['host']] + '; sudo ' + script_path_of_host[config['host']] + \
              ' -u tests/send_packets.py' + \
              ' --file resnet50' + \
              ' --src_ip ' + config['nic_ip'] + \
              ' --dst_ip ' + args.nic_ip + \
              ' --worker_id ' + config['id'] + \
              ' --switch_id ' + config['switch_id'] + \
              ' --degree ' + config['degree'] + \
              ' > ' + PROJECT_ROOT_PATH + 'data/log/worker_' + str(config['id']) + '_log.txt 2>&1'
        print(cmd)
        stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
        stdin.write(str(config['pwd']) + '\n')
        output = []
        out = stdout.read()
        error = stderr.read()
        if out:
            print('[%s] OUT:\n%s' % (config['ssh_ip'], out.decode('utf8')))
            output.append(out.decode('utf-8'))
        if error:
            print('ERROR:[%s]\n%s' % (config['ssh_ip'], error.decode('utf8')))
            output.append(config['ssh_ip'] + ' ' + error.decode('utf-8'))
        print(output)


if __name__ == "__main__":
    config_file_path = PROJECT_ROOT_PATH + args.config_file
    with open(config_file_path) as json_file:
        worker_config = json.load(json_file)["config"]
    # launch workers
    for worker in worker_config:
        t = Thread(target=start_worker, args=(worker,))
        t.start()

    # receive
    nic_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, NGA_TYPE)
    nic_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 20480000)
    print("Recv buff: {}".format(nic_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)))
    nic_socket.bind((args.nic_ip, 0))
    updated_para = []
    recv_thread = RecvThread(func=get_data_from_nic, args=(nic_socket, updated_para, args.nic_ip))
    recv_thread.start()
    print("Start receiving...")

    time.sleep(40)
    print(len(updated_para))
    with open('recv_data', 'w') as f:
        for raw_data in updated_para:
            nga_header = NGAHeader(raw_data[:HEADER_BYTE])
            f.write("Workerid {} sequenceid {}\n".format(nga_header.workermap, nga_header.sequenceid))
            nga_payload = NGAPayload(raw_data[HEADER_BYTE - 4:])
            for d in nga_payload.data:
                f.write(str(d) + ' ')
            f.write('\n')
    print("Write done")
    sys.exit(0)
