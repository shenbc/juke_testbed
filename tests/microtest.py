import argparse
import os
import socket
import sys

import json
import threading
import random

import asyncio

import concurrent
import time

from config import work_dir_of_host, script_path_of_host
from header_config import NGA_TYPE
from server import get_nic_data
from utils.comm_utils import start_remote_process, get_data_from_nic, RecvThread, get_data_socket, connect_send_socket, \
    send_data_socket

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_DIR = os.path.join(BASE_DIR, '../')
print(PROJECT_DIR)
sys.path.append(PROJECT_DIR)

parser = argparse.ArgumentParser(description='Micro Benchmark')
parser.add_argument('--file', type=str, default='worker_config.json')
parser.add_argument('--model', type=str, default='AlexNet')
parser.add_argument('--epoch', type=int, default=10)
parser.add_argument('--listen_ip', type=str, default='172.16.50.3')
parser.add_argument('--dst_ip', type=str, default='172.16.170.3')
parser.add_argument('--alg', type=str, default='NCCL')
args = parser.parse_args()

model_size = {
    'LSTM': 1627,
    'VGG19': 548,
    'NCF': 121,
    'ResNet50': 87,
    'AlexNet': 14
}

degree = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]


def communication_parallel(socket_list, action, data=None):
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        executor = concurrent.futures.ThreadPoolExecutor(max_sockets=len(socket_list), )
        tasks = []
        for socket in socket_list:
            if action == 'send':
                tasks.append(loop.run_in_executor(executor, send_data_socket, data, socket))
            elif action == 'get':
                tasks.append(loop.run_in_executor(executor, verify_send_info, socket))
        loop.run_until_complete(asyncio.wait(tasks))
        loop.close()
    except:
        sys.exit(0)


def verify_send_info(socket):
    received_para = get_data_socket(socket)


if __name__ == '__main__':
    offset = random.randint(0, 20) * 20

    with open(PROJECT_DIR + args.file) as json_file:
        worker_config = json.load(json_file)['worker_config_list'][:2]

    nic_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, NGA_TYPE)
    nic_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 20480000)
    print("Recv buff: {}".format(nic_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)))
    nic_socket.bind((args.dst_ip, 0))
    updated_para = []
    recv_thread = RecvThread(func=get_data_from_nic, args=(nic_socket, updated_para))
    recv_thread.start()

    model = args.model
    tensor_size = model_size[model] * 1024 * 256
    socket_list = []
    for index, worker in enumerate(worker_config):
        if worker['host'] == 'server08':
            switch_id = 1
        else:
            switch_id = 0
        port = 53300 + offset + index
        cmd = ' cd ' + work_dir_of_host[worker['host']] + \
              '; sudo ' + script_path_of_host[worker['host']] + \
              ' -u tests/send_packets.py ' + \
              ' --dst_ip ' + args.dst_ip + \
              ' --src_ip ' + worker['nic_ip'] + \
              ' --tensor_size ' + str(tensor_size) + \
              ' --socket_ip ' + worker['ip'] + \
              ' --port ' + str(port) + \
              ' --epoch ' + str(args.epoch) + \
              ' --worker_id ' + str(index) + \
              ' --switch_id ' + str(switch_id) + \
              ' --degree ' + str(degree[index]) + \
              ' > data/log/microbench_' + str(index) + '_model_' + model + '_log.txt 2>&1'
        t = threading.Thread(target=start_remote_process,
                             args=(worker['ip'], worker['ssh_port'], worker['user'], worker['pwd'], cmd))
        t.start()
        socket_list.append(connect_send_socket(worker['ip'], int(port)))

    aggregate_time = []
    res = ['test']
    print(socket_list)
    print("Start test...")
    for i in range(args.epoch):
        start_time = time.time()
        communication_parallel(socket_list, 'send', res)
        communication_parallel(socket_list, 'get')
        res = get_nic_data(updated_para, tensor_size)
        aggregate_time.append(time.time() - start_time)

    with open('agg_microbench_model_{}_alg_{}'.format(args.model, args.alg)) as f:
        for t in aggregate_time:
            f.write(str(t) + ' ')
