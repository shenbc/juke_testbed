# 对client.py测试
import argparse
import sys
import os
import time

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT_PATH = os.path.join(BASE_DIR, '../')
print(PROJECT_ROOT_PATH)

sys.path.append(PROJECT_ROOT_PATH)
sys.path.append("..")

from utils.comm_utils import send_data_socket, get_data_socket, connect_get_socket
from utils.DataManager import DataManager

parser = argparse.ArgumentParser(description='Gradient Sender')
parser.add_argument('--tensor_size', type=int, default=100)
parser.add_argument('--src_ip', type=str, default='172.16.200.1')
parser.add_argument('--dst_ip', type=str, default='172.16.200.2')
# parser.add_argument('--socket_ip', type=str)
# parser.add_argument('--port', type=int)
parser.add_argument('--epoch', type=int, default=5)
parser.add_argument('--worker_id', type=int, default=77)
parser.add_argument('--switch_id', type=int, default=55)
parser.add_argument('--degree', type=int, default=1)
args = parser.parse_args()

iface = 'ens3f0'
gradient_size = args.tensor_size

if __name__ == "__main__":
    # s=connect_get_socket(args.socket_ip, args.port)
    print("send src_ip: {}, dst_ip: {} ...".format(args.src_ip, args.dst_ip))
    data = [0.001 for i in range(gradient_size)]
    res=['test']
    datamanger = DataManager(args.src_ip, args.dst_ip, data, iface)
    print("Start testing")
    for i in range(args.epoch):
        # get_data_socket(s)
        datamanger.fast_send_data(worker_id=args.worker_id, switch_id=args.switch_id, degree=args.degree)
        # send_data_socket(res, s)

