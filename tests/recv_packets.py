# 对server.py测试
import argparse
import socket
import sys
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UTIL_PATH = os.path.join(BASE_DIR, '..')
print(UTIL_PATH)
sys.path.append(UTIL_PATH)

from utils.NGAPacket import *
from utils.comm_utils import *

ETH_P_ALL = 0x3

parser = argparse.ArgumentParser(description='Packet Sender')
parser.add_argument('--ip', type=str, default='172.16.200.2') # change 

args = parser.parse_args()


def thread_recv(ip, buffer):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, NGA_TYPE)
    s.bind((ip, 0))
    print("Get data from {}...".format(ip))
    while True:
        buffer.append(s.recvfrom(HEADER_BYTE + DATA_BYTE)[0])


if __name__ == "__main__":
    buffer = []
    listen_ip = args.ip
    for i in range(5):
        t = threading.Thread(target=thread_recv, args=(listen_ip, buffer))

    start_time = time.time()
    length = 0
    recv_header = []
    recv_data = []
    print("Start receiving...")
    while True:
        current_time = time.time()
        if current_time - start_time > 5:
            start_time = current_time
            tmp = buffer
            buffer.clear()
            # if len(tmp) == 0:
                # break

            for raw_data in tmp:
                print(len(raw_data))
                nga_header = NGAHeader(raw_data[:HEADER_BYTE])
                print("Workerid and sequenceid: {} {}".format(nga_header.workermap, nga_header.sequenceid))
                print("switchid {}  aggregationDegree {}".format(nga_header.switchid, nga_header.aggregationdegree))
                print("index {}".format(nga_header.aggindex))
                nga_payload = NGAPayload(raw_data[HEADER_BYTE:])
                recv_header.append(nga_header)
                recv_data.append(nga_payload)
    print(len(recv_header))
