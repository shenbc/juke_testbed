import argparse
import struct
import sys
import os
import time

from utils.comm_utils import float_to_int, int_to_float

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT_PATH = os.path.join(BASE_DIR, '../')
print(PROJECT_ROOT_PATH)

sys.path.append(PROJECT_ROOT_PATH)
sys.path.append("..")

from utils.DataManager import DataManager

parser = argparse.ArgumentParser(description='Tensor Cast')
parser.add_argument('--file', type=str, default='resnet50')

args = parser.parse_args()

if __name__ == "__main__":
    print("file name: {}".format(args.file))
    file_path = PROJECT_ROOT_PATH + 'data/log/tensor/' + args.file
    with open(file_path, 'r') as gradient_file:
        data = list(map(float, gradient_file.readline().strip().split(' ')))

    int_data = float_to_int(data)
    tmp=[]
    for d in int_data:
        tmp.append(struct.unpack("i", d)[0])
    float_data = int_to_float(tmp)
    for d, int_d in zip(data, float_data):
        print(str(d) + ' ' + str(int_d))
