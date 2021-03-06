# 和server建立两个TCP连接
# 第一个是ssh连接（连接client 6008端口）
# 第二个是发送参数的连接（连接client master_port参数定义）
# server的接口号可忽略

import argparse
import sys
import time

import torch
import torch.optim as optim
# from pulp import *
from torch.utils.tensorboard import SummaryWriter
from threading import Thread

from config import ClientConfig
from utils import models, datasets
from utils.DataManager import DataManager
from utils.comm_utils import *
from utils.file_utils import write_tensor_to_file
from utils.training_utils import train, test

parser = argparse.ArgumentParser(description='Distributed Client')
parser.add_argument('--idx', type=str, default="0",
                    help='index of worker')
parser.add_argument('--master_ip', type=str, default="127.0.0.1",               # 在client上未用
                    help='IP address for controller or ps')
parser.add_argument('--master_port', type=int, default=58000, metavar='N',      # 本机（client）监听的端口
                    help='')
parser.add_argument('--master_nic_ip', type=str, default="127.0.0.1")
parser.add_argument('--client_ip', type=str, default='127.0.0.1')               # 本机（client）ip
parser.add_argument('--client_nic_ip', type=str, default='127.0.0.1')
parser.add_argument('--dataset', type=str, default='MNIST')
parser.add_argument('--model', type=str, default='LR')
parser.add_argument('--batch_size', type=int, default=64)
parser.add_argument('--lr', type=float, default=0.1)
parser.add_argument('--min_lr', type=float, default=0.001)
parser.add_argument('--ratio', type=float, default=0.2)
parser.add_argument('--step_size', type=float, default=1.0)
parser.add_argument('--decay_rate', type=float, default=0.97)
parser.add_argument('--weight_decay', type=float, default=0.0)
parser.add_argument('--epoch', type=int, default=5)
parser.add_argument('--local_iters', type=int, default=-1)
parser.add_argument('--use_cuda', action="store_false", default=True)
parser.add_argument('--adaptive', action="store_false", default=False)
parser.add_argument('--visible_cuda', type=str, default='-1')
parser.add_argument('--algorithm', type=str, default='proposed')
parser.add_argument('--write_to_file', default=False)
parser.add_argument('--agg_sw_idx', type=int, default=0)
parser.add_argument('--degree', type=int, default=5)
parser.add_argument('--log_note', type=str, default='')

args = parser.parse_args()

os.environ['CUDA_VISIBLE_DEVICES'] = '0'
device = torch.device("cuda" if args.use_cuda and torch.cuda.is_available() else "cpu")
print(device)


def write_tensor(filename, tensor):
    t = Thread(target=write_tensor_to_file, args=(filename, tensor))
    t.start()
    return t


def main():
    client_config = ClientConfig()
    # recorder = SummaryWriter("log_" + str(client_config.idx))
    write_t = None
    # receive config
    # client先建立监听，server再连接
    print(str(args.client_ip), str(args.master_port))
    # client本地ip与端口
    master_socket = connect_get_socket(args.client_ip, args.master_port)
    config_received = get_data_socket(master_socket)

    # print(config_received)

    for k, v in config_received.__dict__.items():
        setattr(client_config, k, v)
    args.local_ip = client_config.client_ip

    for arg in vars(args):
        print(arg, ":", getattr(args, arg))

    print('Create local model.')

    local_model = models.get_model(args.model)
    torch.nn.utils.vector_to_parameters(client_config.para, local_model.parameters())
    local_model.to(device)
    para_nums = torch.nn.utils.parameters_to_vector(local_model.parameters()).nelement()
    print("Len of tensor: {}".format(para_nums))
    train_dataset, test_dataset = datasets.load_datasets(args.dataset)
    train_loader = datasets.create_dataloaders(train_dataset, batch_size=args.batch_size,
                                               selected_idxs=client_config.custom["train_data_idxes"])

    test_loader = datasets.create_dataloaders(test_dataset, batch_size=args.batch_size, shuffle=False)

    local_model.to(device)
    epoch_lr = args.lr
    local_steps, compre_ratio = 50, 1

    data_manager = DataManager(src_ip=args.client_nic_ip,
                               dst_ip=args.master_nic_ip,
                               interface='ens3f0',
                               thread_num=8)

    file_name = 'mapper_'+str(args.client_ip)+'_'+str(args.model)+'_'+str(args.log_note)
    flog = open('log/' + file_name + '.txt', 'w')

    print("\n")
    for epoch in range(1, 1 + args.epoch):
        # 训练及测试
        epoch_lr = max((args.decay_rate * epoch_lr, args.min_lr))
        start_time = time.time()
        optimizer = optim.SGD(local_model.parameters(), lr=epoch_lr, weight_decay=args.weight_decay)
        train_loss = train(local_model, train_loader, optimizer, local_iters=local_steps, device=device,
                           model_type=args.model)
        local_para = torch.nn.utils.parameters_to_vector(local_model.parameters()).clone().detach()
        train_time = time.time() - start_time
        flog.write('EPOCH: ' + str(epoch) + '\n')
        flog.write('train_time: ' + str(train_time) + '\n')
        print('EPOCH: ' + str(epoch))
        print('train_time: ' + str(train_time))
        # print("train time: ", train_time)

        # if args.write_to_file == True and epoch == 1:
        #     write_t = write_tensor("data/log/tensor/model_{}_epoch_{}_worker_{}".
        #                            format(args.model, epoch, args.idx), local_para)

        start_time2 = time.time()
        test_loss, acc = test(local_model, test_loader, device, model_type=args.model)
        test_time = time.time() - start_time2
        flog.write('test_time: ' + str(test_time) + '\n')
        print('test_time: ' + str(test_time))
        # print("after aggregation, epoch: {}, train loss: {}, test loss: {}, test accuracy: {}".format(epoch, train_loss,
        #                                                                                               test_loss, acc))
        
        # 发数据
        print("send para")
        # start_time = time.time()
        # print(len(local_para))
        start_time3 = time.time()
        data_manager.update_data(local_para.detach().tolist())
        data_manager.fast_send_data(int(args.idx), args.agg_sw_idx, args.degree, 100000) # worker id, switch id, degree, no use
        fast_send_time = time.time() - start_time3
        flog.write('fast_send_time (include data process): ' + str(fast_send_time) + '\n')
        print('fast_send_time (include data process): ' + str(fast_send_time))

        start_time4 = time.time()
        send_data_socket(local_para.cpu(), master_socket)
        slow_send_time = time.time() - start_time4
        flog.write('slow_send_time: ' + str(slow_send_time) + '\n')
        print('slow_send_time: ' + str(slow_send_time))

        # 接收数据
        print("get begin")
        start_time5=time.time()
        if torch.cuda.is_available():
            local_para = get_data_socket(master_socket).cuda()
        else:
            local_para = get_data_socket(master_socket)
        send_data_time = time.time() - start_time5
        flog.write('recv_data_time: ' + str(send_data_time) + '\n')
        print('recv_data_time: ' + str(send_data_time))
        print("get end")
        local_para.to(device)
        torch.nn.utils.vector_to_parameters(local_para, local_model.parameters())

        epoch_time = time.time()-start_time
        flog.write('epoch_time: ' + str(epoch_time) + '\n\n')
        print('epoch_time: ' + str(epoch_time))



    flog.close()
    master_socket.shutdown(2)
    master_socket.close()
    # if write_t is not None:
    #     write_t.join()
    sys.exit(0)


if __name__ == '__main__':
    main()
