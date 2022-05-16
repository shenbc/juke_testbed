import argparse
import socket  
  
parser = argparse.ArgumentParser(description='Client')
parser.add_argument('--TCP_UDP', type=str, default='UDP')
parser.add_argument('--src_ip', type=str, default='172.16.200.1')
parser.add_argument('--dst_ip', type=str, default='172.16.200.2')
parser.add_argument('--dst_port', type=int, default=31500)
parser.add_argument('--send_times', type=int, default=10)
args = parser.parse_args()

if args.TCP_UDP == 'UDP':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # s.bind((args.src_ip,0))                                                   # in windows
    s.setsockopt(socket.SOL_SOCKET, 25, 'ens3f0'.encode(encoding="utf-8"))      # in linux

    print("now using:"+str(args.TCP_UDP))
    print("src_ip:"+str(args.src_ip))
    print("dst_ip:"+str(args.dst_ip))
    print("dst_port:"+str(args.dst_port))
    print("send_times"+str(args.send_times))
    print("send data begin")

    for i in range(args.send_times):  
        s.sendto("test udp".encode(encoding="utf-8"), (args.dst_ip, args.dst_port)) 
    
    print("send ok")  
    s.close() 

elif args.TCP_UDP == 'TCP' : # TCP尚未测试
    print("now using:"+str(args.TCP_UDP))
    print("src_ip:"+str(args.src_ip))
    print("dst_ip:"+str(args.dst_ip))
    print("dst_port:"+str(args.dst_port))
    print("send_times"+str(args.send_times))
    print("send data begin")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    try:
        s.connect((args.dst_ip, args.dst_port)) 
    except Exception:
        print("server port not connect!")
    
    for i in range(args.send_times):
        s.send('test tcp')

    print("send ok")
    s.close()

else:
    print("error TCP/UDP type")