import argparse
import socket  
  
parser = argparse.ArgumentParser(description='Server')
parser.add_argument('--TCP_UDP', type=str, default='UDP')
parser.add_argument('--my_ip', type=str, default='172.16.200.2')
parser.add_argument('--my_port', type=int, default=31500)
args = parser.parse_args()

if args.TCP_UDP == 'UDP':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.my_ip, args.my_port))

    print("now using:"+str(args.TCP_UDP))
    print("my_ip:"+str(args.my_ip))
    print("my_port:"+str(args.my_port))
    print("recv data begin")

    while True:  
        data, addr = s.recvfrom(2048)
        datas = str(data,encoding='utf-8')
        print("received:" + datas + "\n")
        # print("received:" + data + "\nfrom:" + addr)
    
    s.close()

elif args.TCP_UDP == 'TCP' : # TCP尚未测试
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    s.bind((args.my_ip, args.my_port)) 
    

    print("now using:"+str(args.TCP_UDP))
    print("my_ip:"+str(args.my_ip))
    print("my_port:"+str(args.my_port))
    print("recv data begin")

    s.listen(5)
    ss, addr = s.accept() # 被动接受TCP客户端连接,(阻塞式)等待连接的到来
    print('got connected from',addr)

    ra = ss.recv(512)
    print(ra)

    ss.close()
    s.close()

else:
    print("error TCP/UDP type")