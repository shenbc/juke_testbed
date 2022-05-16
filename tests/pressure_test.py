import os
from multiprocessing import Pool


def pressure_send(node_id):
    os.system("./pressure_send %s 172.16.160.5" % node_id)


def main():
    pool = Pool(4)
    for i in range(1, 17):
        pool.apply_async(pressure_send, (i,))

    pool.close()
    pool.join()


if __name__ == "__main__":
    main()
