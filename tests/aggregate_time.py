import time

max_ttt = [2.0949907302856445, 4.131427049636841, 6.284679412841797, 10.377572298049927, 10.47489595413208]
total_ttt = [41.22669744491577, 82.40306186676025, 123.71613240242004, 166.96020030975342, 206.13202619552612]
min_ttt = [2.051860809326172, 4.111142873764038, 6.156078815460205, 8.22974157333374, 10.249572515487671]


def aggregate_time(worker_num, gradient_size):
    tmp = [0.01 for i in range(gradient_size)]
    start_time = time.time()
    for i in range(worker_num):
        for d in tmp:
            d += d
    duration = time.time() - start_time
    return duration


if __name__ == "__main__":
    model_size = [25557032]
    worker_num = [4, 8, 12, 16, 20]
    time_res = []
    max_time = [0 for i in range(5)]
    min_time = [1000 for i in range(5)]
    avg_time = [0 for i in range(5)]
    for count in range(20):
        print("epoch {} ".format(str(count)))
        for index, num in enumerate(worker_num):
            agg_time = aggregate_time(num, model_size[0])
            if agg_time > max_time[index]:
                max_time[index] = agg_time
            if agg_time < min_time[index]:
                min_time[index] = agg_time
            avg_time[index] += agg_time
    for tt in avg_time:
        tt = tt / 20
    print(max_time)
    print(avg_time)
    print(min_time)
