#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/in.h>


#define GRADIENT_SIZE 128
#define AGGREGATOR_SIZE 572000


struct payload_t {
    __u16 bitmap;
    __u32 gradient_index;
	__u32 gradient[GRADIENT_SIZE];
} __attribute__((packed));

struct gradient_t {
    __u16 bitmap;
    __u16 counter;
	__u32 gradient[GRADIENT_SIZE];
} __attribute__((packed, aligned(4)));


int main(int argc, char **argv)
{
    int  socket_fd;
	struct sockaddr_in sock_send;
    memset(&sock_send, 0, sizeof(struct sockaddr_in));
	sock_send.sin_family = AF_INET;
	sock_send.sin_addr.s_addr = inet_addr(argv[2]);

	if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
	{
	    perror("Build Raw Socket Error\n");
		exit(-1);
	}

    int size = 256 * 1024;
    setsockopt(socket_fd,SOL_SOCKET,SO_SNDBUF,&size,sizeof(size));

    int node_id = atoi(argv[1]);
    int bitmap = 1 << (node_id-1);
    int i;
    struct gradient_t value;

    int j;
    for (i=0; i<GRADIENT_SIZE ; i++)
    {
        value.gradient[i] = htonl(i);
    }

    clock_t start, end;
    start = clock();
    for (i=0; i<AGGREGATOR_SIZE; i++)
    {
        struct payload_t payload;
        payload.bitmap = htons(bitmap);
        payload.gradient_index = htonl(i);
        memcpy(payload.gradient, value.gradient, GRADIENT_SIZE * sizeof(__u32));

	    if(sendto(socket_fd, &payload, sizeof(struct payload_t), 0, (struct sockaddr *)&sock_send, sizeof(struct sockaddr_in)) < 0)
        {
            perror("sendto() Error\n");
		    exit(-1);
        }
    }
    end = clock();
    printf("程序耗时：%lf\n", (double)(end - start));

	return 0;
}
