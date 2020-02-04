#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define BUF_SIZ 65536
#define SEND 0
#define RECV 1


typedef struct message
{
	char addr[6];
	char name[IFNAMSIZ];
	char data[BUF_SIZ];
	char type[10];
} Message;

int sockfd;

void send_message(char hw_addr[6], Message mes, char if_name[10], struct ifreq if_idx, struct ifreq if_idx2)
{
	//void send_message(Message mes){
	//Do something here
	//define
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	int byteSent;

	char *buf;
	buf = (char *) &mes;
	
	int sendLen = strlen(buf);
	
	printf("%d", sendLen);
	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	byteSent = sendto(sockfd, buf, 100, 0,
	//byteSent = sendto(sockfd, msg, sendLen, 0,
					  (struct sockaddr *)&sk_addr,
					  sizeof(struct sockaddr_ll));
}

void recv_message(char buf[BUF_SIZ], char if_name[10])
//void recv_message(char if_name[IFNAMSIZ])
{
	//void recv_message(Message mes){
	//Do something here
	//define
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	int recvLen;
	
	//receive
	memset(&sk_addr, 0, sk_addr_size);
	recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr *)&sk_addr, &sk_addr_size);
	//recvLen = recvfrom(sockfd, mes, BUF_SIZ, 0, (struct sockaddr *)&sk_addr, &sk_addr_size);
	
	Message *mes;
	mes = (Message *)buf;

	//msg = (Message *)mes;

	//display
	printf("From:\t\t%s\n", mes->name);
	printf("Address:\t%s\n", mes->addr);
	printf("Type:\t\t%s\n", mes->type);
	printf("Message:\t%s\n", mes->data);
}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
	memset(buf, 0, BUF_SIZ);
	Message mes;
	struct ifreq if_idx;
	struct ifreq if_idx2;

	int correct = 0;
	if (argc > 1)
	{
		//./455_proj2 Send <InterfaceName> <DestHWAddr> <Message>
		//./455_proj2 Send h1-eth0 01:23:45:67:89:ab ‘This is a test’
		if (strncmp(argv[1], "Send", 4) == 0)
		{
			if (argc == 5)
			{
				mode = SEND;
				sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				
				for (int i = 0; i < 6; i++)
				{
					mes.addr[i] = hw_addr[i];
				}
				strncpy(mes.data, argv[4], BUF_SIZ);
				strncpy(buf, argv[4], BUF_SIZ);
				correct = 1;
				printf("  buf: %s\n", buf);
			}
		}
		//./455_proj2 Recv <InterfaceName>
		//./455_proj2 Recv h2-eth0
		else if (strncmp(argv[1], "Recv", 4) == 0)
		{
			if (argc == 3)
			{
				mode = RECV;
				correct = 1;
			}
		}
		strncpy(mes.name, argv[2], IFNAMSIZ);
		strncpy(interfaceName, argv[2], IFNAMSIZ);
	}
	if (!correct)
	{
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestHWAddr> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	}

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket() failed");
	}

	//Do something here
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interfaceName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");

	memset(&if_idx2, 0, sizeof(struct ifreq));
	strncpy(if_idx2.ifr_name, interfaceName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_idx2) < 0)
		perror("SIOCGIFHWADDR");

	if (mode == SEND)
	{
		send_message(hw_addr, mes, interfaceName, if_idx, if_idx2);
		//send_message(hw_addr, buf, interfaceName, if_idx, if_idx2);
		//send_message(mes)
	}
	else if (mode == RECV)
	{
		recv_message(buf, interfaceName);
		//recv_message(mes)
	}

	return 0;
}