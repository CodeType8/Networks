#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define BUF_SIZ 65536
#define LENGTH 100
#define SEND 0
#define RECV 1

typedef struct arp_hdr
{
	uint16_t ar_hrd;	//hardware type - ethernet is 1
	uint16_t ar_pro;	//protocal type - ipv4 is 0x0800
	unsigned ar_hln;	//len of hardware addr - ethernet is 6
	unsigned ar_pln;	//len of internetwork addr - arpro, ipv4 is 4
	uint16_t ar_op;		//operation 1 - request, 2 - reply
	unsigned ar_sha[6]; //sender hardware addr
	unsigned ar_sip[4]; //sender ip addr
	unsigned ar_tha[6]; //target hardware addr
	unsigned ar_tip[4]; //target ip addr
} Arp_her;

typedef struct message
{
	char addr[6];
	char name[IFNAMSIZ];
	char data[BUF_SIZ];
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
	buf = (char *)&mes;

	//int sendLen = strlen(buf);

	//printf("%d", sendLen);
	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	byteSent = sendto(sockfd, buf, 100, 0,
					  //byteSent = sendto(sockfd, msg, sendLen, 0,
					  (struct sockaddr *)&sk_addr,
					  sizeof(struct sockaddr_ll));
}

void recv_message(char buf[BUF_SIZ], char if_name[10], int check)
{
	if (check == 1)
	{
		printf("Recived APR request.");
	}
	else
	{
		struct sockaddr_ll sk_addr;
		int sk_addr_size = sizeof(struct sockaddr_ll);
		int recvLen;

		memset(&sk_addr, 0, sk_addr_size);
		recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr *)&sk_addr, &sk_addr_size);

		Message *mes;
		mes = (Message *)buf;

		//display
		printf("From:\t\t%s\n", mes->name);
		printf("Message:\t%s\n", mes->data);
	}
}

unsigned int get_netmask(char *if_name, int sockfd)
{
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
	if ((ioctl(sockfd, SIOCGIFNETMASK, &if_idx)) == -1)
		perror("ioctl():");
	return ((struct sockaddr_in *)&if_idx.ifr_netmask)->sin_addr.s_addr;
}

unsigned int get_ip_saddr(char *if_name, int sockfd)
{
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0)
		perror("SIOCGIFADDR");
	return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr;
}

int16_t ip_checksum(void *vdata, size_t length)
{
	char *data = (char *)vdata;
	uint32_t acc = 0xffff;
	for (size_t i = 0; i + 1 < length; i += 2)
	{
		uint16_t word;
		memcpy(&word, data + i, 2);
		acc += ntohs(word);
		if (acc > 0xffff)
		{
			acc -= 0xffff;
		}
	}
	if (length & 1)
	{
		uint16_t word = 0;
		memcpy(&word, data + length - 1, 1);
		acc += ntohs(word);
		if (acc > 0xffff)
		{
			acc -= 0xffff;
		}
	}
	return htons(~acc);
}

int main(int argc, char *argv[])
{
	Arp_her arp;
	Message mes;
	struct ether_header mess;
	struct ifreq if_idx;
	struct ifreq if_idx2;
	struct ifreq if_idx3;
	struct in_addr addr;
	struct in_addr addrR;
	struct iphdr header;
	struct sockaddr_ll sk_addr;
	char interfaceName[IFNAMSIZ];
	char hw_addr[6];
	int byteSent, recvLen;
	int mode;
	int correct = 0;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	unsigned int address, netmask;

	char buf[BUF_SIZ];

	//get arguments
	if (argc > 1)
	{
		strncpy(interfaceName, argv[2], IFNAMSIZ);

		//./a.out Send <InterfaceName> <DestIP> <RouterIP> <Message>
		//./a.out Send h1x1-eth0 10.0.0.102 192.168.1.1 ‘This is a test’
		if (strncmp(argv[1], "Send", 4) == 0)
		{
			if (argc == 6)
			{
				mode = SEND;
				//inet_aton("192.168.1.0", &addr);
				inet_aton(argv[2], &addr);  //dest IP
				inet_aton(argv[3], &addrR); //Router IP

				strncpy(mes.data, argv[5], BUF_SIZ); //Message

				correct = 1;
				printf("  Message: %s\n", mes.data);
			}
		}
		//./a.out Recv <InterfaceName>
		//./a.out Recv h3x2-eth0
		else if (strncmp(argv[1], "Recv", 4) == 0)
		{
			if (argc == 3)
			{
				mode = RECV;
				correct = 1;
			}
		}
	}

	if (!correct)
	{
		fprintf(stderr, "Wrong argument\n./455_proj3 <Send/Recv> <InterfaceName> <Destination>\n");
		exit(1);
	}

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket() failed");
	}

	//if_idx setting
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interfaceName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDE+X\n");

	memset(&if_idx2, 0, sizeof(struct ifreq));
	strncpy(if_idx2.ifr_name, interfaceName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_idx2) < 0)
		perror("SIOCGIFHWADDR\n");

	memset(&if_idx3, 0, sizeof(struct ifreq));
	strncpy(if_idx3.ifr_name, interfaceName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_idx3) < 0)
	{
		printf("SIOCGIFADDR\n");
	}

	//Sender
	if (mode == SEND)
	{
		memcpy(mess.ether_shost, &if_idx2.ifr_hwaddr.sa_data, 6);
		sscanf("ff:ff:ff:ff:ff:ff", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
		memcpy(mess.ether_dhost, hw_addr, 6);
		mess.ether_type = htons(ETH_P_ARP);

		//header setting
		//struct iphdr *header = (struct iphdr *)(sendbuff + sizeof(struct ethhdr));
		header.ihl = 5;
		header.version = 4;
		header.tos = 16;
		header.id = htons(10201);
		header.ttl = 64;
		header.protocol = 17;
		header.saddr = ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr;
		header.daddr = addr.s_addr;
		//header.saddr = inet_addr(inet_ntoa((((struct sockaddr_in *)&(if_idx3.ifr_addr))->sin_addr)));
		//header.daddr = inet_addr();	//destication ip address
		int header_len = sizeof(struct iphdr);

		//get ip/netmask address
		address = get_ip_saddr(interfaceName, sockfd);
		netmask = get_netmask(interfaceName, sockfd);

		//arp setting
		arp.ar_hrd = htons(0x0001);
		arp.ar_pro = htons(0x0800);
		arp.ar_hln = 6;
		arp.ar_pln = 4;
		arp.ar_op = htons(0x0001);
		memcpy(arp.ar_sha, &if_idx2.ifr_hwaddr.sa_data, 6);
		memcpy(arp.ar_sip, &address, 4);

		//if same netmask then
		unsigned int net1, net2, mask;

		//(senderip & netmask) == (destip & netmask), then local network
		//inet_aton(address, &net1);
		//inet_aton(addr.s_addr, &net2);	//it is already binary
		//inet_aton(netmask, &mask);
		if ((address & netmask) == (addr.s_addr & netmask))
		{
			memcpy(arp.ar_tip, &addr.s_addr, 4);
		}
		else
		{
			//to the router
			memcpy(arp.ar_tip, &addrR.s_addr, 4);
		}

		//Send ARP request for get HWaddress
		memcpy(buf, &mess, sizeof(struct ether_header));
		memcpy(&buf[14], &arp, sizeof(struct arp_hdr));

		memset(&sk_addr, 0, sk_addr_size);
		sk_addr.sll_ifindex = if_idx.ifr_ifindex;
		sk_addr.sll_halen = ETH_ALEN;

		printf("Sending ARP request for get HWaddress...\n");
		byteSent = sendto(sockfd, buf, LENGTH, 0, (struct sockaddr *)&sk_addr, sizeof(struct sockaddr_ll));

		//Recive ARP response
		recvLen = recvfrom(sockfd, buf, LENGTH, 0, (struct sockaddr *)&sk_addr, &sk_addr_size);
		printf("Recived\n");

		Arp_her *arp2;

		arp2 = (Arp_her *)&buf[14];

		//Now, HWaddress = arp2->ar_sha

		//Sending message
		printf("Sending message...\n");

		for (int i = 0; i < 6; i++)
		{
			mes.addr[i] = arp2->ar_sha[i];
		}

		send_message(hw_addr, mes, interfaceName, if_idx, if_idx2);
	}

	//reciever
	else if (mode == RECV)
	{
		recv_message(buf, interfaceName, 2);
	}

	return 0;
}