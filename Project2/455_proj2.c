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

#define BUF_SIZ 65536
#define LENGTH 100
#define SEND 0
#define RECV 1

typedef struct arp_hdr
{
	uint16_t ar_hrd;		//hardware type - ethernet is 1
	uint16_t ar_pro;		//protocal type - ipv4 is 0x0800
	unsigned ar_hln;		//len of hardware addr - ethernet is 6
	unsigned ar_pln;		//len of internetwork addr - arpro, ipv4 is 4
	uint16_t ar_op;			//operation 1 - request, 2 - reply
	unsigned ar_sha[6];		//sender hardware addr
	unsigned ar_sip[4];		//sender ip addr
	unsigned ar_tha[6];		//target hardware addr
	unsigned ar_tip[4];		//target ip addr
}Arp_her;

int sockfd;

void sending()
{
	
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

int main(int argc, char *argv[])
{
	Arp_her arp;
	struct ether_header mess;
	struct ifreq if_idx;
	struct ifreq if_idx2;
	struct in_addr addr;
	char interfaceName[IFNAMSIZ];
	char hw_addr[6];
	int byteSent, recvLen;
	unsigned int address;
	
	int correct = 0;

	if (argc > 1)
	{
		inet_aton(argv[2], &addr);
		strncpy(interfaceName, argv[1], IFNAMSIZ);
		
		correct = 1;
	}

	if (!correct)
	{
		fprintf(stderr, "./455_proj2 <InterfaceName> <Destination>\n");
		exit(1);
	}

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket() failed");
	}
	
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interfaceName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDE+X");

	memset(&if_idx2, 0, sizeof(struct ifreq));
	strncpy(if_idx2.ifr_name, interfaceName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_idx2) < 0)
		perror("SIOCGIFHWADDR");


	memcpy(mess.ether_shost, &if_idx2.ifr_hwaddr.sa_data, 6);
	sscanf("ff:ff:ff:ff:ff:ff", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
	memcpy(mess.ether_dhost, hw_addr, 6);
	mess.ether_type = htons(ETH_P_ARP);
	
	address = get_ip_saddr(interfaceName, sockfd);

	arp.ar_hrd = htons(0x0001);
	arp.ar_pro = htons(0x0800);
	arp.ar_hln = 6;
	arp.ar_pln = 4;
	arp.ar_op = htons(0x0001);
	memcpy(arp.ar_sha, &if_idx2.ifr_hwaddr.sa_data, 6);
	memcpy(arp.ar_sip, &address, 4);
	memcpy(arp.ar_tip, &addr.s_addr, 4);

	//send
	char buf[BUF_SIZ];
	//buf = (char *) &arp;
	memcpy(buf, &mess, sizeof(struct ether_header));
	memcpy(&buf[14], &arp, sizeof(struct arp_hdr));
	//memcpy(buf+sizeof(struct ether_header), &arp, sizeof(struct arp_hdr));

	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);

	memset(&sk_addr, 0, sk_addr_size);
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	
	int mess_size = sizeof(struct ether_header);

	printf("Request Sending...");
	byteSent = sendto(sockfd, buf, LENGTH, 0, (struct sockaddr *)&sk_addr, sizeof(struct sockaddr_ll));
	printf("\tDone\n");
	
	printf("byteSent: %d\n", byteSent);

	//recv	
	printf("Waiting for respond Recieving...");
	recvLen = recvfrom(sockfd, buf, LENGTH, 0, (struct sockaddr *)&sk_addr, &sk_addr_size);
	printf("\tDone\n");

	Arp_her * arp2;

	arp2 = (Arp_her *) &buf[14];

	printf("MAX address: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", arp2->ar_sha[0], arp2->ar_sha[1], arp2->ar_sha[2], arp2->ar_sha[3], arp2->ar_sha[4], arp2->ar_sha[5]);

	return 0;
}