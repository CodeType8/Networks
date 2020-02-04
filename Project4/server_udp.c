#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>

#define SERVER_PORT 5432
#define MAX_LINE 256
#define MAX 80

int main(int argc, char * argv[])
{
    char *fname;
    char buf[MAX_LINE], buf2[MAX];
    struct sockaddr_in sin;
    int len;
    int s, i;
    struct timeval tv;
    char seq_num = 1; 
    FILE *fp;

    if (argc==2) {
        fname = argv[1];
    }
    else {
        fprintf(stderr, "usage: ./server_udp filename\n");
        exit(1);
    }


    /* build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(SERVER_PORT);

    /* setup passive open */
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("simplex-talk: socket");
        exit(1);
    }
    if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        perror("simplex-talk: bind");
        exit(1);
    }

    socklen_t sock_len = sizeof sin;

    fp = fopen(fname, "w");
    if (fp==NULL){
        printf("Can't open file\n");
        exit(1);
    }

    //sequence number
    int seq = 1;
    
    while(1){
        len = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sin, &sock_len);

        if(len == -1){
                perror("PError");
        }    
        else if(len == 1){
            if (buf[0] == 0x02){
                printf("Transmission Complete\n");
                break;
            }
        }
        else if(len > 1){
            //reply server recived line.
            buf2[0] = seq;

            sendto(s, buf2, sizeof(buf2), 0, (struct sockaddr *)&sin, sock_len);
            
            //display buf from second element
            //first element is seqence number
            if(fputs((char *) &buf[1], fp) < 1){
                printf("fputs() error\n");
            }

            seq += 1;
        }
    }
    fclose(fp);
    close(s);
}
