#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define SERVER_PORT 5432
#define MAX_LINE 80
#define WINSIZE 10

int main(int argc, char *argv[])
{
    FILE *fp;
    struct hostent *hp;
    struct sockaddr_in sin;
    char *host;
    char *fname;
    char buf[MAX_LINE], buf2[(MAX_LINE + 1)];
    int s;
    int slen;

    if (argc == 3)
    {
        host = argv[1];
        fname = argv[2];
    }
    else
    {
        fprintf(stderr, "Usage: ./client_udp host filename\n");
        exit(1);
    }
    /* translate host name into peer’s IP address */
    hp = gethostbyname(host);
    if (!hp)
    {
        fprintf(stderr, "Unknown host: %s\n", host);
        exit(1);
    }

    fp = fopen(fname, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Can't open file: %s\n", fname);
        exit(1);
    }

    /* build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
    sin.sin_port = htons(SERVER_PORT);

    /* active open */
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Socket");
        exit(1);
    }

    socklen_t sock_len = sizeof sin;

    //timeouts 1 sec
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("PError");
    }

    int reply = 0, seq = 1, i = 0;
    char save[WINSIZE][MAX_LINE];

    /* main loop: get and send lines of text */
    while (fgets(buf, 80, fp) != NULL)
    {
        slen = strlen(buf);
        buf[slen] = '\0';

        //add sequence number to first byte of packet
        buf2[0] = seq;
        //add line data from second byte of packet
        strcpy(&buf2[1], buf);
        //save line data in case resends are needed
        if ((seq - 1) > 9)
        {
            //save previous data is oldest to newest order
            for (i = 0; i < 10; i++)
            {
                if (i == 9)
                {
                    //save new buf aat the end
                    strcpy(save[i], buf);
                }
                else
                {
                    //push all data to front
                    strcpy(save[i], save[i + 1]);
                }
            }
        }
        else
        {
            strcpy(save[(seq - 1)], buf);
        }

        if (sendto(s, buf2, slen + 1, 0, (struct sockaddr *)&sin, sock_len) < 0)
        {
            perror("SendTo Error\n");
            exit(1);
        }
        else
        {
            printf("sequence number %d sending....\t", seq);
        }

        //get reply from server
        reply = recvfrom(s, buf, slen, 0, (struct sockaddr *)&sin, &sock_len);

        //if packet droped
        if (reply == -1)
        {
            printf("packet droped\n");

            //re-send packet
            if (sendto(s, buf2, slen + 1, 0, (struct sockaddr *)&sin, sock_len) < 0)
            {
                perror("SendTo Error\n");
                exit(1);
            }

            printf("sequence number %d re-sent\n", seq);
        }
        //packet successfully sent
        else
        {
            printf("OK\n");
        }
        seq += 1;
    }

    *buf = 0x02;
    if (sendto(s, buf, 1, 0, (struct sockaddr *)&sin, sock_len) < 0)
    {
        perror("SendTo Error\n");
        exit(1);
    }
    fclose(fp);
}
