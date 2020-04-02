/*
 * Simple traceroute utility to demonstrate use of RAW Sockets
 */


#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unitypes.h>
#include <limits.h>
#include <libnet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/ip.h>

#define IP_ICMP_PROTO 1
#define ICMP_TYPE_ECHO_REQ 8
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_TIME_EXCEED 11
#define ICMP_REQ_ID 10
#define ICMP_REQ_SEQNUM 55

#define MAX_WAIT 2
#define MAX_TTL  20
#define INIT_IPV4_BASE_HEADER(header){\
        header.header_len = 5;\
        header.version = 4;\
        header.serv_type = 0;\
        header.lenght = sizeof(struct ip_header) + sizeof(struct icmp_msg);\
        header.identifier = 0;\
        header.frag = 0;\
        header.ttl = 1;\
        header.proto = IP_ICMP_PROTO;\
        header.cksum = 0;\
        header.orig_ip = 0;\
        header.dest_ip = 0;}

#define INIT_ECHO_REQ_MSG(msg){\
        msg.type = ICMP_TYPE_ECHO_REQ;\
        msg.code = 0;\
        msg.id = 0;\
        msg.seqnum = 0;\
        msg.cksum = 0;}

static int init_connection();
static uint16_t checksum(const uint16_t *const data, const size_t byte_sz);
static char *get_my_ip();
static void sg_handler(int sig);
static void set_alarm_handler();


/* 
 * Generic IP and ICMP packet structures can be found
 * in linux/ip.h and linux/icmp.h, here we are making
 * our own just for fun :)
 */

struct icmp_msg{
        uint8_t  type;
        uint8_t  code;
        uint16_t cksum;
        uint16_t id;
        uint16_t seqnum;
};

struct ip_header{
        uint8_t  header_len : 4,
                 version : 4;
        uint8_t  serv_type;
        uint16_t lenght;
        uint16_t identifier;
        uint16_t frag;
        uint8_t  ttl;
        uint8_t  proto;
        uint16_t cksum;
        uint32_t orig_ip;
        uint32_t dest_ip;
};

struct datagram{
        struct ip_header ipheader;
        struct icmp_msg  icmp;
};

extern int errno;
int main(int argc, char *argv[]){
        
        unsigned char ipbuf[sizeof(struct in_addr)];
        int raw_sock;
        ssize_t status;
        struct sockaddr_in sin = {0};
        struct datagram  sent_dgram  = {0};
        struct datagram  recv_dgram  = {0};
        char *myip;

        if (argc != 2){
                printf("Usage: trc IPv4\n"
                       "Example : trc 200.43.80.12 \n");
                exit(EXIT_SUCCESS);
        }
        else if (inet_pton(AF_INET, argv[1], ipbuf) != 1){
                printf("formato de direccion ipv4 invalida\n");
                exit(EXIT_FAILURE);
        }

        set_alarm_handler();
        myip = get_my_ip();
        printf("source ip selected: %s \n\n", myip);

        /* format ip header */
        INIT_IPV4_BASE_HEADER(sent_dgram.ipheader);
        sent_dgram.ipheader.orig_ip = inet_addr(myip);
        sent_dgram.ipheader.dest_ip = inet_addr(argv[1]);
        
        /* format echo request */
        INIT_ECHO_REQ_MSG(sent_dgram.icmp);
        sent_dgram.icmp.id = ICMP_REQ_ID;
        sent_dgram.icmp.seqnum = ICMP_REQ_SEQNUM;
        sent_dgram.icmp.cksum = checksum((uint16_t *) &(sent_dgram.icmp), sizeof(struct ip_header));
        INIT_ECHO_REQ_MSG(recv_dgram.icmp);

        sin.sin_family = AF_INET;
	sin.sin_port   = htons(0);
	sin.sin_addr.s_addr = inet_addr(argv[1]);
        
        /* obtain raw sock */
        raw_sock = init_connection();

        struct sockaddr_in rip;
        uint8_t ipttl = 1;
        do{
                sent_dgram.ipheader.ttl = ipttl++;
                sent_dgram.ipheader.cksum = checksum((uint16_t *) &(sent_dgram.ipheader), sizeof(struct ip_header));
                status = sendto(raw_sock, &sent_dgram, sizeof(struct datagram), 0, (struct sockaddr *) &sin, sizeof(sin));
                if(status == -1){
                        perror("Sending echo request");
                        exit(EXIT_FAILURE);
                }
                alarm(MAX_WAIT); /* timeout wait */
                status =  recvfrom(raw_sock, &recv_dgram, sizeof(struct datagram), 0, NULL, NULL);
                alarm(0);
                if(status == -1 && errno == EINTR){
                        printf("*  *  * \n"); 
                        continue;
                }
                else if (status == -1){
                        perror("Receiving icmp reply");
                        exit(EXIT_FAILURE);
                }
                else{
                        rip.sin_addr.s_addr = recv_dgram.ipheader.orig_ip;
                        printf("%s \n", inet_ntoa(rip.sin_addr) );
                }
                
        }while(recv_dgram.icmp.type != ICMP_TYPE_ECHO_REPLY && ipttl < MAX_TTL);

        return 0;
}


static int 
init_connection(void)
{
        int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
		perror("Unable to obtain socket file descriptor");
		exit(EXIT_FAILURE);
        }
        int a = 1;
        /* informing kernel we well include the IP header inside message */
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &a, sizeof(a)) < 0) {
                perror("setsockopt() error");
                exit(EXIT_FAILURE);
        }
        
	return sockfd;
}

static
uint16_t checksum(const uint16_t *const data, const size_t byte_sz)
{

        uint32_t accu = 0;
        for (size_t i=0; i < (byte_sz >> 1); ++i) {
                accu = accu + data[i];
        }

        /*  Fold 32-bit sum to 16 bits */
         while (accu >> 16) {
                accu = (accu & 0xffff) + (accu >> 16);
        }

        const uint16_t checksum = ~accu;
        return checksum;
}


char *get_my_ip()
{
        struct ifaddrs *ifaddr, *ifa;
        int family, s, n;
        char *host = calloc(NI_MAXHOST, sizeof(char));
        
        if (host == NULL){
                perror("calloc");
                exit(EXIT_FAILURE);
        }

        if (getifaddrs(&ifaddr) == -1) {
                perror("getifaddrs");
                exit(EXIT_FAILURE);
        }

           /* Walk through linked list, maintaining head pointer so we
              can free list later */

        for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
                
                if (ifa->ifa_addr == NULL)
                        continue;
                
                family = ifa->ifa_addr->sa_family;
                if (family == AF_INET) {
                        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                        if (s != 0) {
                                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                                exit(EXIT_FAILURE);
                        }
                        /* use first address different than loopback address */
                        if (strncmp(host, "127.", 4) != 0)
                                break;
                        
               } 

       }
       freeifaddrs(ifaddr);
       return host;
}

static void sg_handler(int sig){}

static void set_alarm_handler(){
        struct sigaction sa;
        sa.sa_handler = sg_handler;
        sa.sa_flags = SA_SIGINFO;
        if (sigaction(SIGALRM, &sa, NULL) == -1){
                perror("Seteando el manejador de senal : ");
                exit(EXIT_FAILURE);
        }
}

