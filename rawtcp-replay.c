#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PCK_LEN 8192

#define PACK_STRUCT __attribute__((__packed__))

void hexp(const char *name, const unsigned char *p, size_t plen) {
	size_t i;
	printf("%s: \n", name);
	for (i = 0; i < plen; i++) {
		if (i != 0 && i % 4 == 0) {
			printf("\n");
		}
		printf("%02x ", p[i]);
	}
	printf("\n");
}

/* IP header */
struct PACK_STRUCT ipheader {
  unsigned char iph_ihl : 4, iph_ver : 4; /* Little Endian */
  unsigned char iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident;
  // unsigned char iph_flags;
  unsigned short int iph_offset;
  unsigned char iph_ttl;
  unsigned char iph_protocol;
  unsigned short int iph_chksum;
  unsigned int iph_sourceip;
  unsigned int iph_destip;
};

/* TCP header */
struct PACK_STRUCT tcpheader {
  unsigned short int tcph_srcport;
  unsigned short int tcph_destport;
  unsigned int tcph_seqnum;
  unsigned int tcph_acknum;
  unsigned char tcph_reserved : 4, tcph_offset : 4;
  unsigned int tcp_resl : 4, tcph_hlen : 4, tcph_fin : 1, tcph_sync : 1,
      tcph_rst : 1, tcph_psh : 1, tcph_ack : 1, tcph_urg : 1, tcph_res2 : 2;

  unsigned short int tcph_win;
  unsigned short int tcph_chksum;
  unsigned short int tcph_urgptr;
};

/* checksum */
unsigned short csum(unsigned short *buf, int len) {
  unsigned long sum;
  for (sum = 0; len > 0; len--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

#define SIP "1.2.3.4"
#define DIP "4.3.2.1"
#define SPORT 999
#define DPORT 808

int main(int argc, char *argv[]) {
  int sd;
  char buffer[PCK_LEN];
  struct ipheader *ip = (struct ipheader *)buffer;
  struct tcpheader *tcp =
      (struct tcpheader *)(buffer + sizeof(struct ipheader));
  struct sockaddr_in sin, din;
  int one = 1;
  const int *val = &one;
  memset(buffer, 0, PCK_LEN);

  sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sd < 0) {
    perror("socket() error");
    exit(-1);
  }

  sin.sin_family = AF_INET;
  din.sin_family = AF_INET;
  sin.sin_port = htons(SPORT);
  din.sin_port = htons(DPORT);
  sin.sin_addr.s_addr = inet_addr(SIP);
  din.sin_addr.s_addr = inet_addr(DIP);

  ip->iph_ihl = 5;
  ip->iph_ver = 4;
  ip->iph_tos = 16;
  ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
  ip->iph_ident = htons(0x1234);
  ip->iph_offset = 0;
  ip->iph_ttl = 64;
  ip->iph_protocol = 6; // TCP
  ip->iph_chksum = 0;   // Done by kernel???
  ip->iph_sourceip = inet_addr(SIP);
  ip->iph_destip = inet_addr(DIP);

  tcp->tcph_srcport = htons(SPORT);
  tcp->tcph_destport = htons(DPORT);
  tcp->tcph_seqnum = htonl(1);
  tcp->tcph_acknum = 0;
  tcp->tcph_offset = 5;
  tcp->tcph_sync = 1;
  tcp->tcph_ack = 0;
  tcp->tcph_win = htons(10000);
  tcp->tcph_chksum = 0; // Done by kernel
  tcp->tcph_urgptr = 0;

  ip->iph_chksum = csum((unsigned short *)buffer,
                        (sizeof(struct ipheader) + sizeof(struct tcpheader)));

  hexp("buffer", buffer, sizeof(struct ipheader) + sizeof(struct tcpheader));

  // inform the kernel do not fill up the headers' structure, we fabricated our
  // own.
  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    perror("setsockopt() error");
    exit(-1);
  }

  unsigned int count;
  for (count = 0; count < 20; count++) {
    if (sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin,
               sizeof(sin)) < 0) {
      perror("sendto error");
      exit(-1);
    }
  }
  close(sd);
  return 0;
}

