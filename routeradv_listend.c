#include <stdio.h>
#include <ctype.h>
#include <string.h> /* memset() */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* inet_pton() */
#include <sys/queue.h> /* list management macro */
#include <unistd.h> /* getopt() */
#include <net/if.h> /* if_nametoindex() */
#include <netinet/icmp6.h> /* ICMP6 structures */


 
#define LEN 1000
 
void hexdump(const void *, size_t);
void parse(void *, size_t);
void usage();
 
int main(int argc, char **argv) {
	struct icmp6_filter myfilt;
        struct ipv6_mreq mreq;  /* Multicast address join structure */
	char buffer[LEN];
	size_t len;
	int iface = 0;
	int ch, fd;

	while ((ch = getopt(argc, argv, "i:")) != -1) {
		switch (ch) {
			case 'i':
				iface = if_nametoindex(optarg);
				printf("Interface %s specified, index %d\n", optarg, iface);
				if (iface == 0) {
					perror("if_nametoindex()");
					return(1);
				}
				break;
			default:
				usage();
				return(1);
		}
	}


 
	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (fd < 0) {
		perror("socket()");
		return 1;
	}
 
 
	/* Filter to permit only router advertisements */
	memset(&myfilt, 0, sizeof(myfilt));
	ICMP6_FILTER_SETBLOCKALL(&myfilt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &myfilt);
	if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &myfilt, sizeof(myfilt)) != 0) {
		perror("setsockopt()");
		return 1;
	}

	/* Specify multicast address to listen to */
	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_interface = iface;
	if (inet_pton(AF_INET6, "ff02::1", &mreq.ipv6mr_multiaddr) != 1) {
		perror("inet_pton()");
		return 1;
	}
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) != 0) {
		perror("setsockopt()");
		return 1;
	}
 
	for (;;) {
		len = recv(fd, buffer, LEN, 0);
		if (len == -1) {
			perror("recv()");
			return 1;
		}
		parse(buffer, len);
 
		hexdump(buffer, len);
	}
 
 
	return 0;
}

void
parse(void *pkt, size_t len) {
	if (len < sizeof(struct icmp6_hdr)) {
		fprintf(stderr, "Did not receive complete ICMP packet\n");
		return;
	}
	struct icmp6_hdr *hdr = (struct icmp6_hdr *)pkt;

	switch(hdr->icmp6_type) {
		case ND_ROUTER_ADVERT:
			if (len < sizeof(struct nd_router_advert)) {
				fprintf(stderr, "Did not receive complete ICMP packet\n");
				return;
			}
			struct nd_router_advert *ra = (struct nd_router_advert *)pkt;

			fprintf(stderr, "RA\ntype:\t%d\ncode:\t%d\nchsum:\t%d\nhoplimit\t%d\nmanaged\t%d\nother\t%d\nha\t%d\nlifetime\t%d\n",
				ra->nd_ra_type,
				ra->nd_ra_code,
				ra->nd_ra_cksum,
				ra->nd_ra_curhoplimit,
				ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED, 
				ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER,
				ra->nd_ra_flags_reserved & ND_RA_FLAG_HA,
				ra->nd_ra_router_lifetime);

			
			break;
		default:
			fprintf(stderr, "Unsupported ICMP type\n");
	}
}
 
 
 
 
void
hexdump(const void *ptr, size_t buflen) {
	const unsigned char *buf = (const unsigned char*)ptr;
	int i, j;
	for (i = 0; i < buflen; i += 16) {
		printf("%06x: ", i);
		for (j = 0; j < 16; j ++) 
			if (i + j < buflen)
				printf("%02x ", buf[i + j]);
			else
				printf("   ");
		printf(" ");
		for (j = 0; j < 16; j ++) 
			if (i + j < buflen)
				printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
		printf("\n");
	}
}

void
usage() {
	fprintf(stderr, "usage()\n");
}
