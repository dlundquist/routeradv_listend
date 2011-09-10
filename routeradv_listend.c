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
#include <stdlib.h> /* exit() */



#define LEN 1000

void hexdump(const void *, ssize_t);
void parse(const void *, size_t);
void usage();

int main(int argc, char **argv) {
    struct icmp6_filter myfilt;
    struct ipv6_mreq mreq;  /* Multicast address join structure */

    struct sockaddr_in6 source_addr;
    socklen_t source_addr_len;

    char buffer[LEN];
    char address_str[INET6_ADDRSTRLEN];
    ssize_t len;
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

    /* main loop */ 
    for (;;) {
        source_addr_len = sizeof(source_addr);
        len = recvfrom(fd, buffer, LEN, 0, (struct sockaddr *)&source_addr, &source_addr_len);
        if (len == -1) {
            perror("recvfrom()");
            return 1;
        }
        
        inet_ntop(AF_INET6, &(source_addr.sin6_addr), address_str, INET6_ADDRSTRLEN);

        fprintf(stderr, "Received %zd bytes from %s\n", len, address_str);

        if (! IN6_IS_ADDR_LINKLOCAL(&source_addr)) {
            fprintf(stderr, "Not link local, ignoreing \n");
            continue;
        }


        parse(buffer, len);
    }


    return 0;
}

void
parse(const void *pkt, size_t len) {
    int tries = 10;
    size_t parsed_len = 0;
    if (len < sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "Did not receive complete ICMP packet\n");
        return;
    }
    const struct icmp6_hdr *hdr = (const struct icmp6_hdr *)pkt;

    /* TODO verify checksum */

    switch(hdr->icmp6_type) {
        case ND_ROUTER_ADVERT:
            if (len < sizeof(struct nd_router_advert)) {
                fprintf(stderr, "Did not receive complete ICMP packet\n");
                return;
            }
            const struct nd_router_advert *ra = (const struct nd_router_advert *)pkt;

            fprintf(stderr, "RA\ntype:\t%d\ncode:\t%d\nchsum:\t%d\nhoplimit\t%d\nmanaged\t%d\nother\t%d\nlifetime\t%d\nreachable\t%d\nretransmit\t%d\n",
                    ra->nd_ra_type,
                    ra->nd_ra_code,
                    ra->nd_ra_cksum,
                    ra->nd_ra_curhoplimit,
                    ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED, 
                    ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER,
                    ra->nd_ra_router_lifetime,
                    ra->nd_ra_reachable,
                    ra->nd_ra_retransmit);

            parsed_len = sizeof(struct nd_router_advert);

            /* Now read the options */
            while (len - parsed_len >= sizeof(struct nd_opt_hdr) && tries --) {
                const struct nd_opt_hdr *opt = (const struct nd_opt_hdr *)((const char *)ra + parsed_len);

                switch(opt->nd_opt_type) {
                    case ND_OPT_SOURCE_LINKADDR:
                        /* Source Link layer address */
                        break;
                    case ND_OPT_PREFIX_INFORMATION:
                        if (len < sizeof(struct nd_opt_prefix_info)) {
                            fprintf(stderr, "Did not receive complete ICMP packet option\n");
                            return;
                        }
                        const struct nd_opt_prefix_info *pi = (const struct nd_opt_prefix_info *)opt;
                        char prefix_str[INET6_ADDRSTRLEN];

                        inet_ntop(AF_INET6, &(pi->nd_opt_pi_prefix), prefix_str, INET6_ADDRSTRLEN);

                        fprintf(stderr, "Prefix Info\nprefix\t%s/%d\nonlink\t%d\nauto\t%d\nraddr\t%d\nvalid_type\t%d\npreferred_time\t%d\n",
                                prefix_str,
                                pi->nd_opt_pi_prefix_len,
                                pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK,
                                pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO,
                                pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_RADDR,
                                pi->nd_opt_pi_valid_time,
                                pi->nd_opt_pi_preferred_time);

                        break;
                    case ND_OPT_MTU:
                        if (len < sizeof(struct nd_opt_mtu)) {
                            fprintf(stderr, "Did not receive complete ICMP packet option\n");
                            return;
                        }
                        const struct nd_opt_mtu *mtu= (const struct nd_opt_mtu *)opt;

                        fprintf(stderr, "MTU %d\n", ntohl(mtu->nd_opt_mtu_mtu));
                        break;
                    default:
                        fprintf(stderr, "Unsupported option %d\n", opt->nd_opt_type);
                        hexdump(pkt, len);
                        exit(99);
                }
                parsed_len += opt->nd_opt_len * 8;
            }

            if (parsed_len != len) {
                fprintf(stderr, "%zd trailing bytes\n", len - parsed_len);
            }

            break;
        default:
            fprintf(stderr, "Unsupported ICMP type\n");
    }
}




void
hexdump(const void *ptr, ssize_t buflen) {
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
