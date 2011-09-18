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
#include <time.h> /* time(), time_t */


#define LEN 256

struct Router {
    struct in6_addr address;
    time_t valid_until;
    SLIST_ENTRY(Router) entries;
};

static SLIST_HEAD(, Router) routers;

void hexdump(const void *, ssize_t);
int parse(const void *, size_t);
uint16_t checksum(const struct in6_addr *, const struct in6_addr *, const void *, size_t);
void usage();

int main(int argc, char **argv) {
    char buffer[LEN];
    char address_str[INET6_ADDRSTRLEN];
    char ifname_str[IF_NAMESIZE];
    ssize_t len;
    int iface = 0;
    int fd, ch;

    SLIST_INIT(&routers);

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
    struct icmp6_filter myfilt;
    memset(&myfilt, 0, sizeof(myfilt));
    ICMP6_FILTER_SETBLOCKALL(&myfilt);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &myfilt);
    if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &myfilt, sizeof(myfilt)) != 0) {
        perror("setsockopt()");
        return 1;
    }

    /* Specify multicast address to listen to */
    struct ipv6_mreq mreq;  /* Multicast address join structure */
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

    /* Specify additional ancillary data */
    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) != 0) {
        perror("setsockopt()");
        return 1;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) != 0) {
        perror("setsockopt()");
        return 1;
    }

    /* main loop */ 
    for (;;) {
        struct msghdr m;
        struct sockaddr_in6 source_addr;
        const struct in6_addr *destination_addr;
        struct iovec iov[1];
        char control_data[LEN];
        int hop_limit;

        memset(&m, 0, sizeof(m));
        memset(&iov, 0, sizeof(iov));
        memset(&source_addr, 0, sizeof(source_addr));
        memset(buffer, 0, sizeof(buffer));
        memset(control_data, 0, sizeof(control_data));

        m.msg_name = &source_addr;
        m.msg_namelen = sizeof(source_addr);
        iov[0].iov_base = buffer;
        iov[0].iov_len = sizeof(buffer);
        m.msg_iov = iov;
        m.msg_iovlen = 1;
        m.msg_control = (void *)control_data;
        m.msg_controllen = sizeof(control_data);
        m.msg_flags = 0;

        len = recvmsg(fd, &m, 0);
        if (len < 0) {
            perror("recvmsg()");
            return 1;
        }

        if (inet_ntop(AF_INET6, &(source_addr.sin6_addr), address_str, INET6_ADDRSTRLEN) == NULL) {
            perror("inet_ntop()");
            return 1;
        }

        fprintf(stderr, "Received %zd bytes from %s\n", len, address_str);


        /* Parse ancillary data */
        struct cmsghdr *cmsg;
        const struct in6_pktinfo *pktinfo;
        for (cmsg = CMSG_FIRSTHDR(&m); cmsg != NULL; cmsg = CMSG_NXTHDR(&m,cmsg)) {
            /*
            fprintf(stderr, "cmsg level %d, type %d, len %zd\n", cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);
            hexdump(CMSG_DATA(cmsg), cmsg->cmsg_len - sizeof(struct cmsghdr));
            */
            switch(cmsg->cmsg_level) {
                case IPPROTO_IPV6:
                    switch(cmsg->cmsg_type) {
                        case IPV6_HOPLIMIT:
                            hop_limit = *(int *)CMSG_DATA(cmsg);
                            fprintf(stderr, "hop limit %d\n", hop_limit);
                            break;
                        case IPV6_PKTINFO:
                            pktinfo = (const struct in6_pktinfo *)CMSG_DATA(cmsg);
                            destination_addr = &(pktinfo->ipi6_addr);
                            if (inet_ntop(AF_INET6, destination_addr, address_str, INET6_ADDRSTRLEN) == NULL) {
                                perror("inet_ntop()");
                                return 1;
                            }

                            if (if_indextoname(pktinfo->ipi6_ifindex, ifname_str) == NULL) {
                                perror("if_indextoname()");
                                return 1;
                            }

                            fprintf(stderr, "Received packet destined for %s on interface %s\n", address_str, ifname_str);
                            break;
                        default:
                            fprintf(stderr, "Unexpected cmsg type %d\n", cmsg->cmsg_type);
                            return -1;
                    }
                    break;
                default:
                    fprintf(stderr, "Unexpected cmsg level %d\n", cmsg->cmsg_level);
                    return -1;
            }
        }


        /*
         * RFC4861 requires 6 validations of router advertisments
         *
         * - IP Source Address is a link-local address.  Routers must use
         *   their link-local address as the source for Router Advertisement
         *   and Redirect messages so that hosts can uniquely identify
         *   routers.
         * - The IP Hop Limit field has a value of 255, i.e., the packet
         *   could not possibly have been forwarded by a router.
         * - ICMP Checksum is valid.
         * - ICMP Code is 0.
         * - ICMP length (derived from the IP length) is 16 or more octets.
         * - All included options have a length that is greater than zero.
         */
        if (! IN6_IS_ADDR_LINKLOCAL(&(source_addr.sin6_addr))) {
            fprintf(stderr, "Not link local, ignoring\n");
            continue;
        }

        if (hop_limit != 255) {
            fprintf(stderr, "Hop limit is not 255, ignoring\n");
            continue;
        }
   
        if (checksum(&(source_addr.sin6_addr), destination_addr, iov[0].iov_base, len) != 0) {
            fprintf(stderr, "Invalid checksum, ignoring\n");
            continue;
        }

        parse(iov[0].iov_base, iov[0].iov_len);
    }
    return 0;
}

uint16_t
checksum(const struct in6_addr *src, const struct in6_addr *dst, const void *data, size_t len) {
    uint32_t checksum = 0;
    union {
        uint32_t dword;
        uint16_t word[2];
        uint8_t byte[4];
    } temp;

    checksum += src->s6_addr16[0];
    checksum += src->s6_addr16[1];
    checksum += src->s6_addr16[2];
    checksum += src->s6_addr16[3];
    checksum += src->s6_addr16[4];
    checksum += src->s6_addr16[5];
    checksum += src->s6_addr16[6];
    checksum += src->s6_addr16[7];

    checksum += dst->s6_addr16[0];
    checksum += dst->s6_addr16[1];
    checksum += dst->s6_addr16[2];
    checksum += dst->s6_addr16[3];
    checksum += dst->s6_addr16[4];
    checksum += dst->s6_addr16[5];
    checksum += dst->s6_addr16[6];
    checksum += dst->s6_addr16[7];

    temp.dword = htonl(len);
    checksum += temp.word[0];
    checksum += temp.word[1];

    temp.byte[0] = 0;
    temp.byte[1] = 0;
    temp.byte[2] = 0;
    temp.byte[3] = 58;
    checksum += temp.word[0];
    checksum += temp.word[1];

    while (len > 1) {
        checksum += *((const uint16_t *)data);
        data = (const uint16_t *)data + 1;
        len -= 2;
    }

    if (len > 0)
        checksum += *((const uint8_t *)data);
    
    while (checksum >> 16 != 0)
        checksum = (checksum & 0xffff) + (checksum >> 16);

    checksum = ~checksum;

    return (uint16_t)checksum;
}

int
parse(const void *pkt, size_t len) {
    size_t parsed_len = 0;
    if (len < sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "Did not receive complete ICMP packet\n");
        return -1;
    }
    const struct icmp6_hdr *hdr = (const struct icmp6_hdr *)pkt;


    switch(hdr->icmp6_type) {
        case ND_ROUTER_ADVERT:
            if (len < sizeof(struct nd_router_advert)) {
                fprintf(stderr, "Did not receive complete ICMP packet\n");
                return -1;
            }
            const struct nd_router_advert *ra = (const struct nd_router_advert *)pkt;

            if (ra->nd_ra_code != 0) {
                fprintf(stderr, "Nonzero ICMP code,  ignoring\n");
                return -1;
            }

            fprintf(stderr, "RA\ntype:\t%d\ncode:\t%d\nchsum:\t%x\nhoplimit\t%d\nmanaged\t%d\nother\t%d\nlifetime\t%d\nreachable\t%d\nretransmit\t%d\n",
                    ra->nd_ra_type,
                    ra->nd_ra_code,
                    ra->nd_ra_cksum,
                    ra->nd_ra_curhoplimit,
                    ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED, 
                    ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER,
                    ntohs(ra->nd_ra_router_lifetime),
                    ntohl(ra->nd_ra_reachable),
                    ntohl(ra->nd_ra_retransmit));

            parsed_len = sizeof(struct nd_router_advert);

            /* Now read the options */
            while (len - parsed_len >= sizeof(struct nd_opt_hdr)) {
                const struct nd_opt_hdr *opt = (const struct nd_opt_hdr *)((const char *)ra + parsed_len);
                if (opt->nd_opt_len == 0) {
                    fprintf(stderr, "Invalid length\n");
                    return -1;
                }
                if (len - parsed_len < opt->nd_opt_len * 8) {
                    fprintf(stderr, "Did not receive complete ICMP packet option\n");
                    return -1;
                }

                switch(opt->nd_opt_type) {
                    case ND_OPT_SOURCE_LINKADDR:
                        /* Source Link layer address */
                        break;
                    case ND_OPT_PREFIX_INFORMATION:
                        if (len - parsed_len < sizeof(struct nd_opt_prefix_info)) {
                            fprintf(stderr, "Did not receive complete ICMP packet option\n");
                            return -1;
                        }
                        const struct nd_opt_prefix_info *pi = (const struct nd_opt_prefix_info *)opt;

                        char prefix_str[INET6_ADDRSTRLEN];

                        if (inet_ntop(AF_INET6, &(pi->nd_opt_pi_prefix), prefix_str, INET6_ADDRSTRLEN) == NULL) {
                            perror("inet_ntop()");
                            return -1;
                        }

                        fprintf(stderr, "Prefix Info\nprefix\t%s/%d\nonlink\t%d\nauto\t%d\nraddr\t%d\nvalid_time\t%d\npreferred_time\t%d\n",
                                prefix_str,
                                pi->nd_opt_pi_prefix_len,
                                pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK,
                                pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO,
                                pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_RADDR,
                                ntohl(pi->nd_opt_pi_valid_time),
                                ntohl(pi->nd_opt_pi_preferred_time));
                        break;
                    case ND_OPT_MTU:
                        if (len - parsed_len < sizeof(struct nd_opt_mtu)) {
                            fprintf(stderr, "Did not receive complete ICMP packet option\n");
                            return -1;
                        }
                        const struct nd_opt_mtu *mtu = (const struct nd_opt_mtu *)opt;

                        fprintf(stderr, "MTU %d\n", ntohl(mtu->nd_opt_mtu_mtu));
                        break;
                    default:
                        fprintf(stderr, "Unsupported option %d\n", opt->nd_opt_type);
                        hexdump(pkt, len);
                        return -1;
                }
                parsed_len += opt->nd_opt_len * 8;
            }

            if (parsed_len != len) {
                fprintf(stderr, "%zd trailing bytes\n", len - parsed_len);
                return -1;
            }

            break;
        default:
            fprintf(stderr, "Unsupported ICMP type\n");
    }
    return 0;
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
