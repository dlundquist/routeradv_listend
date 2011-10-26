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
#include "icmp.h"


struct RouterAdvertisment {
    /* unfortunatly we do not have a nice symetry here */
    struct sockaddr_in6 src_addr;
    struct in6_addr dst_addr;
    int hop_limit;
    int ifindex;
    struct timeval timestamp;
    int lifetime;
    int reachable;
    int retransmit;
};

static void apply_icmp_filter(int);
static void multicast_listen(int, const char *, int);
static void setup_ancillary_data(int);
static void parse_ancillary_data(struct RouterAdvertisment *, struct msghdr *);
static uint16_t checksum(const struct in6_addr *, const struct in6_addr *, int, const void *, size_t);
static void parse_icmp_data(struct RouterAdvertisment *, const void *, size_t);

int
init_icmp_socket(int ifindex) {
    int sockfd;

    sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sockfd < 0) {
        perror("socket()");
        return 1;
    }

    apply_icmp_filter(sockfd);

    multicast_listen(sockfd, "ff02::1", ifindex);

    setup_ancillary_data(sockfd);

    return sockfd;
}

void
recv_icmp_msg(int sockfd) {
    char data_buf[256];
    char control_buf[256];
    struct RouterAdvertisment ra;
    struct msghdr m;
    struct iovec iov;
    ssize_t len;

    /* Clear out our data structures */
    memset(data_buf, 0, sizeof(data_buf));
    memset(control_buf, 0, sizeof(control_buf));
    memset(&ra, 0, sizeof(ra));
    memset(&m, 0, sizeof(m));
    memset(&iov, 0, sizeof(iov));

    /* Setup for recvmsg */
    m.msg_name = &ra.src_addr;
    m.msg_namelen = sizeof(ra.src_addr);
    iov.iov_base = data_buf;
    iov.iov_len = sizeof(data_buf);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = (void *)control_buf;
    m.msg_controllen = sizeof(control_buf);
    m.msg_flags = 0;

    len = recvmsg(sockfd, &m, 0);
    if (len < 0) {
        perror("recvmsg()");
        return;
    }

    parse_ancillary_data(&ra, &m);

    if (! IN6_IS_ADDR_LINKLOCAL(&ra.src_addr.sin6_addr)) {
        fprintf(stderr, "Not link local, ignoring\n");
        return;
    }

    if (ra.hop_limit != 255) {
        fprintf(stderr, "Hop limit is not 255, ignoring\n");
        return;
    }

    if (checksum(&ra.src_addr.sin6_addr, &ra.dst_addr, IPPROTO_ICMPV6, data_buf, len) != 0) {
        fprintf(stderr, "Invalid ICMP checksum, ignoring\n");
        return;
    }

    parse_icmp_data(&ra, data_buf, sizeof(data_buf));

}

static void
apply_icmp_filter(int sockfd) {
    struct icmp6_filter filter;

    memset(&filter, 0, sizeof(filter));
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
    if (setsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) != 0) {
        perror("setsockopt()");
        return;
    }
}

static void
multicast_listen(int sockfd, const char * addr_str, int ifindex) {
    struct ipv6_mreq mreq;  /* Multicast address join structure */

    memset(&mreq, 0, sizeof(mreq));

    mreq.ipv6mr_interface = ifindex;
    if (inet_pton(AF_INET6, addr_str, &mreq.ipv6mr_multiaddr) != 1) {
        perror("inet_pton()");
        return;
    }
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) != 0) {
        perror("setsockopt()");
        return;
    }
}

static void
setup_ancillary_data(int sockfd) {
    int on = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) != 0) {
        perror("setsockopt()");
    }
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) != 0) {
        perror("setsockopt()");
    }
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) != 0) {
        perror("setsockopt()");
    }
}

static void
parse_ancillary_data(struct RouterAdvertisment *ra, struct msghdr *m) {
    struct cmsghdr *cmsg;
    const struct in6_pktinfo *pktinfo;

    for (cmsg = CMSG_FIRSTHDR(m); cmsg != NULL; cmsg = CMSG_NXTHDR(m, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP)
            memcpy(&ra->timestamp, CMSG_DATA(cmsg), sizeof(ra->timestamp));

        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
            ra->hop_limit = *(int *)CMSG_DATA(cmsg);

        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            pktinfo = (const struct in6_pktinfo *)CMSG_DATA(cmsg);
            ra->ifindex = pktinfo->ipi6_ifindex;
            memcpy(&ra->dst_addr, &pktinfo->ipi6_addr, sizeof(ra->dst_addr));
        }
    }
}

static uint16_t
checksum(const struct in6_addr *src, const struct in6_addr *dst, int proto, const void *data, size_t len) {
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
    temp.byte[3] = (uint8_t)proto;
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

static void
parse_icmp_data(struct RouterAdvertisment *adv, const void *pkt, size_t pkt_len) {
    size_t parsed_len = 0;

    if (pkt_len < sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "Did not receive complete ICMP packet\n");
        return;
    }
    const struct icmp6_hdr *hdr = (const struct icmp6_hdr *)pkt;

    if (hdr->icmp6_type != ND_ROUTER_ADVERT) {
        /* not a RA */
        return;
    }

    if (pkt_len < sizeof(struct nd_router_advert)) {
        fprintf(stderr, "Did not receive complete ICMP packet\n");
        return;
    }
    const struct nd_router_advert *ra = (const struct nd_router_advert *)pkt;

    if (ra->nd_ra_code != 0) {
        fprintf(stderr, "Nonzero ICMP code,  ignoring\n");
        return;
    }

    adv->lifetime = ntohs(ra->nd_ra_router_lifetime);
    adv->reachable = ntohl(ra->nd_ra_reachable);
    adv->retransmit = ntohl(ra->nd_ra_retransmit);

    parsed_len = sizeof(struct nd_router_advert);

    /* Now read the options */
    while (pkt_len - parsed_len >= sizeof(struct nd_opt_hdr)) {
        const struct nd_opt_hdr *opt = (const struct nd_opt_hdr *)((const char *)ra + parsed_len);
        if (opt->nd_opt_len == 0) {
            fprintf(stderr, "Invalid length\n");
            return;
        }
        if (pkt_len - parsed_len < opt->nd_opt_len * 8) {
            fprintf(stderr, "Did not receive complete ICMP packet option\n");
            return;
        }

        /*
        switch(opt->nd_opt_type) {
            case ND_OPT_SOURCE_LINKADDR:
                break;
            case ND_OPT_PREFIX_INFORMATION:
                if (pkt_len - parsed_len < sizeof(struct nd_opt_prefix_info)) {
                    fprintf(stderr, "Did not receive complete ICMP packet option\n");
                    return;
                }
                const struct nd_opt_prefix_info *pi = (const struct nd_opt_prefix_info *)opt;

                break;
            case ND_OPT_MTU:
                if (pkt_len - parsed_len < sizeof(struct nd_opt_mtu)) {
                    fprintf(stderr, "Did not receive complete ICMP packet option\n");
                    return;
                }
                const struct nd_opt_mtu *mtu = (const struct nd_opt_mtu *)opt;

                break;
            default:
                fprintf(stderr, "Unsupported option %d\n", opt->nd_opt_type);
                return;
        }
        */
        parsed_len += opt->nd_opt_len * 8;
    }

    if (parsed_len != pkt_len) {
        fprintf(stderr, "%zd trailing bytes\n", pkt_len - parsed_len);
        return;
    }

    return;
}
