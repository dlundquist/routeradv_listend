#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include "gateway.h"

/* Initial version, future version will use a NETLINK socket */

void add_gateway(const struct in6_addr * addr, int if_index) {
    char cmd_string[256];
    char addr_str[INET6_ADDRSTRLEN];
    char if_name[IF_NAMESIZE];
    int ret;

    if (inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str)) == NULL) {
        syslog(LOG_CRIT, "inet_ntop: %s", strerror(errno));
        return;
    }

    if (if_indextoname(if_index, if_name) == NULL) {
        syslog(LOG_CRIT, "if_indextoname: %s", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "adding default route via %s", addr_str);

    if (snprintf(cmd_string, sizeof(cmd_string), "/sbin/ip -6 route add ::/0 via %s dev %s", addr_str, if_name) >= (ssize_t)sizeof(cmd_string)) {
        syslog(LOG_CRIT, "exceeded command string length");
        return;
    }
    
    ret = system(cmd_string);
    if (ret != 0) {
        syslog(LOG_CRIT, "%s returned %d", cmd_string, ret);
    }
}

void remove_gateway(const struct in6_addr *addr, int if_index) {
    char cmd_string[256];
    char addr_str[INET6_ADDRSTRLEN];
    char if_name[IF_NAMESIZE];
    int ret;

    if (inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str)) == NULL) {
        syslog(LOG_CRIT, "inet_ntop: %s", strerror(errno));
        return;
    }

    if (if_indextoname(if_index, if_name) == NULL) {
        syslog(LOG_CRIT, "if_indextoname: %s", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "removing default route via %s", addr_str);

    if (snprintf(cmd_string, sizeof(cmd_string), "/sbin/ip -6 route del ::/0 via %s dev %s", addr_str, if_name) >= (ssize_t)sizeof(cmd_string)) {
        syslog(LOG_CRIT, "exceeded command string length");
        return;
    }
    
    ret = system(cmd_string);
    if (ret != 0) {
        syslog(LOG_CRIT, "%s returned %d", cmd_string, ret);
    }
}
