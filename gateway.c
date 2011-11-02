#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include "gateway.h"

/* Initial version, future version will use a NETLINK socket */

void add_gateway(const struct in6_addr * addr) {
    char cmd_string[256];
    char addr_str[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str)) == NULL) {
        syslog(LOG_CRIT, "inet_ntop: %s", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "adding default route via %s", addr_str);

    if (snprintf(cmd_string, sizeof(cmd_string), "/sbin/route -A inet6 add -net ::/0 gw %s", addr_str) >= (ssize_t)sizeof(cmd_string)) {
        syslog(LOG_CRIT, "exceeded command string length");
        return;
    }
    
    if (system(cmd_string) != 0) {
        syslog(LOG_CRIT, "error adding default route via %s", addr_str);
    }
}

void remove_gateway(const struct in6_addr *addr) {
    char cmd_string[256];
    char addr_str[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str)) == NULL) {
        syslog(LOG_CRIT, "inet_ntop: %s", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "deletting default route via %s", addr_str);

    if (snprintf(cmd_string, sizeof(cmd_string), "/sbin/route -A inet6 del -net ::/0 gw %s", addr_str) >= (ssize_t)sizeof(cmd_string)) {
        syslog(LOG_CRIT, "exceeded command string length");
        return;
    }
    
    if (system(cmd_string) != 0) {
        syslog(LOG_CRIT, "error removing default route via %s", addr_str);
    }
}
