#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "gateway.h"

/* Initial version, future version will use a NETLINK socket */

void add_gateway(const struct in6_addr * addr) {
    char cmd_string[256];
    char addr_str[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str)) == NULL) {
        perror("inet_ntop()");
        return;
    }

    if (snprintf(cmd_string, sizeof(cmd_string), "/sbin/route -A inet6 add -net ::/0 gw %s", addr_str) >= sizeof(cmd_string)) {
        perror("exceeded command string length");
        return;
    }
    
    if (system(cmd_string) != 0) {
        perror("error adding route");
    }
}

void remove_gateway(const struct in6_addr *addr) {
    char cmd_string[256];
    char addr_str[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str)) == NULL) {
        perror("inet_ntop()");
        return;
    }

    if (snprintf(cmd_string, sizeof(cmd_string), "/sbin/route -A inet6 del -net ::/0 gw %s", addr_str) >= sizeof(cmd_string)) {
        perror("exceeded command string length");
        return;
    }
    
    if (system(cmd_string) != 0) {
        perror("error removing route");
    }
}
