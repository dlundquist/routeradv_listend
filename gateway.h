#ifndef GATEWAY_H
#define GATEWAY_H

void add_gateway(const struct in6_addr *, int);
void remove_gateway(const struct in6_addr *, int);

#endif
