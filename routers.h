#ifndef ROUTERS_H
#define ROUTERS_H 1

#include <netinet/in.h>
#include <time.h>
#include <sys/queue.h>

struct Router {
    struct in6_addr addr;
    time_t valid_until;
    int if_index;
    SLIST_ENTRY(Router) entries;
};

void init_routers();
void update_router(const struct in6_addr *, int, time_t);
time_t next_timeout();
void handle_routers();

#endif
