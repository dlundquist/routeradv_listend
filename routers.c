#include <stdio.h>
#include <stdlib.h> /* calloc() */
#include <string.h> /* memcpy() */
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "routers.h"
#include "gateway.h"

#define MIN(X,Y) ((X) > (Y) ? (Y) : (X))


static SLIST_HEAD(, Router) *routers;


static struct Router *find_router(const struct in6_addr *, int);
static struct Router *add_router(const struct in6_addr *, int);
static void remove_router(struct Router *);
static void print_routers();


#ifndef SLIST_FOREACH_SAFE
#define SLIST_FOREACH_SAFE(var, head, field, tvar)          \
    for ((var) = SLIST_FIRST((head));               \
        (var) && ((tvar) = SLIST_NEXT((var), field), 1);        \
        (var) = (tvar))
#endif

void
init_routers() {
    routers = calloc(1, sizeof(*routers));
    if (routers == NULL) {
        syslog(LOG_CRIT, "calloc(): %s", strerror(errno));
        exit(1);
    }

    SLIST_INIT(routers);
}

void
update_router(const struct in6_addr *addr, int if_index, time_t valid_until) {
    struct Router *r;

    r = find_router(addr, if_index);
    if (r == NULL)
        r = add_router(addr, if_index);


    r->valid_until = valid_until;
}

void
handle_routers() {
    struct Router *iter, *temp;
    time_t now;

    print_routers();

    time(&now);

    SLIST_FOREACH_SAFE(iter, routers, entries, temp) {
        if (iter->valid_until < now)
            remove_router(iter);
    }
}

time_t
next_timeout() {
    struct Router *iter;
    time_t now, min_valid_until;

    /* Start with a min value of one hours from now */
    min_valid_until = time(&now) + 3600;

    SLIST_FOREACH(iter, routers, entries) {
        min_valid_until = MIN(min_valid_until, iter->valid_until);
    }
        
    return min_valid_until - now;
}

static struct Router *
find_router(const struct in6_addr *addr, int if_index) {
    struct Router *iter;

    SLIST_FOREACH(iter, routers, entries) {
        if (IN6_ARE_ADDR_EQUAL(&iter->addr, addr) && iter->if_index == if_index)
            return iter;
    }
    return NULL;
}

static struct Router *
add_router(const struct in6_addr *addr, int if_index) {
    struct Router *r;

    r = calloc(1, sizeof(struct Router));
    if (r == NULL) {
        syslog(LOG_CRIT, "calloc(): %s", strerror(errno));
        return r;
    }

    memcpy(&r->addr, addr, sizeof(struct in6_addr));
    r->if_index = if_index;

    add_gateway(&r->addr, if_index);

    SLIST_INSERT_HEAD(routers, r, entries);

    return r;
}

static void
remove_router(struct Router *router) {
    SLIST_REMOVE(routers, router, Router, entries);

    remove_gateway(&router->addr, router->if_index);

    free(router);
}

static void print_routers() {
    struct Router *iter;
    char addr_str[INET6_ADDRSTRLEN];
    char if_name[IF_NAMESIZE];

    printf("Routers:\n");
    SLIST_FOREACH(iter, routers, entries) {
        if (inet_ntop(AF_INET6, &iter->addr, addr_str, sizeof(addr_str)) == NULL) {
            syslog(LOG_CRIT, "inet_ntop: %s", strerror(errno));
            return;
        }

        if (if_indextoname(iter->if_index, if_name) == NULL) {
            syslog(LOG_CRIT, "if_indextoname: %s", strerror(errno));
            return;
        }
        printf("\t%s\t%ld\t%s\n", addr_str, iter->valid_until, if_name);
    }
}
