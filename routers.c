#include <stdlib.h> /* calloc() */
#include <syslog.h>
#include <string.h> /* memcpy() */
#include "routers.h"
#include "gateway.h"

#define MIN(X,Y) ((X) > (Y) ? (Y) : (X))


static SLIST_HEAD(, Router) *routers;


static struct Router *find_router(const struct in6_addr *);
static struct Router *add_router(const struct in6_addr *);
static void remove_router(struct Router *);


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
        syslog(LOG_CRIT, "calloc failed");
        exit(1);
    }

    SLIST_INIT(routers);
}

void
update_router(const struct in6_addr *addr, time_t valid_until) {
    struct Router *r;

    r = find_router(addr);
    if (r == NULL)
        r = add_router(addr);


    r->valid_until = valid_until;
}

void
handle_routers() {
    struct Router *iter, *temp;
    time_t now;

    time(&now);

    SLIST_FOREACH_SAFE(iter, routers, entries, temp) {
        if (iter->valid_until < now)
            remove_router(iter);
    }
}

time_t
next_timeout() {
    struct Router *iter;
    time_t min_valid_until;

    /* Start with a min value of one hours from now */
    time(&min_valid_until);
    min_valid_until += 3600;

    SLIST_FOREACH(iter, routers, entries) {
        min_valid_until = MIN(min_valid_until, iter->valid_until);
    }
        
    return min_valid_until;
}

static struct Router *
find_router(const struct in6_addr *addr) {
    struct Router *iter;

    SLIST_FOREACH(iter, routers, entries) {
        if (IN6_ARE_ADDR_EQUAL(&iter->addr, addr))
            return iter;
    }
    return NULL;
}

static struct Router *
add_router(const struct in6_addr *addr) {
    struct Router *r;

    r = calloc(1, sizeof(struct Router));
    if (r == NULL) {
        syslog(LOG_CRIT, "calloc failed");
        return r;
    }

    memcpy(&r->addr, addr, sizeof(struct in6_addr));

    add_gateway(&r->addr);

    SLIST_INSERT_HEAD(routers, r, entries);

    return r;
}

static void
remove_router(struct Router *router) {
    SLIST_REMOVE(routers, router, Router, entries);

    remove_gateway(&router->addr);

    free(router);
}
