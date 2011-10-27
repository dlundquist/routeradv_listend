#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset() */
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <net/if.h> /* if_nametoindex() */
#include "icmp.h"
#include "routers.h"


static void usage();
static void daemonize(const char *, int);


int
main(int argc, char **argv) {
    int opt, sockfd;
    int background_flag = 1;
    int if_index = 0;
    fd_set rfds;
    struct timeval timeout;

    while ((opt = getopt(argc, argv, "fi:")) != -1) {
        switch (opt) {
            case 'f': /* foreground */
                background_flag = 0;
                break;
            case 'i':
                if_index = if_nametoindex(optarg);
                break;
            default: 
                usage();
                exit(EXIT_FAILURE);
        }
    }


    sockfd = init_icmp_socket(if_index);
    if (sockfd < 0)
        return -1;

    
    if (background_flag)
        daemonize(argv[0], sockfd);

    openlog(argv[0], LOG_CONS, LOG_DAEMON);

    init_routers();

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = next_timeout();

        if (select(sockfd + 1, &rfds, NULL, NULL, &timeout) < 0) {
            /* select() might have failed because we received a signal, so we need to check */
            if (errno != EINTR) {
                perror("select");
                return 1;
            }
            /* handle signals */
            continue; /* our file descriptor sets are undefined, so select again */
        }


        if (FD_ISSET (sockfd, &rfds))
            recv_icmp_msg(sockfd);

        handle_routers();
    }


    return 0;
}

static void
daemonize(const char *cmd, int sockfd) {
    int i, fd0, fd1, fd2;
    pid_t pid;

    umask(0);

    if ((pid = fork()) < 0) {
        perror("fork()");
        exit(1);
    } else if (pid != 0) {
        exit(0);
    }

    if (chdir("/") < 0) {
        perror("chdir()");
        exit(1);
    }

    if (setsid() < 0) {
        perror("setsid()");
        exit(1);
    }

    for (i = sysconf(_SC_OPEN_MAX); i >= 0; i--)
        if (i != sockfd)
            close(i);

    fd0 = open("/dev/null", O_RDWR);
    fd1 = dup(fd0);
    fd2 = dup(fd0);

    openlog(cmd, LOG_CONS, LOG_DAEMON);
    if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
        fprintf(stderr, "Unexpected file descriptors\n");
        exit(2);
    }

    pid = fork();
    if (pid < 0) {
        perror("fork()");
        exit(1);
    } else if (pid > 0) {
        exit(0);
    }
}

static void
usage() {
    fprintf(stderr, "Usage: routeradv_listend [-f] [-i <interface>]\n");
}
