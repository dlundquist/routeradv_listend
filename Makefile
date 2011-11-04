CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -D_GNU_SOURCE

all: routeradv_listend

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $<

routeradv_listend: routeradv_listend.o icmp.o routers.o gateway.o
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean all install

clean:
	rm -f *.o routeradv_listend

install: routeradv_listend routeradv_listend.init
	install routeradv_listend.init /etc/init.d/routeradv_listend
	install routeradv_listend /sbin/routeradv_listend

