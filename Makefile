CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -D_GNU_SOURCE

all: routeradv_listend

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $<

routeradv_listend: routeradv_listend.o icmp.o routers.o gateway.o
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean all

clean:
	rm -f *.o routeradv_listend

