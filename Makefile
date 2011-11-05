NAME = routeradv_listend
VERSION = 0.2
RELEASE = 3
DISTBASENAME = ${NAME}-${VERSION}-${RELEASE}
DISTFILENAME = ${DISTBASENAME}.tar.gz
PREFIX = ${DESTDIR}/


all: 
	make -C src all

.PHONY: clean all

clean:
	rm -f ${DISTFILENAME}
	make -C src clean

dist: ${DISTFILENAME}

${DISTFILENAME}: dist_files
	tar -c -T dist_files --transform 's!^.!${DISTBASENAME}!' -f ${DISTFILENAME} -z

install: all
	install -D src/routeradv_listend ${PREFIX}/sbin/routeradv_listend
