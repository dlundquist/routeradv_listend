NAME = routeradv_listend
VERSION = 0.2
RELEASE = 3
DISTBASENAME = ${NAME}-${VERSION}-${RELEASE}
DISTFILENAME = ${DISTBASENAME}.tar.gz


all: 
	make -C src all

.PHONY: clean all

clean:
	rm ${DISTFILENAME}
	make -C src clean

dist: ${DISTFILENAME}

${DISTFILENAME}: dist_files
	tar -c -T dist_files --transform 's!^.!${DISTBASENAME}!' -f ${DISTFILENAME} -z

