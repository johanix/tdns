PROG:=sidecar-cli

GOFLAGS:=-ldflags "-X app.version=$(VERSION)-$(COMMIT) -v"

# There is now sqlite in ../music/ so we need CGO=1, unfortunately.
GO:=CGO_ENABLED=1 go

include ../utils/Makefile.common

install:
	@mkdir -p ../etc ../sbin
#	install -s -b ${PROG} ../sbin/
	if [ ! -e ../etc/${CONFIG} ] ; then install -c ${CONFIG}.sample ../etc/${CONFIG}; fi

clean:
	rm -f $(PROG)
	rm -f *~ */*~


