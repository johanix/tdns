PROG:=tdns-server

GOOS ?= $(shell uname -s | tr A-Z a-z)
# GO:=GOWORK=/Users/johani/src/git/tdns/go.work CGO_ENABLED=1 go
GO:= CGO_ENABLED=1 go

include ../utils/Makefile.common

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/libexec/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete

