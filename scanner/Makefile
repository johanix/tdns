PROG:=tdns-scanner

GOOS ?= $(shell uname -s | tr A-Z a-z)
GO:=CGO_ENABLED=1 go
include ../utils/Makefile.common

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/libexec/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
