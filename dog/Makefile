PROG:=dog

GOOS ?= $(shell uname -s | tr A-Z a-z)
# GO:=GOOS=$(GOOS) CGO_ENABLED=0 go
GO:=CGO_ENABLED=0 go
include ../utils/Makefile.common

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/bin/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
