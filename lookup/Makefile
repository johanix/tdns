PROG:=tdns-lookup

GOOS ?= $(shell uname -s | tr A-Z a-z)
# We need CGO because we now need sqlite also in tdns-cli
# GO:=GOOS=$(GOOS) CGO_ENABLED=1 go
GO:=CGO_ENABLED=1 go
include ../utils/Makefile.common

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/bin/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete

