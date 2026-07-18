PROG:=tdns-agent

GOOS ?= $(shell uname -s | tr A-Z a-z)
GO:=CGO_ENABLED=1 go
include ../../utils/Makefile.common

# Shared ALGREPO cache + per-app C-library env for algs.list.
#   tdns-genalgs --algrepo=<dnssec-algorithms root> --list=algs.list --out=.
-include ../algs-env.mk
-include algs-libs.mk

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/libexec/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete

