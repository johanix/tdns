PROG:=tdns-imr

GOOS ?= $(shell uname -s | tr A-Z a-z)
# CGO is required: the algorithms selected in algs.list are C-backed
# (liboqs/sqisign/qruov), linked via the genalgs-generated files.
GO:= CGO_ENABLED=1 go
include ../../utils/Makefile.common

# Shared ALGREPO cache + per-app C-library env for algs.list.
#   tdns-genalgs --algrepo=<dnssec-algorithms root> --list=algs.list --out=.
-include ../algs-env.mk
-include algs-libs.mk

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/bin/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete

