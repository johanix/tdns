PROG:=dog

GOOS ?= $(shell uname -s | tr A-Z a-z)
# CGO is required: dog validates RRSIGs across the full algorithm range,
# so it links the C-backed algorithms (liboqs/sqisign/qruov) selected in
# algs.list. This drops dog's former static/no-cgo build.
GO:=CGO_ENABLED=1 go
include ../../utils/Makefile.common

# Shared ALGREPO cache + per-app C-library env for algs.list.
#   tdns-genalgs --algrepo=<dnssec-algorithms root> --list=algs.list --out=.
-include ../algs-env.mk
-include algs-libs.mk

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/bin/

# No "pkg" target here on purpose: dog ships inside the tdns-cli package, whose
# recipe (in ../../utils/Makefile.common) builds and installs this directory
# before packing. A "pkg" alias here would build that same package from a
# directory that cannot say whether tdns-cli itself is current.

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
