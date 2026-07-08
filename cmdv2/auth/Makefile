PROG:=tdns-auth

# GO:=GOWORK=/Users/johani/src/git/tdns/go.work CGO_ENABLED=1 go
GO:= CGO_ENABLED=1 go

include ../../utils/Makefile.common

# Generated algorithm build environment: PKG_CONFIG_PATH for the C-backed
# algorithms selected in algs.list, plus ALGREPO (the dnssec-algorithms
# checkout path) so `make` can re-run genalgs when algs.list changes (see
# the generate rule in Makefile.common). Written by tdns-genalgs alongside
# metadata_algs.go / registered_algs.go. -include (not include): absent on
# a fresh tree until genalgs has been run once with --algrepo.
-include algs-env.mk

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/libexec/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete

