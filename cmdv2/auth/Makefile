PROG:=tdns-auth

# GO:=GOWORK=/Users/johani/src/git/tdns/go.work CGO_ENABLED=1 go
GO:= CGO_ENABLED=1 go

include ../../utils/Makefile.common

# Shared ALGREPO cache (cmdv2/algs-env.mk) + per-app C-library env
# (algs-libs.mk). Written by tdns-genalgs; -include so a fresh tree is OK
# until genalgs has been run once with --algrepo.
-include ../algs-env.mk
-include algs-libs.mk

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/libexec/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete

