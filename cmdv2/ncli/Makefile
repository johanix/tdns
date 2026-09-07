PROG:=tdns-ncli

# CGO for the same reason tdns-cli needs it: sqlite, for the --offline
# keystore commands.
GO:=CGO_ENABLED=1 go
include ../../utils/Makefile.common

# Shared ALGREPO cache + per-app libs fragment (empty for metadata-only cli).
-include ../algs-env.mk
-include algs-libs.mk

.PHONY: clean install

# /usr/local/bin, alongside tdns-cli rather than replacing it: for the whole
# parallel-running period both binaries are installed and either may be used.
# See docs/2026-09-07-cli-multi-instance-design.md.
install:
	install -s -b -c ${PROG} /usr/local/bin/

# No `pkg` target yet, and no entry in ../Makefile's pkg list: tdns-ncli is
# not shipped as a NetBSD package until it graduates. Build and copy it by
# hand while it is being evaluated.

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
