.PHONY: all v2 genalgs version clean install install-dirs check-root tarball pkg

# all apps in this directory
all: v2

# tdns-genalgs must exist before any app's generate rule runs.
# Algorithm selection is per-app via algs.list (see utils/Makefile.common);
# there are no WITH_LIBOQS / WITH_SQISIGN / WITH_QRUOV make knobs.
genalgs:
	$(MAKE) -C ./genalgs/

version: genalgs
	$(MAKE) -C ./auth/ version
	$(MAKE) -C ./cli/ version
	$(MAKE) -C ./agent/ version
	$(MAKE) -C ./imr/ version
	$(MAKE) -C ./dog/ version

# experimental version of major apps
v2: genalgs
	$(MAKE) -C ./auth/
	$(MAKE) -C ./cli/
	$(MAKE) -C ./agent/
	$(MAKE) -C ./imr/
	$(MAKE) -C ./dog/

clean:
	$(MAKE) -C ./genalgs/ clean
	$(MAKE) -C ./auth/ clean
	$(MAKE) -C ./cli/ clean
	$(MAKE) -C ./agent/ clean
	$(MAKE) -C ./imr/ clean
	$(MAKE) -C ./dog/ clean

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Must run as root"; exit 1; fi

install-dirs: check-root
	mkdir -p /usr/local/bin /usr/local/libexec

install: check-root install-dirs
	$(MAKE) -C ./auth/ install
	$(MAKE) -C ./cli/ install
	$(MAKE) -C ./agent/ install
	$(MAKE) -C ./imr/ install
	$(MAKE) -C ./dog/ install

# NetBSD binary packages -- four of them, one per component. See
# ../utils/mkpkg.sh for the reasoning and ../utils/Makefile.common for the
# rules. Each app's "pkg" target builds, installs and packs its own binaries,
# so this needs root for the same reason "install" does.
#
# The .tgz files are left in the app directories. Publishing is deliberately
# NOT a target here: they go into a per-osrelease tree
# (/var/tmp/axfr.net/ftpfiles/pkg/amd64-<osrelease>/) on a lab dom0, and the
# same file is copied into EVERY such tree -- OS_VERSION mismatch only warns.
# Which trees exist is a property of the lab, not of this repo.
#
# cli/ also builds and installs dog/, so dog is not listed separately.
pkg: check-root install-dirs genalgs
	$(MAKE) -C ./auth/ pkg
	$(MAKE) -C ./agent/ pkg
	$(MAKE) -C ./imr/ pkg
	$(MAKE) -C ./cli/ pkg

TAR_VERSION:=v2
TARFILE:=/tmp/usr.local.tdns.$(TAR_VERSION).tar.gz
TAR_CONTENTS:=bin/tdns-cli bin/dog \
	libexec/tdns-imr libexec/tdns-auth \
	libexec/tdns-agent

tarball: install
	cd /usr/local && tar -czf $(TARFILE) $(TAR_CONTENTS)
