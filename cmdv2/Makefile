.PHONY: all v2 version clean install install-dirs check-root tarball

# WITH_LIBOQS=1 enables the liboqs-backed PQ algorithms (Falcon-512,
# MAYO-1, SNOVA-24_5_4) in agent/auth/imr. See utils/Makefile.common.
# Passed explicitly on each recursive $(MAKE) call below — works on
# both GNU make and NetBSD bmake (bmake's `export` requires VAR=value
# syntax, which differs from GNU make's bare-name form).
WITH_LIBOQS ?= 0
MAKE_VARS = WITH_LIBOQS=$(WITH_LIBOQS)

# all apps in this directory
all: v2

version:
	$(MAKE) $(MAKE_VARS) -C ./auth/ version
	$(MAKE) $(MAKE_VARS) -C ./cli/ version
	$(MAKE) $(MAKE_VARS) -C ./agent/ version
	$(MAKE) $(MAKE_VARS) -C ./imr/ version
	$(MAKE) $(MAKE_VARS) -C ./dog/ version

# experimental version of major apps
v2:
	$(MAKE) $(MAKE_VARS) -C ./auth/
	$(MAKE) $(MAKE_VARS) -C ./cli/
	$(MAKE) $(MAKE_VARS) -C ./agent/
	$(MAKE) $(MAKE_VARS) -C ./imr/
	$(MAKE) $(MAKE_VARS) -C ./dog/

clean:
	$(MAKE) $(MAKE_VARS) -C ./auth/ clean
	$(MAKE) $(MAKE_VARS) -C ./cli/ clean
	$(MAKE) $(MAKE_VARS) -C ./agent/ clean
	$(MAKE) $(MAKE_VARS) -C ./imr/ clean
	$(MAKE) $(MAKE_VARS) -C ./dog/ clean

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Must run as root"; exit 1; fi

install-dirs: check-root
	mkdir -p /usr/local/bin /usr/local/libexec

install: check-root install-dirs
	$(MAKE) $(MAKE_VARS) -C ./auth/ install
	$(MAKE) $(MAKE_VARS) -C ./cli/ install
	$(MAKE) $(MAKE_VARS) -C ./agent/ install
	$(MAKE) $(MAKE_VARS) -C ./imr/ install
	$(MAKE) $(MAKE_VARS) -C ./dog/ install

TAR_VERSION:=v2
TARFILE:=/tmp/usr.local.tdns.$(TAR_VERSION).tar.gz
TAR_CONTENTS:=bin/tdns-cli bin/dog \
	libexec/tdns-imr libexec/tdns-auth \
	libexec/tdns-agent

tarball: install
	cd /usr/local && tar -czf $(TARFILE) $(TAR_CONTENTS)
