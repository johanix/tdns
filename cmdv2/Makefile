.PHONY: all v2 clean install install-dirs check-root tarball

# all apps in this directory
all: v2

# experimental version of major apps
v2:
	$(MAKE) -C ./authv2/
	$(MAKE) -C ./cliv2/
	$(MAKE) -C ./agentv2/
	$(MAKE) -C ./combinerv2/
	$(MAKE) -C ./imrv2/
	$(MAKE) -C ./dogv2/

clean:
	$(MAKE) -C ./authv2/ clean
	$(MAKE) -C ./cliv2/ clean
	$(MAKE) -C ./agentv2/ clean
	$(MAKE) -C ./combinerv2/ clean
	$(MAKE) -C ./imrv2/ clean
	$(MAKE) -C ./dogv2/ clean

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Must run as root"; exit 1; fi

install-dirs: check-root
	mkdir -p /usr/local/bin /usr/local/libexec

install: check-root install-dirs
	$(MAKE) -C ./authv2/ install
	$(MAKE) -C ./cliv2/ install
	$(MAKE) -C ./agentv2/ install
	$(MAKE) -C ./combinerv2/ install
	$(MAKE) -C ./imrv2/ install
	$(MAKE) -C ./dogv2/ install

TAR_VERSION:=v2
TARFILE:=/tmp/usr.local.tdns.$(TAR_VERSION).tar.gz
TAR_CONTENTS:=bin/tdns-cliv2 bin/dogv2 \
	libexec/tdns-imrv2 libexec/tdns-authv2 \
	libexec/tdns-agentv2 libexec/tdns-combinerv2

tarball: install
	cd /usr/local && tar -czf $(TARFILE) $(TAR_CONTENTS)

include ../utils/Makefile.common
