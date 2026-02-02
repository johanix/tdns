.PHONY: all v1 clean install install-dirs check-root tarball

# all apps in this directory
all: v1
	$(MAKE) -C ./reporter/
	$(MAKE) -C ./scanner/

# production version of major apps
v1:
	$(MAKE) -C ./auth/
	$(MAKE) -C ./cli/
	$(MAKE) -C ./agent/
	$(MAKE) -C ./combiner/
	$(MAKE) -C ./imr/
	$(MAKE) -C ./dog/

clean:
	$(MAKE) -C ./cli/ clean
	$(MAKE) -C ./agent/ clean
	$(MAKE) -C ./dog/ clean
	$(MAKE) -C ./combiner/ clean
	$(MAKE) -C ./imr/ clean
	$(MAKE) -C ./reporter/ clean
	$(MAKE) -C ./scanner/ clean
#	$(MAKE) -C ./msa/ clean
#	$(MAKE) -C ./sidecar-cli/ clean

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Must run as root"; exit 1; fi

install-dirs: check-root
	mkdir -p /usr/local/bin /usr/local/libexec

install: check-root install-dirs
	$(MAKE) -C ./auth/ install
	$(MAKE) -C ./cli/ install
	$(MAKE) -C ./agent/ install
	$(MAKE) -C ./dog/ install
	$(MAKE) -C ./combiner/ install
	$(MAKE) -C ./imr/ install
	$(MAKE) -C ./reporter/ install
	$(MAKE) -C ./scanner/ install
#	$(MAKE) -C ./msa/ install
#	$(MAKE) -C ./sidecar-cli/ install

TAR_VERSION:=v1
TARFILE:=/tmp/usr.local.tdns.$(TAR_VERSION).tar.gz
TAR_CONTENTS:=bin/tdns-cli bin/tdns-imr bin/dog \
	libexec/tdns-auth libexec/tdns-agent libexec/tdns-combiner \
	libexec/tdns-reporter libexec/tdns-scanner

tarball: install
	cd /usr/local && tar -czf $(TARFILE) $(TAR_CONTENTS)

include ../utils/Makefile.common
