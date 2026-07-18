.PHONY: all v2 genalgs version clean install install-dirs check-root tarball

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

TAR_VERSION:=v2
TARFILE:=/tmp/usr.local.tdns.$(TAR_VERSION).tar.gz
TAR_CONTENTS:=bin/tdns-cli bin/dog \
	libexec/tdns-imr libexec/tdns-auth \
	libexec/tdns-agent

tarball: install
	cd /usr/local && tar -czf $(TARFILE) $(TAR_CONTENTS)
