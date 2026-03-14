.PHONY: v1 all v2 clean install

default: v2

# production version of major apps
v1:
	$(MAKE) -C ./cmd/ v1

# experimental version of major apps
v2:
	$(MAKE) -C ./cmdv2/ v2

# both versions of major apps + some minor apps
all:	v1 v2
	$(MAKE) -C ./cmd/ all
#	$(MAKE) -C ./obe/msa/
#	$(MAKE) -C ./obe/sidecar-cli/

clean:
	$(MAKE) -C ./cmd/ clean
	$(MAKE) -C ./cmdv2/ clean
#	$(MAKE) -C ./msa/ clean
#	$(MAKE) -C ./sidecar-cli/ clean

install:
	$(MAKE) -C ./cmd/ install
	$(MAKE) -C ./cmdv2/ install
#	$(MAKE) -C ./msa/ install
#	$(MAKE) -C ./sidecar-cli/ install

include utils/Makefile.common
