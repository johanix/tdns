.PHONY: v1 all v2 clean install

# production version of major apps
v1:
	$(MAKE) -C ./cmd/auth/
	$(MAKE) -C ./cmd/cli/
	$(MAKE) -C ./cmd/agent/
	$(MAKE) -C ./cmd/combiner/
	$(MAKE) -C ./cmd/imr/
	$(MAKE) -C ./cmd/dog/

# experimental version of major apps
v2:
	$(MAKE) -C ./cmdv2/authv2/
	$(MAKE) -C ./cmdv2/cliv2/
	$(MAKE) -C ./cmdv2/agentv2/
	$(MAKE) -C ./cmdv2/combinerv2/
	$(MAKE) -C ./cmdv2/imrv2/
	$(MAKE) -C ./cmdv2/dogv2/

# both versions of major apps + some minor apps
all:	v1 v2
	$(MAKE) -C ./cmd/reporter/
	$(MAKE) -C ./cmd/scanner/
#	$(MAKE) -C ./obe/msa/
#	$(MAKE) -C ./obe/sidecar-cli/

clean:
	$(MAKE) -C ./cmd/auth/ clean
	$(MAKE) -C ./cmd/cli/ clean
	$(MAKE) -C ./cmd/imr/ clean
	$(MAKE) -C ./cmd/dog/ clean
	$(MAKE) -C ./cmd/agent/ clean
	$(MAKE) -C ./cmd/combiner/ clean

	$(MAKE) -C ./cmdv2/authv2/ clean
	$(MAKE) -C ./cmdv2/cliv2/ clean
	$(MAKE) -C ./cmdv2/imrv2/ clean
	$(MAKE) -C ./cmdv2/dogv2/ clean
	$(MAKE) -C ./cmdv2/agentv2/ clean
	$(MAKE) -C ./cmdv2/combinerv2/ clean

	$(MAKE) -C ./reporter/ clean
	$(MAKE) -C ./scanner/ clean
#	$(MAKE) -C ./msa/ clean
#	$(MAKE) -C ./sidecar-cli/ clean

install:
#	$(MAKE) -C ./auth/ install
#	$(MAKE) -C ./cli/ install
#	$(MAKE) -C ./agent/ install
#	$(MAKE) -C ./dog/ install
#	$(MAKE) -C ./combiner/ install
#	$(MAKE) -C ./imr/ install
#	$(MAKE) -C ./reporter/ install
#	$(MAKE) -C ./scanner/ install
#	$(MAKE) -C ./msa/ install
#	$(MAKE) -C ./sidecar-cli/ install

include utils/Makefile.common
