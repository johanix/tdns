.PHONY: v1 all v2 clean install

v1:
	$(MAKE) -C ./cmd/auth/
	$(MAKE) -C ./cmd/cli/
	$(MAKE) -C ./cmd/agent/
	$(MAKE) -C ./cmd/combiner/
	$(MAKE) -C ./cmd/imr/
	$(MAKE) -C ./cmd/dog/

v2:
	$(MAKE) -C ./cmdv2/authv2/
	$(MAKE) -C ./cmdv2/cliv2/
	$(MAKE) -C ./cmdv2/agentv2/
	$(MAKE) -C ./cmdv2/combinerv2/
	$(MAKE) -C ./cmdv2/imrv2/
	$(MAKE) -C ./cmdv2/dogv2/

all:	v1 v2
	$(MAKE) -C ./reporter/
	$(MAKE) -C ./scanner/
#	$(MAKE) -C ./msa/
#	$(MAKE) -C ./sidecar-cli/

clean:
	$(MAKE) -C ./auth/ clean
	$(MAKE) -C ./cli/ clean
	$(MAKE) -C ./agent/ clean
	$(MAKE) -C ./dog/ clean
	$(MAKE) -C ./combiner/ clean
	$(MAKE) -C ./imr/ clean
	$(MAKE) -C ./reporter/ clean
	$(MAKE) -C ./scanner/ clean
#	$(MAKE) -C ./msa/ clean
#	$(MAKE) -C ./sidecar-cli/ clean

install:
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

include utils/Makefile.common
