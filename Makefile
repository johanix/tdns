
all:
	$(MAKE) -C ./auth/
	$(MAKE) -C ./cli/
	$(MAKE) -C ./agent/
	$(MAKE) -C ./dog/
	$(MAKE) -C ./combiner/
	$(MAKE) -C ./imr/
	$(MAKE) -C ./reporter/
	$(MAKE) -C ./scanner/
	$(MAKE) -C ./kdc/
	$(MAKE) -C ./krs/
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
	$(MAKE) -C ./kdc/ clean
	$(MAKE) -C ./krs/ clean
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
	$(MAKE) -C ./kdc/ install
	$(MAKE) -C ./krs/ install
#	$(MAKE) -C ./msa/ install
#	$(MAKE) -C ./sidecar-cli/ install

include utils/Makefile.common
