all:
	$(MAKE) -C ./server/
	$(MAKE) -C ./cli/
	$(MAKE) -C ./agent/
	$(MAKE) -C ./dog/
	$(MAKE) -C ./sidecar/
	$(MAKE) -C ./sidecar-cli/


clean:
	$(MAKE) -C ./server/ clean
	$(MAKE) -C ./cli/ clean
	$(MAKE) -C ./agent/ clean
	$(MAKE) -C ./dog/ clean
	$(MAKE) -C ./sidecar/ clean
	$(MAKE) -C ./sidecar-cli/ clean

install:
	$(MAKE) -C ./server/ install
	$(MAKE) -C ./cli/ install
	$(MAKE) -C ./agent/ install
	$(MAKE) -C ./dog/ install
	$(MAKE) -C ./sidecar/ install
	$(MAKE) -C ./sidecar-cli/ install
