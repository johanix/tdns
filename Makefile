all:
	$(MAKE) -C ./tdnsd/
	$(MAKE) -C ./tdns-cli/
	$(MAKE) -C ./agent/
	$(MAKE) -C ./dog/

clean:
	$(MAKE) -C ./tdnsd/ clean
	$(MAKE) -C ./tdns-cli/ clean
	$(MAKE) -C ./agent/ clean
	$(MAKE) -C ./dog/ clean

install:
	$(MAKE) -C ./tdnsd/ install
	$(MAKE) -C ./tdns-cli/ install
	$(MAKE) -C ./agent/ install
	$(MAKE) -C ./dog/ install
