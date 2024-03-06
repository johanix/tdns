all:
	$(MAKE) -C ./tdnsd/
	$(MAKE) -C ./tdns-cli/
	$(MAKE) -C ./dog/

clean:
	$(MAKE) -C ./tdnsd/ clean
	$(MAKE) -C ./tdns-cli/ clean
	$(MAKE) -C ./dog/ clean
