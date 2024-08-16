all:
	$(MAKE) -C ./server/
	$(MAKE) -C ./tdns-cli/
	$(MAKE) -C ./agent/
	$(MAKE) -C ./dog/

clean:
	$(MAKE) -C ./server/ clean
	$(MAKE) -C ./tdns-cli/ clean
	$(MAKE) -C ./agent/ clean
	$(MAKE) -C ./dog/ clean

install:
	$(MAKE) -C ./server/ install
	$(MAKE) -C ./tdns-cli/ install
	$(MAKE) -C ./agent/ install
	$(MAKE) -C ./dog/ install
