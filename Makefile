all:
	$(MAKE) -C ./server/
	$(MAKE) -C ./cli/
	$(MAKE) -C ./agent/
	$(MAKE) -C ./dog/

clean:
	$(MAKE) -C ./server/ clean
	$(MAKE) -C ./cli/ clean
	$(MAKE) -C ./agent/ clean
	$(MAKE) -C ./dog/ clean

install:
	$(MAKE) -C ./server/ install
	$(MAKE) -C ./cli/ install
	$(MAKE) -C ./agent/ install
	$(MAKE) -C ./dog/ install
