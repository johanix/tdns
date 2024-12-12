# Variabler
LOCAL_PROJECT_PATH := /Users/berra/git/tdns/
REMOTE_USER := root
REMOTE_PROJECT_PATH := /root/tdns/
APP_NAME := tdns

TDNS1_ADDR := 3.249.198.88
TDNS2_ADDR := 3.255.230.249

default: all

# Standardmål
tdns1:
	$(MAKE) TDNS_ADDR=$(TDNS1_ADDR) deploy-tdns

tdns2:
	$(MAKE) TDNS_ADDR=$(TDNS2_ADDR) deploy-tdns


# Kopiera projektet till VM
copy-tdns:
	rsync -av --delete --exclude-from=norsync.txt $(LOCAL_PROJECT_PATH) $(REMOTE_USER)@$(TDNS_ADDR):$(REMOTE_PROJECT_PATH)
	ssh $(REMOTE_USER)@$(TDNS_ADDR) "sed -i 's|Users/berra|etc|g' /root/tdns/tdns/defaults.go && \
						chown -R root:root $(REMOTE_PROJECT_PATH)"

# Bygg applikationen på VM
build-tdns:
	ssh $(REMOTE_USER)@$(TDNS_ADDR) "cd $(REMOTE_PROJECT_PATH) && make"

# Kör applikationen på VM
run-tdns:
	ssh $(REMOTE_USER)@$(TDNS_ADDR) "cd $(REMOTE_PROJECT_PATH) && ./server/tdns-server -v"


# Kombinerat mål för att kopiera, bygga och köra applikationen
deploy-tdns: copy-tdns build-tdns

# Rensa byggda filer på VM
clean-tdns:
	echo ssh $(REMOTE_USER)@$(TDNS_ADDR) "cd $(REMOTE_PROJECT_PATH) && rm -f $(APP_NAME)"


.PHONY: all tdns1 tdns2 copy-tdns build-tdns run-tdns deploy-tdns clean-tdns

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
