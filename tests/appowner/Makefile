# appowner: an application client of tdns-auth's management API, for
# run.sh. Not a tdns binary and not installed: run.sh builds it into its own
# temporary directory with BIN=.
#
# CGO for the same reason as the cmdv2 apps: the v2 library links sqlite.

BIN ?= appowner
GO := CGO_ENABLED=1 go

.PHONY: build vet clean

build:
	$(GO) build -o $(BIN) .

vet:
	$(GO) vet ./...

clean:
	rm -f appowner
