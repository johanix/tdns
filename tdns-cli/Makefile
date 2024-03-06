PROG:=tdns-cli
VERSION:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`

GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)"

GOOS ?= $(shell uname -s | tr A-Z a-z)
# GOARCH:=amd64

# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go
GO:=GOOS=$(GOOS) CGO_ENABLED=0 go

default: ${PROG}

${PROG}: build

build:
	$(GO) build $(GOFLAGS) -o ${PROG}

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

.PHONY: build clean

