PROG:=tdns-cli
VERSION:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`

GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)"

GOOS ?= $(shell uname -s | tr A-Z a-z)
# GOARCH:=amd64

# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go
# We need CGO because we now need sqlite also in tdns-cli
GO:=GOOS=$(GOOS) CGO_ENABLED=1 go

default: ${PROG}

${PROG}: build

build:
	$(GO) build $(GOFLAGS) -o ${PROG}

netbsd: 
	GOOS=netbsd GOARCH=amd64 $(GO) build $(GOFLAGS) -o ${PROG}.netbsd

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

install:
	install -s -b -c ${PROG} /usr/local/bin/

.PHONY: build clean

