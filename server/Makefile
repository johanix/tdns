PROG:=tdns-server
COMMIT:=`git describe --dirty=+WiP --always`
VERSION=`cat ./VERSION`
APPDATE=`date +"%Y-%m-%d-%H:%M"`

GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)-$(COMMIT)"

GOOS ?= $(shell uname -s | tr A-Z a-z)
# GOARCH:=amd64

# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go
# GO:=GOOS=$(GOOS) CGO_ENABLED=1 go
GO:=CGO_ENABLED=1 go

default: ${PROG}

${PROG}: build

version.go:	VERSION Makefile
	/bin/sh make-version.sh $(VERSION)-$(COMMIT) $(APPDATE) $(PROG)

build:	version.go
	GOOS=$(shell uname -s | tr A-Z a-z) $(GO) build $(GOFLAGS) -o ${PROG}

netbsd: 
	GOOS=netbsd GOARCH=amd64 $(GO) build $(GOFLAGS) -o ${PROG}.netbsd

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

install:
	install -s -b -c ${PROG} /usr/local/libexec/

lint:
	go fmt ./...
	go vet ./...
	staticcheck ./...
	gosec ./...
	golangci-lint run

.PHONY: build clean
