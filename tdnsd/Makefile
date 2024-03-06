PROG:=tdnsd
COMMIT:=`git describe --dirty=+WiP --always`
VERSION=`cat ./VERSION`

GOFLAGS:=-ldflags "-X app.version=$(VERSION)-$(COMMIT)"

GOOS ?= $(shell uname -s | tr A-Z a-z)
# GOARCH:=amd64

# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go
GO:=GOOS=$(GOOS) CGO_ENABLED=1 go

default: ${PROG}

${PROG}: build

build:
	$(GO) build $(GOFLAGS) -o ${PROG}

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

install:
	install -s -b -c ${PROG} /usr/local/libexec/

.PHONY: build clean
