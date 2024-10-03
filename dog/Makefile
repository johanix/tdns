PROG:=dog

GOOS ?= $(shell uname -s | tr A-Z a-z)
# GO:=GOOS=$(GOOS) CGO_ENABLED=0 go
GO:=CGO_ENABLED=0 go
include ../utils/Makefile.common

install:
	install -s -b -c ${PROG} /usr/local/bin/

