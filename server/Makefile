PROG:=tdns-server

GOOS ?= $(shell uname -s | tr A-Z a-z)
GO:=CGO_ENABLED=1 go

include ../utils/Makefile.common

install:
	install -s -b -c ${PROG} /usr/local/libexec/

