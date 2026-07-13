PROG:=tdns-debug

# Pure client: no sqlite, no C-backed algorithms (no algs.list / genalgs).
GO:=CGO_ENABLED=0 go
include ../../utils/Makefile.common

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/bin/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
