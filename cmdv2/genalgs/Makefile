# Build the tdns-genalgs code generator. The parent cmdv2/Makefile builds
# this first so app generate rules can invoke $(GENALGS).

PROG := tdns-genalgs
GO   ?= go

.PHONY: all clean

all: $(PROG)

$(PROG):
	$(GO) build -o $(PROG) .

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
