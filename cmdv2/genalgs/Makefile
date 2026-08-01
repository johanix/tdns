# Build the tdns-genalgs code generator. The parent cmdv2/Makefile builds
# this first so app generate rules can invoke $(GENALGS).

PROG := tdns-genalgs
GO   ?= go

# $(PROG) is .PHONY on purpose. As a file target with no prerequisites it was
# only ever built when MISSING, so an existing tdns-genalgs was treated as
# up to date no matter how old it was -- which is how hosts ended up
# regenerating months-old build config from a stale generator long after the
# sources were fixed, silently. Listing the .go sources instead would need
# $(wildcard ...), which is GNU-make-only and unavailable in NetBSD bmake.
# Deferring to `go build` every time is correct and nearly free: its build
# cache makes a no-op rebuild a fraction of a second.
.PHONY: all clean $(PROG)

all: $(PROG)

$(PROG):
	$(GO) build -o $(PROG) .

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
