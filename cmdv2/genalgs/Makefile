# Build the tdns-genalgs code generator. The parent cmdv2/Makefile builds
# this first so app generate rules can invoke $(GENALGS).

PROG := tdns-genalgs
GO   ?= go

# Sources are listed explicitly rather than gathered with $(wildcard ...),
# which is a GNU make function and expands to nothing under NetBSD bmake.
# Keep this list in step with the .go files here (test files excluded: they
# are not inputs to the binary).
SRCS := env.go main.go registry.go

# $(PROG) must NOT be .PHONY, and the prerequisites above are the reason.
#
# Without prerequisites it was only ever built when MISSING, so a months-old
# generator counted as up to date and silently emitted stale build config.
# Making it .PHONY fixed that but overshot: `go build -o` rewrites the output
# file on every run, so the binary's mtime always moved, which made the
# "generated files are current" test in utils/Makefile.common
# ([ ! $(GENALGS) -nt registered_algs.go ]) fail every time. Every build in
# every app directory then regenerated -- and, worse, needed the
# dnssec-algorithms checkout present, so a host that built fine from current
# generated files would start failing if that path moved.
#
# With real prerequisites the binary is relinked only when its sources change,
# its mtime is stable, and that test does what it was written to do. The
# always-recurse behaviour lives in Makefile.common, where it belongs.
.PHONY: all clean

all: $(PROG)

$(PROG): $(SRCS)
	$(GO) build -o $(PROG) .

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
