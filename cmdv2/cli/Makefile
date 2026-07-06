PROG:=tdns-cli

# We need CGO because we now need sqlite also in tdns-cli
# GO:=GOOS=$(GOOS) CGO_ENABLED=1 go
GO:=CGO_ENABLED=1 go
include ../../utils/Makefile.common

.PHONY: clean install docs

install:
	install -s -b -c ${PROG} /usr/local/bin/

# Regenerate the generated CLI reference (reference/cli/*.md) from the live
# cobra command tree. Output is stable (no auto-gen date footer), so re-running
# is a no-op diff unless the command tree actually changed -- which makes it
# usable as a CI drift check: `make docs && git diff --exit-code reference/cli`.
docs: $(PROG)
	./$(PROG) gen-docs --dir ../../reference/cli

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete

