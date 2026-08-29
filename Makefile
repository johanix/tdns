.PHONY: default v1 all v2 clean install bump-johanix-deps check-all namecheck

default: v2

# production version of major apps
v1:
	$(MAKE) -C ./cmd/ v1

# experimental version of major apps
v2:
	$(MAKE) -C ./cmdv2/ v2

# both versions of major apps + some minor apps
all:	v1 v2
	$(MAKE) -C ./cmd/ all
#	$(MAKE) -C ./obe/msa/
#	$(MAKE) -C ./obe/sidecar-cli/

clean:
	$(MAKE) -C ./cmd/ clean
	$(MAKE) -C ./cmdv2/ clean
#	$(MAKE) -C ./msa/ clean
#	$(MAKE) -C ./sidecar-cli/ clean

install:
	$(MAKE) -C ./cmd/ install
	$(MAKE) -C ./cmdv2/ install
#	$(MAKE) -C ./msa/ install
#	$(MAKE) -C ./sidecar-cli/ install

# namecheck: the gate that keeps DNS names folded by the DNS rule.
#
# Six stages of conversion produced four defects with one shape -- two sides of
# a pair folded by different functions -- and a grep would have caught none of
# them, because in every case the call it would flag had already been converted.
# So this parses. See tools/namecheck and
# docs/2026-08-28-case-insensitive-names-scope.md.
#
# Exit status is 1 on any finding. Run it in CI.
namecheck:
	@cd tools/namecheck && go build -o /tmp/tdns-namecheck .
	@/tmp/tdns-namecheck v2 cmdv2

# check-all: unit tests for every live module, then every gate.
#
# The gates are part of testing rather than something to remember: `go test`
# and `go vet` cannot run namecheck -- it is a program, not an analyzer -- but
# nothing stops this target from running both, and a gate nobody runs is a gate
# that does not hold.
#
# NOT named "test": utils/Makefile.common defines that as the per-app
# `go test -v -cover`, which the app directories use. Redefining it here would
# override the shared one and warn on every invocation.
#
# The module list is explicit rather than found by `find . -name go.mod`. The
# v1 tree, music/ and obe/ are frozen and are not what this checks; a target
# that fails because a frozen module no longer builds is one people learn to
# skip.
TESTMODS = v2 v2/core v2/cache v2/cli v2/debug v2/edns0 tools/namecheck

check-all:
	@rc=0; \
	for mod in $(TESTMODS); do \
	   printf '==> go test %s\n' "$$mod"; \
	   ( cd $$mod && go test ./... ) || rc=1; \
	done; \
	printf '==> gates\n'; \
	$(MAKE) --no-print-directory check || rc=1; \
	if [ $$rc -eq 0 ]; then printf '\nall modules pass, all gates clean\n'; fi; \
	exit $$rc

# bump-johanix-deps: in every go.mod under this repo, refresh every
# github.com/johanix/* require line to its current proxy 'latest'
# (default-branch HEAD of the corresponding repo). Third-party deps
# are not touched. Runs `go mod tidy` per-module afterwards.
#
# Caveat: some johanix sub-modules (notably tdns/v2/cli) currently
# have unresolved pseudo-versions for their sibling sub-modules and
# will fail to fetch externally. The target prints the failure and
# moves on; rerun once the underlying structural issue is fixed.
bump-johanix-deps:
	@for mod in $$(find . -name go.mod -not -path './obe/*' -not -path './music/*' -not -path './.git/*'); do \
	   dir=$$(dirname $$mod); \
	   deps=$$(awk '/^require \(/,/^\)/ { if ($$1 ~ /^github\.com\/johanix\//) print $$1 }' $$mod | sort -u); \
	   if [ -z "$$deps" ]; then \
	      continue; \
	   fi; \
	   echo "=== $$dir ==="; \
	   for dep in $$deps; do \
	      echo "  $$dep"; \
	      (cd $$dir && go get $$dep@latest) || echo "  ! $$dep@latest failed (likely unresolved sub-module pin)"; \
	   done; \
	   (cd $$dir && go mod tidy) || echo "  ! go mod tidy failed in $$dir"; \
	done

include utils/Makefile.common
