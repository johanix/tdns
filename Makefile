.PHONY: default v1 all v2 clean install bump-johanix-deps

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
