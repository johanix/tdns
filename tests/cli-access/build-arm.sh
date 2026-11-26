#!/bin/sh
# build-arm.sh CHECKOUT OUTDIR TAG: build the five binaries the rig runs from
# a tdns checkout at the commit under test, with make, and collect them in
# OUTDIR with a BUILD file ("TAG <commit> <date> <os>"). Run it on a build
# host (NetBSD: godev101; Linux: godeb12), never on a lab host.
#
# The rig never builds anything itself: "run.sh use OUTDIR" on the daemon
# host installs what this collected, and "run.sh ship" passes the client
# binaries on to the CLI host, so both hosts run the same build.
set -e
[ $# -eq 3 ] || { echo "usage: build-arm.sh CHECKOUT OUTDIR TAG" >&2; exit 2; }
co=$1 outdir=$2 tag=$3
commit=$(git -C "$co" rev-parse HEAD)
[ -z "$(git -C "$co" status --porcelain --untracked-files=no)" ] \
	|| { echo "$co has local changes; build a clean checkout" >&2; exit 1; }
MAKE=${MAKE:-make}
command -v gmake > /dev/null && MAKE=gmake
# A fresh checkout has no record of where dnssec-algorithms is; ALGREPO
# names it (the apps' make then runs genalgs from there).
if [ ! -f "$co/cmdv2/algs-env.mk" ] && [ -n "$ALGREPO" ]; then
	echo "ALGREPO := $ALGREPO" > "$co/cmdv2/algs-env.mk"
fi
$MAKE -C "$co/cmdv2" genalgs
for d in auth imr ncli cli dog; do $MAKE -C "$co/cmdv2/$d"; done
mkdir -p "$outdir"
for b in auth/tdns-auth imr/tdns-imr ncli/tdns-ncli cli/tdns-cli dog/dog; do
	cp "$co/cmdv2/$b" "$outdir/"
done
echo "$tag $commit $(date -u +%FT%TZ) $(uname -sm)" > "$outdir/BUILD"
echo "BUILD OK $(cat "$outdir/BUILD")"
