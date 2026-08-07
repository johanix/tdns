#!/bin/sh
#
# mkpkg.sh -- build a NetBSD binary package from files already installed
#             under a prefix. Companion to the tarball targets: same file
#             lists, but producing a registered package instead of a bare
#             tarball.
#
#   usage: mkpkg.sh <pkgbase> <prefix> <file> [file ...]
#   e.g.   mkpkg.sh tdns-cli /usr/local bin/tdns-cli bin/dog
#
# This is a near-verbatim sibling of labstuff's utils/mkpkg.sh. The ~20 lines
# of duplication are deliberate: they are separate repos, and vendoring one
# into the other is worse than keeping two copies that rarely change. If you
# fix something here, fix it there too.
#
# WHY A PACKAGE AND NOT A TARBALL. A bintar leaves no record: nothing on the
# machine can answer "what is installed here, and which build is it?". That
# question has been expensive more than once -- the tdns bintar sat at Feb 2025
# on every lab machine and only a timestamp revealed it. pkg_info answers it,
# and pkg_delete can undo it.
#
# And for tdns specifically there is a second reason. tdns-auth starts at boot
# from rc.d on the lab master, but the binary used to arrive via swprep, which
# runs AFTER boot -- so a freshly built master had no binary, the daemon
# failed, and the zones it serves were served by nothing. A package can be
# pkg_add'ed into the mounted image before first boot; a swprep bintar cannot.
#
# FOUR THINGS THAT ARE NOT OBVIOUS, all of which cost a failed attempt:
#
#  1. pkg_create infers NEITHER the compression NOR the extension. Without
#     "-F gzip" and an explicit .tgz name you get an uncompressed tar with no
#     suffix, which nothing downstream recognises.
#
#  2. PKGTOOLS_VERSION must not exceed the INSTALLING host's pkg_install
#     version, or pkg_add refuses outright with "built with a newer pkg_install
#     version" -- naming a version, but not which of the two is wrong. Pinned
#     old below so any host accepts it.
#
#  3. -p is where the files are NOW (the staging tree); -I is where they go at
#     install time. Both take the same relative paths from the packing list.
#
#  4. OS_VERSION mismatch only WARNS, and installs anyway (verified both
#     directions, 9.3<->10.1). So it is metadata, not enforcement: one package
#     built here is dropped into every per-release tree deliberately. Go
#     binaries built on an older NetBSD run on a newer one, which is the
#     direction we are in -- the build host is 9.3 and the lab is moving to
#     10.1. If that ever inverts, build explicitly on a host of the needed
#     release rather than lying in this field.
#
# The staging copy is required by pkg_create, which needs a tree it can treat as
# the package root. The files come from $PREFIX, i.e. from wherever "make
# install" put them -- same source the tarball targets use.

set -e

# pkg_create lives in /usr/sbin, which is NOT on the PATH of a non-interactive
# ssh session -- so a build driven remotely (which is how the lab builds) fails
# with "pkg_create: not found" while it works fine when you are logged in.
# Overridable for a host that keeps it elsewhere.
PKG_CREATE="${PKG_CREATE:-}"
if [ -z "$PKG_CREATE" ]; then
	for c in /usr/sbin/pkg_create /usr/pkg/sbin/pkg_create; do
		[ -x "$c" ] && PKG_CREATE="$c" && break
	done
fi
[ -z "$PKG_CREATE" ] && PKG_CREATE=$(command -v pkg_create 2>/dev/null || true)
if [ -z "$PKG_CREATE" ]; then
	echo "mkpkg.sh: cannot find pkg_create (looked in /usr/sbin, /usr/pkg/sbin, PATH)" >&2
	exit 1
fi

PKGBASE="$1"; shift
PREFIX="$1"; shift

if [ -z "$PKGBASE" ] || [ -z "$PREFIX" ] || [ $# -eq 0 ]; then
	echo "usage: mkpkg.sh <pkgbase> <prefix> <file> [file ...]" >&2
	exit 1
fi

# Version: VERSION.DATE, e.g. tdns-auth-0.8.20260807.
#
# A pkgsrc version must START WITH A DIGIT and contain no '-': pkg_add splits
# name-version on the last hyphen, and its version COMPARISON -- the reason for
# packaging at all -- gives up on a leading 'v'. Hence the sed below (tdns's
# VERSION file says "v0.8"), and hence a DOT between version and date rather
# than a second dash.
#
# NO COMMIT HASH, deliberately. A hash makes every build a distinct version, so
# the published tree accumulates forever and nothing can be pruned without
# correlating each file back to git history. A date is readable, sorts
# correctly, and makes "keep the last N" a decision you can take by looking.
# The commit IS recorded, in the DESC below, where it costs nothing.
#
# The cost, worth knowing: two builds on the SAME DAY carry the same version.
# pkg_add will treat the second as already-installed and skip it, so a
# rebuild-and-redeploy loop within one day needs pkg_add -U (or pkg_delete
# first). It will not silently install the old one -- it will decline and say so.
#
# PKGVERSION may be supplied by the caller. The Makefile does so, because it
# needs to know the output filename BEFORE running this script -- that is what
# lets the package be a real make target with the binaries as prerequisites,
# instead of a phony target that rebuilds a 40MB package on every invocation.
if [ -z "$PKGVERSION" ]; then
	BASEVERSION=$(cat ../../VERSION 2>/dev/null || echo 0)
	BASEVERSION=$(echo "$BASEVERSION" | sed 's/^[vV]//; s/[^0-9.].*$//; s/\.*$//')
	[ -z "$BASEVERSION" ] && BASEVERSION=0
	PKGVERSION="${BASEVERSION}.$(date +%Y%m%d)"
fi

# Refuse a version that is not one. The caller passing an EMPTY PKGVERSION is
# not hypothetical: $(shell ...) under BSD make expands to nothing, which in
# labstuff produced "axfr-statusd-..tgz" -- a full-size package, plausibly
# named, with no version in it. That is worse than a failure, because it
# installs.
case "$PKGVERSION" in
	[0-9]*.[0-9]*) ;;
	*)
		echo "mkpkg.sh: refusing to build with version '$PKGVERSION'" >&2
		echo "  expected something like 0.8.20260807 (digits, dot, digits)." >&2
		echo "  If invoked from make, PKGVER did not expand. The two ways that" >&2
		echo "  happens, both silent: \$(shell ...) is GNU-make only and yields" >&2
		echo "  nothing under NetBSD's bmake, and '!=' needs bmake or GNU make" >&2
		echo "  4.0+ (macOS still ships 3.81). Build on the NetBSD build host." >&2
		exit 1
		;;
esac
PKGNAME="${PKGBASE}-${PKGVERSION}"

STAGE=$(mktemp -d /tmp/mkpkg.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

META="$STAGE/.meta"
ROOT="$STAGE/root"
mkdir -p "$META" "$ROOT"

: > "$META/PLIST"
for f in "$@"; do
	if [ ! -f "$PREFIX/$f" ]; then
		echo "mkpkg.sh: $PREFIX/$f does not exist -- run the build and install it first" >&2
		exit 1
	fi
	mkdir -p "$ROOT/$(dirname "$f")"
	cp -p "$PREFIX/$f" "$ROOT/$f"
	echo "$f" >> "$META/PLIST"
done

# The exact source revision, for the DESC only -- never for the version field.
# git describe anchors on whatever tag happens to be nearest, which is not a
# thing to build a package version out of; as free text next to the date it is
# exactly what you want when asking "which build is this?".
SRCREV=$(git describe --dirty=+WiP --always 2>/dev/null || echo unknown)
SRCBRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)

# tdns produces four packages from one repo, so a single hardcoded one-line
# COMMENT would describe none of them. Callers pass PKGCOMMENT; the default
# below is the fallback for a hand-run invocation.
COMMENT="${PKGCOMMENT:-$PKGBASE, part of the tdns DNS toolset}"
echo "$COMMENT (built $(date +%Y-%m-%d))" > "$META/COMMENT"

cat > "$META/DESC" <<EOF
$COMMENT.

Built from $(basename "$PWD") on $(date +%Y-%m-%d), source $SRCBRANCH/$SRCREV.
Installed under $PREFIX.

Packaged rather than shipped as a bintar so that the machine keeps a record of
what it is running: pkg_info reports the exact source revision without having
to run the binary, and pkg_delete can remove it cleanly. A package can also be
installed into a VM image before first boot, which is what lets tdns-auth start
from rc.d on a freshly built lab master.
EOF

cat > "$META/BUILD_INFO" <<EOF
OPSYS=NetBSD
OS_VERSION=$(uname -r)
MACHINE_ARCH=$(uname -p)
PKGTOOLS_VERSION=20091115
EOF

"$PKG_CREATE" -F gzip \
	-B "$META/BUILD_INFO" \
	-c "$META/COMMENT" \
	-d "$META/DESC" \
	-f "$META/PLIST" \
	-p "$ROOT" \
	-I "$PREFIX" \
	"${PKGNAME}.tgz"

echo "built ${PKGNAME}.tgz ($(ls -l "${PKGNAME}.tgz" | awk '{print $5}') bytes, $# files, OS_VERSION=$(uname -r), src $SRCREV)"
