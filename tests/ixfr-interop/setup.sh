#!/bin/sh
# Seed the IXFR interop rig into $RIG (default /var/tmp/ixfrinterop).
#
# No TLS is involved -- IXFR is orthogonal to transport -- but tdns's API
# server wants a certificate even with TLS off, so one is minted here.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
RIG="${RIG:-/var/tmp/ixfrinterop}"
TDNS="${TDNS:-/Users/johani/src/git/tdns-project/tdns}"
CLI="$TDNS/cmdv2/cli/tdns-cli"
[ -x "$CLI" ] || { echo "need tdns-cli at $CLI (set TDNS=)" >&2; exit 1; }

rm -rf "$RIG"
mkdir -p "$RIG"/{zones,log,certs,bind,run} \
         "$RIG"/tdns-auth-p "$RIG"/tdns-auth-s

"$CLI" cert ca --name ixfr-ca --out-dir "$RIG/certs" >/dev/null
"$CLI" cert leaf --ca "$RIG/certs/ixfr-ca.crt" --ca-key "$RIG/certs/ixfr-ca.key" \
	--name localhost --dns localhost --ip 127.0.0.1 --out-dir "$RIG/certs" >/dev/null

cp "$SRC"/zones/*.zone       "$RIG"/zones/

# The configs are written against the default location, so seeding a rig
# anywhere else has to rewrite the paths inside them. Without this a custom
# $RIG half-works: the daemons start, but they read and write the default
# tree, and run.sh then counts transfers in a log nobody is writing to.
seed() { sed "s|/var/tmp/ixfrinterop|$RIG|g" "$SRC/$1" > "$RIG/$2/$1"; }
seed tdns-auth-p.yaml tdns-auth-p
seed tdns-auth-s.yaml tdns-auth-s
seed named.conf       bind
seed tdns-cli.yaml    .
# BIND rewrites its primary zone on every dynamic update, so it gets its own
# copy rather than sharing the one tdns serves from.
cp "$SRC"/zones/b.ixfr.test.zone "$RIG"/bind/
chmod -R u+w "$RIG"/bind

echo "seeded $RIG -- next: $SRC/run.sh start"
