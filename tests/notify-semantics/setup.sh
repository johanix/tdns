#!/bin/sh
# Seed the notify-semantics rig into $RIG (default /var/tmp/notifysem).
#
# No zone files: both zones are SECONDARIES and their content arrives from the
# rig over AXFR. No TLS either -- but tdns's API server wants a certificate
# even with TLS off, so one is minted here.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
RIG="${RIG:-/var/tmp/notifysem}"
TDNS="${TDNS:-$(cd "$SRC/../.." && pwd)}"
CLI="$TDNS/cmdv2/cli/tdns-cli"
[ -x "$CLI" ] || { echo "need tdns-cli at $CLI (set TDNS=)" >&2; exit 1; }

rm -rf "$RIG"
mkdir -p "$RIG"/log "$RIG"/certs "$RIG"/tdns-auth

"$CLI" cert ca --name notifysem-ca --out-dir "$RIG/certs" >/dev/null
"$CLI" cert leaf --ca "$RIG/certs/notifysem-ca.crt" --ca-key "$RIG/certs/notifysem-ca.key" \
	--name localhost --dns localhost --ip 127.0.0.1 --out-dir "$RIG/certs" >/dev/null

# The config is written against the default location, so seeding anywhere else
# has to rewrite the paths inside it -- otherwise the daemon starts but reads
# and writes the default tree, and the log the run is read from is not the one
# being written.
sed "s|/var/tmp/notifysem|$RIG|g" "$SRC/tdns-auth.yaml" > "$RIG/tdns-auth/tdns-auth.yaml"

echo "seeded $RIG -- next: $SRC/run.sh full"
