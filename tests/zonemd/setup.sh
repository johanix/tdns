#!/bin/sh
# Seed the ZONEMD gate rig into $RIG (default /var/tmp/zonemd).
# No TLS is involved — ZONEMD is orthogonal to transport — but tdns's API
# server wants a cert even with TLS off, so one is minted here.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
RIG="${RIG:-/var/tmp/zonemd}"
TDNS="${TDNS:-/Users/johani/src/git/tdns-project/tdns}"
CLI="$TDNS/cmdv2/cli/tdns-cli"
[ -x "$CLI" ] || { echo "need tdns-cli at $CLI (set TDNS=)" >&2; exit 1; }

rm -rf "$RIG"
mkdir -p "$RIG"/{zones,log,certs} "$RIG"/run/knot "$RIG"/tdns-auth \
         "$RIG"/tdns-agent/zones "$RIG"/knot/db "$RIG"/knot/zones

"$CLI" cert ca --name zonemd-ca --out-dir "$RIG/certs" >/dev/null
"$CLI" cert leaf --ca "$RIG/certs/zonemd-ca.crt" --ca-key "$RIG/certs/zonemd-ca.key" \
	--name localhost --dns localhost --ip 127.0.0.1 --out-dir "$RIG/certs" >/dev/null

cp "$SRC"/zones/*.zone      "$RIG"/zones/
cp "$SRC"/tdns-auth.yaml    "$RIG"/tdns-auth/
cp "$SRC"/tdns-agent.yaml   "$RIG"/tdns-agent/
cp "$SRC"/knot.conf         "$RIG"/knot/
echo "seeded $RIG — next: $SRC/run.sh start"
