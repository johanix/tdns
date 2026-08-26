#!/bin/sh
# Seed the XoT interop rig into $RIG (default /var/tmp/xotinterop).
#
# Mints a private CA and one leaf certificate per daemon, copies the configs
# and zones in, and substitutes each server's real SPKI pin into the
# tdns-agent config. Certificates are NEVER committed: they carry private keys
# and their pins change on every issuance, so they are made here instead.
#
# Re-running is destructive to state (db, logs, transferred zones) but keeps
# nothing stale. Pass -k to keep the existing CA and certs.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
RIG="${RIG:-/var/tmp/xotinterop}"
TDNS="${TDNS:-/Users/johani/src/git/tdns-project/tdns}"
CLI="$TDNS/cmdv2/cli/tdns-cli"
KEEPCERTS=0
[ "$1" = "-k" ] && KEEPCERTS=1

[ -x "$CLI" ] || { echo "need tdns-cli at $CLI (set TDNS=) — build cmdv2/cli first" >&2; exit 1; }

echo "rig root: $RIG"
rm -rf "$RIG/tdns-auth" "$RIG/tdns-agent" "$RIG/nsd" "$RIG/bind" "$RIG/knot" \
       "$RIG/log" "$RIG/run" "$RIG/zones"
mkdir -p "$RIG"/ca "$RIG"/certs "$RIG"/zones "$RIG"/log "$RIG"/run/knot \
         "$RIG"/tdns-auth "$RIG"/tdns-agent/zones \
         "$RIG"/nsd/xfr "$RIG"/bind "$RIG"/knot/db "$RIG"/knot/zones

# --- PKI -------------------------------------------------------------------
if [ "$KEEPCERTS" = 0 ] || [ ! -f "$RIG/ca/xot-ca.crt" ]; then
	rm -rf "$RIG/ca" "$RIG/certs"; mkdir -p "$RIG/ca" "$RIG/certs"
	echo "minting CA"
	"$CLI" cert ca --name xot-ca --out-dir "$RIG/ca" >/dev/null
	# a second, unrelated CA: a valid PEM that signed none of our certs,
	# used by the "wrong CA" negative test
	"$CLI" cert ca --name bogus-ca --out-dir "$RIG/ca" >/dev/null
	for n in tdnsauth tdnsagent nsd bind knot; do
		echo "minting ns-$n.xot.test"
		"$CLI" cert leaf --ca "$RIG/ca/xot-ca.crt" --ca-key "$RIG/ca/xot-ca.key" \
			--name "ns-$n.xot.test" --dns "ns-$n.xot.test" --ip 127.0.0.1 \
			--client --out-dir "$RIG/certs" >/dev/null
	done
fi

# --- configs + zones -------------------------------------------------------
cp "$SRC"/zones/*.zone "$RIG"/zones/
cp "$SRC"/tdns-auth.yaml "$RIG"/tdns-auth/
cp "$SRC"/nsd.conf       "$RIG"/nsd/
cp "$SRC"/named.conf     "$RIG"/bind/
cp "$SRC"/knot.conf      "$RIG"/knot/

# the agent pins each primary's certificate; fill in the pins just minted
PIN_NSD=$("$CLI"  cert pin "$RIG/certs/ns-nsd.xot.test.crt"  | tail -1)
PIN_BIND=$("$CLI" cert pin "$RIG/certs/ns-bind.xot.test.crt" | tail -1)
PIN_KNOT=$("$CLI" cert pin "$RIG/certs/ns-knot.xot.test.crt" | tail -1)
sed -e "s|@PIN_NSD@|$PIN_NSD|" -e "s|@PIN_BIND@|$PIN_BIND|" -e "s|@PIN_KNOT@|$PIN_KNOT|" \
	"$SRC"/tdns-agent.yaml > "$RIG"/tdns-agent/tdns-agent.yaml

echo
echo "seeded. pins in use:"
printf "  ns-nsd   %s\n  ns-bind  %s\n  ns-knot  %s\n" "$PIN_NSD" "$PIN_BIND" "$PIN_KNOT"
echo
echo "next: $SRC/run.sh start"
