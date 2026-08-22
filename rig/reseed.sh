#!/bin/sh
# Reset the rig zone to the pristine seed. Run as a FILE, never inline over ssh:
# an inline `pkill -f` pattern matches the shell's own command line and kills it.
R=/var/tmp/ixfrtest
set -e

pkill -f "tdns-auth --config $R/" 2>/dev/null || true
pkill -f "named -c $R/named/named.conf" 2>/dev/null || true
sleep 2

mkdir -p /var/tmp/ixfrtest-preseed
cp $R/zones/rig.example /var/tmp/ixfrtest-preseed/ 2>/dev/null || true
cp $R/tdns.db /var/tmp/ixfrtest-preseed/ 2>/dev/null || true

cat > $R/zones/rig.example <<'ZONE'
; The IXFR/journal rig zone. Deliberately tiny, and UNSIGNED: the zone runs with
; inline-signing, so tdns-auth signs what it serves and rewrites this file only
; when asked (write / sync / freeze).
rig.example.	300	IN	SOA	ns.rig.example. hostmaster.rig.example. 1 1800 900 604800 300
rig.example.	300	IN	NS	ns.rig.example.
ns.rig.example.	300	IN	A	127.0.0.1
static.rig.example.	300	IN	TXT	"never changes"
www.rig.example.	300	IN	A	192.0.2.1
ZONE

# A fresh database: no stale journal anchored to the old file, no recorded file
# identity, and new signing keys minted from the `rig` policy at load.
rm -f $R/tdns.db
rm -f $R/zones/rig.example.*.rejected
rm -f $R/named/rig.example.db $R/named/rig.example.db.jnl

echo "seeded:"
cat $R/zones/rig.example
