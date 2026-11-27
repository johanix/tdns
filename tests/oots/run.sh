#!/bin/sh
# The OOTS transport-signal rig. See README.md.
#
#   run.sh setup               mint certificates and keys, build the rig root
#   run.sh list                the suites
#   run.sh suite NAME [NAME..] run suites, each on its own
#   run.sh all                 every suite, one after another
#   run.sh clean               remove the work root
#
# Everything runs inside an unprivileged Linux network namespace (unshare -rn),
# which this script enters by itself: 127.0.0.0/8 is local there, port 53 needs
# no privilege, and every daemon dies with the namespace when the command ends.
# So each suite starts from nothing, and suites run in any order.

RIG="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$OOTS_RIG_NS" ]; then
	case "$1" in
	list|clean|"") ;;
	*)	command -v unshare >/dev/null || { echo "rig: needs unshare (Linux)" >&2; exit 2; }
		OOTS_RIG_NS=1 exec unshare -rn sh "$0" "$@" ;;
	esac
fi

. "$RIG/lib.sh"
for _f in "$RIG"/suites/*.sh; do . "$_f"; done

[ -n "$OOTS_RIG_NS" ] && ip link set lo up 2>/dev/null

# The rig root delegates one zone per party, to an address of its own. Signed
# children are named with the party holding their keys; setup puts their DS in
# the root. A suite may only use a zone listed here.
DELEGATIONS="
ports.test.  ns1.ports.test.  127.0.0.11  -
p2.test.     ns.p2.test.      127.0.0.12  -
p6.test.     ns.p6.test.      127.0.0.13  -
p22.test.    ns.p22.test.     127.0.0.14  -
ign.test.    ns.ign.test.     127.0.0.21  -
ign2.test.   ns.ign2.test.    127.0.0.22  -
tb1.test.    ns.tb1.test.     127.0.0.31  -
tb2.test.    ns.tb2.test.     127.0.0.32  -
cs.test.     ns.cs.test.      127.0.0.41  cs-pri:127.0.0.40
csu.test.    ns.csu.test.     127.0.0.42  -
pub.test.    ns1.pub.test.    127.0.0.51  -
provider.test. ns1.provider.test. 127.0.0.61 cust:127.0.0.61
customer.test. ns1.customer.test. 127.0.0.61 cust:127.0.0.61
customer2.test. ns1.customer2.test. 127.0.0.61 cust:127.0.0.61
other.test.    ns1.provider.test. 127.0.0.61 cust:127.0.0.61
two.test.      ns1.provider.test. 127.0.0.61 cust:127.0.0.61
far.test.      ns1.far.test.      127.0.0.61 cust:127.0.0.61
"

suites() { sed -n 's/^suite_\([a-z0-9_]*\)().*/\1/p' "$RIG"/suites/*.sh; }

# A suite is green when nothing failed and something passed. A skip is never a
# pass, so a suite whose every check skipped showed nothing: it is not green,
# and neither is the run.
summary() {
	echo "----"
	echo "$1: $NPASS pass, $NFAIL fail, $NSKIP skip"
	[ "$NFAIL" -eq 0 ] || return 1
	[ "$NPASS" -gt 0 ] || { echo "$1: nothing passed, so it is not green"; return 1; }
}

# Keys for one signed child: start its primary once with an empty zone, wait
# for the DNSKEY, and ask its keystore for the DS. The keys stay in the
# party's database, which the suite later starts again.
child_ds() { # zone party address
	local _z _p _a
	_z="$1"; _p="$2"; _a="$3"
	ZDIR="$WORK/$_p/zones"; mkdir -p "$ZDIR"
	zonefile "$_z" "ns.$_z=$_a" </dev/null > "$ZDIR/${_z}zone"
	{ y_service "$_p" "ns.$_z"; y_listeners "$_a"; y_common "$_p" "$_a"
	  y_zones; y_primary "$_z" online-signing; } | auth_up "$_p" "$AUTH_PUB" "$_a" "$_z" || return 1
	wait_for 30 answers "$_a" "$_z" DNSKEY || { echo "rig: no DNSKEY for $_z" >&2; return 1; }
	"$CLI_PUB" --config "$WORK/$_p/tdns-cli.yaml" auth keystore dnssec gen-ds --zone "$_z" 2>&1 |
		awk '$0 ~ /IN[ \t]+DS[ \t]/ && $(NF-1) == "2" { sub(/^[^I]*IN/, "IN"); print; exit }
		     $0 ~ /IN[ \t]+DS[ \t]/ { for (i = 1; i <= NF; i++) if ($i == "DS" && $(i+3) == "2") {
		         s = "IN"; for (j = i; j <= NF; j++) s = s " " $j; print s; exit } }' > "$WORK/$_p/${_z}ds"
	stop_daemons
	[ -s "$WORK/$_p/${_z}ds" ] || { echo "rig: gen-ds gave no SHA-256 DS for $_z" >&2; return 1; }
}

do_setup() {
	rm -rf "$WORK"
	mkdir -p "$WORK/certs" "$WORK/infra/zones"
	"$CLI" cert ca --name oots-rig-ca --out-dir "$WORK/certs" >/dev/null || die "cert ca"
	"$CLI" cert leaf --ca "$WORK/certs/oots-rig-ca.crt" --ca-key "$WORK/certs/oots-rig-ca.key" \
		--name rig --dns localhost --ip 127.0.0.1 --out-dir "$WORK/certs" >/dev/null || die "cert leaf"
	[ -f "$WORK/certs/rig.crt" ] || die "no $WORK/certs/rig.crt after cert leaf"

	# The signed children first: the root needs their DS.
	echo "$DELEGATIONS" | while read -r z ns a signer; do
		[ -n "$z" ] && [ "$signer" != "-" ] || continue
		child_ds "$z" "${signer%%:*}" "${signer#*:}" || exit 1
	done || die "a signed child could not be set up"

	{
		echo "\$ORIGIN ."
		echo "\$TTL 3600"
		echo ". IN SOA a.root.test. hostmaster.root.test. 1 3600 600 86400 60"
		echo ". IN NS a.root.test."
		echo "a.root.test. IN A 127.0.0.2"
		echo "$DELEGATIONS" | while read -r z ns a signer; do
			[ -n "$z" ] || continue
			echo "$z IN NS $ns"
			echo "$ns IN A $a"
			[ "$signer" = "-" ] || echo "$z $(cat "$WORK/${signer%%:*}/${z}ds")"
		done
	} > "$WORK/infra/root.zone.src"

	ZDIR="$WORK/infra/zones"
	{ y_service infra "a.root.test."; y_listeners 127.0.0.2; y_common infra 127.0.0.2
	  y_zones; y_primary . online-signing; } > "$WORK/infra/tdns-auth.yaml"
	cli_conf infra 127.0.0.2 auth
	infra_up
	wait_for 30 answers 127.0.0.2 . DNSKEY || die "the rig root is not signed"
	dogq 127.0.0.2 . DNSKEY | awk '$1 == "." && $0 ~ /DNSKEY[ \t]+257[ \t]/' > "$WORK/infra/root.ta"
	[ -s "$WORK/infra/root.ta" ] || die "no root KSK"
	printf '. 3600000 IN NS a.root.test.\na.root.test. 3600000 IN A 127.0.0.2\n' > "$WORK/infra/root.hints"
	stop_daemons
	echo "setup done: $WORK"
}

do_suite() { # name
	type "suite_$1" >/dev/null 2>&1 || die "no suite $1 (run.sh list)"
	[ -s "$WORK/infra/root.ta" ] || die "run setup first"
	NPASS=0; NFAIL=0; NSKIP=0
	echo "==== suite $1   AUTH_PUB=$AUTH_PUB AUTH_SEC=$AUTH_SEC IMR=$IMR CLI_IMR=$CLI_IMR"
	rm -f "$PIDS"
	infra_up
	"suite_$1"
	stop_daemons
	summary "suite $1"
}

case "$1" in
setup)	do_setup ;;
list)	suites ;;
suite)	shift; [ $# -gt 0 ] || die "which suite? (run.sh list)"
	rc=0
	for s in "$@"; do do_suite "$s" || rc=1; done
	exit $rc ;;
all)	rc=0
	for s in $(suites); do do_suite "$s" || rc=1; done
	exit $rc ;;
clean)	rm -rf "$WORK"; echo "removed $WORK" ;;
*)	sed -n '2,13p' "$0"; exit 2 ;;
esac
