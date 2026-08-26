#!/bin/sh
# ZONEMD gate rig: start | stop | restart | status | verify
# Run setup.sh once first. See README.md.
RIG="${RIG:-/var/tmp/zonemd}"
TDNS="${TDNS:-/Users/johani/src/git/tdns-project/tdns}"
KNOT="${KNOT:-/Users/johani/src/git/tdns-project/knot-dns-v3.5.2/src}"

stop() {
	for p in "tdns-auth --config $RIG" "tdns-agent --config $RIG" "knotd -c $RIG"; do
		pkill -f "$p" 2>/dev/null
	done
	sleep 2; echo "stopped"
}

start() {
	[ -f "$RIG/tdns-auth/tdns-auth.yaml" ] || { echo "not seeded — run setup.sh" >&2; exit 1; }
	(cd "$TDNS/cmdv2/auth" && nohup ./tdns-auth --config "$RIG/tdns-auth/tdns-auth.yaml" \
		< /dev/null > "$RIG/log/tdns-auth.stdout" 2>&1 &)
	sleep 4
	$KNOT/knotd -c "$RIG/knot/knot.conf" < /dev/null > "$RIG/log/knotd.stdout" 2>&1 &
	sleep 4
	(cd "$TDNS/cmdv2/agent" && nohup ./tdns-agent --config "$RIG/tdns-agent/tdns-agent.yaml" \
		< /dev/null > "$RIG/log/tdns-agent.stdout" 2>&1 &)
	sleep 12; status
}

soa() { dig +short @127.0.0.1 -p "$1" "$2" SOA 2>/dev/null | awk '{print $3}'; }

status() {
	printf "%-22s %-14s %-14s %s\n" "zone" "tdns-auth" "tdns-agent" "knot"
	for z in good bad warn knotgen none unsup tmpl tmplpart; do
		printf "  %-20s %-14s %-14s %s\n" "$z" \
			"$(soa 5311 $z.zonemd.test)" \
			"$(soa 5312 $z.zonemd.test)" \
			"$(soa 5315 $z.zonemd.test)"
	done
}

# The gate assertions. Each names the behaviour observed 2026-08-25; a change
# here is a change in what the two implementations promise, not a flaky test.
verify() {
	fail=0
	want() { # label port zone expect(present|absent)
		got=$(soa "$2" "$3.zonemd.test")
		if [ "$4" = present ] && [ -n "$got" ]; then echo "  PASS  $1"
		elif [ "$4" = absent ] && [ -z "$got" ]; then echo "  PASS  $1"
		else echo "  FAIL  $1 (serial='$got', wanted $4)"; fail=1; fi
	}
	echo "1. a valid digest is accepted by both"
	want "tdns-agent accepts good" 5312 good present
	want "knot accepts good"       5315 good present
	echo "2. a wrong digest is refused by both -- the gate itself"
	want "tdns-agent refuses bad"  5312 bad  absent
	want "knot refuses bad"        5315 bad  absent
	echo "3. on-verify-failure: warn adopts the same wrong digest"
	want "tdns-agent adopts warn"  5312 warn present
	echo "4. cross-implementation: tdns verifies a digest Knot generated"
	want "tdns-agent accepts knotgen" 5312 knotgen present
	echo "5. DIVERGENCE: nothing checkable -- tdns adopts, knot refuses"
	want "tdns-agent adopts none (no ZONEMD)"       5312 none  present
	want "knot refuses none (no ZONEMD)"            5315 none  absent
	want "tdns-agent adopts unsup (alg 240)"        5312 unsup present
	want "knot refuses unsup (alg 240)"             5315 unsup absent
	echo "6. the zonemd: block templates, per field"
	want "tmpl inherits the whole block (warn -> adopted)"      5312 tmpl     present
	want "tmplpart sets algorithms, still inherits warn"        5312 tmplpart present
	echo
	[ $fail = 0 ] && echo "all assertions hold" || echo "FAILURES above"
	return $fail
}

case "${1:-status}" in
	start) start ;; stop) stop ;; restart) stop; start ;;
	status) status ;; verify) verify ;;
	*) echo "usage: $0 {start|stop|restart|status|verify}"; exit 1 ;;
esac
