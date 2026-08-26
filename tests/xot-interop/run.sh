#!/bin/sh
# XoT interop rig: start | stop | restart | status | verify
# Run setup.sh once first. See README.md.
RIG="${RIG:-/var/tmp/xotinterop}"
TDNS="${TDNS:-/Users/johani/src/git/tdns-project/tdns}"
KNOT="${KNOT:-/Users/johani/src/git/tdns-project/knot-dns-v3.5.2/src}"
NSD="${NSD:-/opt/local/sbin/nsd}"
NAMED="${NAMED:-/opt/local/sbin/named}"

stop() {
	for p in "tdns-auth --config $RIG" "tdns-agent --config $RIG" \
	         "nsd -c $RIG" "named -c $RIG" "knotd -c $RIG"; do
		pkill -f "$p" 2>/dev/null
	done
	sleep 2; echo "stopped"
}

start() {
	[ -f "$RIG/ca/xot-ca.crt" ] || { echo "not seeded — run setup.sh first" >&2; exit 1; }
	(cd "$TDNS/cmdv2/auth" && nohup ./tdns-auth --config "$RIG/tdns-auth/tdns-auth.yaml" \
		< /dev/null > "$RIG/log/tdns-auth.stdout" 2>&1 &)
	sleep 4
	$NSD   -c "$RIG/nsd/nsd.conf"     -d < /dev/null > "$RIG/log/nsd.stdout"   2>&1 &
	$NAMED -c "$RIG/bind/named.conf"  -g < /dev/null > "$RIG/log/named.stdout" 2>&1 &
	$KNOT/knotd -c "$RIG/knot/knot.conf" < /dev/null > "$RIG/log/knotd.stdout" 2>&1 &
	(cd "$TDNS/cmdv2/agent" && nohup ./tdns-agent --config "$RIG/tdns-agent/tdns-agent.yaml" \
		< /dev/null > "$RIG/log/tdns-agent.stdout" 2>&1 &)
	sleep 10; status
}

status() {
	echo "listeners (Do53 / DoT):"
	lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null \
	  | grep -E ':(530[1-5]|540[1-5]) ' | awk '{print "  " $1, $9}' | sort -u
	echo "serials:"
	for pz in "5301:a.xot.test" "5303:a.xot.test" "5304:a.xot.test" "5305:a.xot.test" \
	          "5303:b-nsd.xot.test" "5304:b-bind.xot.test" "5305:b-knot.xot.test" \
	          "5302:b-nsd.xot.test" "5302:b-bind.xot.test" "5302:b-knot.xot.test"; do
		p=${pz%%:*}; z=${pz#*:}
		printf "  %-5s %-20s %s\n" "$p" "$z" \
		  "$(dig +short @127.0.0.1 -p $p $z SOA 2>/dev/null | awk '{print $3}')"
	done
}

# verify: the assertions the rig exists to make
verify() {
	fail=0
	norm() { dig +noall +answer +onesoa +tcp @127.0.0.1 -p "$1" "$2" AXFR 2>/dev/null \
	         | awk 'NF>=4{$1=tolower($1); print}' | tr -s ' \t' ' ' | sort; }
	chk() { # label srcport dstport zone
		a=$(norm "$2" "$4"); b=$(norm "$3" "$4"); n=$(printf '%s\n' "$a" | grep -c .)
		if [ -n "$a" ] && [ "$a" = "$b" ]; then echo "  PASS  $1 ($n RRs)"
		else echo "  FAIL  $1"; fail=1; fi; }

	echo "A. tdns-auth primary -> secondaries (a.xot.test)"
	chk "NSD  " 5301 5303 a.xot.test
	chk "BIND9" 5301 5304 a.xot.test
	chk "Knot " 5301 5305 a.xot.test
	echo "B. primaries -> tdns-agent secondary"
	chk "from NSD  " 5303 5302 b-nsd.xot.test
	chk "from BIND9" 5304 5302 b-bind.xot.test
	chk "from Knot " 5305 5302 b-knot.xot.test
	echo "C. negative zones must NOT have transferred"
	for pz in "5303:neg1" "5304:neg1" "5305:neg1" "5305:neg2"; do
		p=${pz%%:*}; z=${pz#*:}
		got=$(dig +short @127.0.0.1 -p $p canary.$z.xot.test TXT 2>/dev/null)
		if [ -z "$got" ]; then echo "  PASS  $z refused on :$p"
		else echo "  FAIL  $z LEAKED on :$p -> $got"; fail=1; fi
	done
	echo
	[ $fail = 0 ] && echo "all assertions hold" || echo "FAILURES above"
	return $fail
}

case "${1:-status}" in
	start)   start ;;
	stop)    stop ;;
	restart) stop; start ;;
	status)  status ;;
	verify)  verify ;;
	*) echo "usage: $0 {start|stop|restart|status|verify}"; exit 1 ;;
esac
