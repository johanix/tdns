#!/bin/sh
# IXFR interop rig: start | stop | restart | status | churn | verify
# Run setup.sh once first. See README.md.
RIG="${RIG:-/var/tmp/ixfrinterop}"
TDNS="${TDNS:-/Users/johani/src/git/tdns-project/tdns}"
NAMED="${NAMED:-/opt/local/sbin/named}"
NSUPDATE="${NSUPDATE:-/opt/local/bin/nsupdate}"
DIG="${DIG:-dig}"
CLI="$TDNS/cmdv2/cli/tdns-cli"
# How many updates each scenario makes. The point of a long series is that an
# apply error compounds: one wrong RR at delta 3 is still wrong at delta 25,
# and only a whole-zone comparison at the end will say so.
ROUNDS="${ROUNDS:-24}"

P=5321   # tdns-auth primary
S=5322   # tdns-auth secondary
B=5323   # named

stop() {
	for p in "tdns-auth --config $RIG/tdns-auth-p" "tdns-auth --config $RIG/tdns-auth-s"; do
		pkill -f "$p" 2>/dev/null
	done
	pkill -f "named -c $RIG/bind/named.conf" 2>/dev/null
	sleep 2; echo "stopped"
}

start() {
	[ -f "$RIG/tdns-auth-p/tdns-auth-p.yaml" ] || { echo "not seeded -- run setup.sh" >&2; exit 1; }
	(cd "$TDNS/cmdv2/auth" && nohup ./tdns-auth --config "$RIG/tdns-auth-p/tdns-auth-p.yaml" \
		< /dev/null > "$RIG/log/tdns-auth-p.stdout" 2>&1 &)
	sleep 4
	# No -f: named daemonises itself. Backgrounding a foreground named would
	# hold the caller's stdout open, so `run.sh start` would never return.
	"$NAMED" -c "$RIG/bind/named.conf" < /dev/null > "$RIG/log/named.stdout" 2>&1
	sleep 3
	(cd "$TDNS/cmdv2/auth" && nohup ./tdns-auth --config "$RIG/tdns-auth-s/tdns-auth-s.yaml" \
		< /dev/null > "$RIG/log/tdns-auth-s.stdout" 2>&1 &)
	sleep 8; status
}

soa() { $DIG +short @127.0.0.1 -p "$1" "$2" SOA 2>/dev/null | awk '{print $3}'; }

status() {
	printf "%-18s %-12s %-12s %s\n" "zone" "tdns-p:$P" "tdns-s:$S" "named:$B"
	printf "  %-16s %-12s %-12s %s\n" "a"    "$(soa $P a.ixfr.test)"    "$(soa $S a.ixfr.test)"    "-"
	printf "  %-16s %-12s %-12s %s\n" "b"    "-"                        "$(soa $S b.ixfr.test)"    "$(soa $B b.ixfr.test)"
	printf "  %-16s %-12s %-12s %s\n" "c"    "$(soa $P c.ixfr.test)"    "-"                        "$(soa $B c.ixfr.test)"
	printf "  %-16s %-12s %-12s %s\n" "casc" "$(soa $P casc.ixfr.test)" "$(soa $S casc.ixfr.test)" "$(soa $B casc.ixfr.test)"
}

# --- driving the primaries -------------------------------------------------

# tdns primary: through the management API, which is the staging path that
# builds an outbound IXFR chain. A zone-file rewrite would NOT: FetchFromFile
# goes through applyRefreshReplacementLocked, which resets the chain by design.
api_update() { # zone round
	"$CLI" --config "$RIG/tdns-cli.yaml" auth zone update addrr --zone "$1" --via api \
		--rr "churn$2.$1 3600 IN A 10.9.$(( $2 / 256 )).$(( $2 % 256 ))" >/dev/null 2>&1
}

# BIND primary: dynamic update, one delta per change, journalled.
bind_update() { # round
	printf 'server 127.0.0.1 %s\nzone b.ixfr.test\nupdate add churn%s.b.ixfr.test 3600 A 10.9.%s.%s\nsend\n' \
		"$B" "$1" "$(( $1 / 256 ))" "$(( $1 % 256 ))" | "$NSUPDATE" >/dev/null 2>&1
}

churn() {
	echo "making $ROUNDS updates per scenario"
	i=1
	while [ $i -le "$ROUNDS" ]; do
		api_update a.ixfr.test. $i
		api_update c.ixfr.test. $i
		api_update casc.ixfr.test. $i
		bind_update $i
		# Let the notify/refresh settle so each change is transferred as its
		# own delta rather than several being collapsed into one.
		sleep 2
		i=$(( i + 1 ))
	done
	sleep 8
	echo "churn done"
}

# --- the oracle ------------------------------------------------------------

# A canonical rendering of a zone as served: every RR, sorted, with the SOA
# included. NOT the raw AXFR byte stream -- RR order within an AXFR is not
# guaranteed to match across implementations or even across runs, so comparing
# wire bytes would report differences that are not differences.
axfr_canon() { # port zone
	$DIG +noall +answer +onesoa @127.0.0.1 -p "$1" "$2" AXFR 2>/dev/null \
		| grep -v '^;' | awk 'NF' | sed 's/[[:space:]]\+/ /g' | sort
}

zonemd_of() { # port zone
	$DIG +short @127.0.0.1 -p "$1" "$2" ZONEMD 2>/dev/null | sort | head -1
}

# --- verification ----------------------------------------------------------

fail=0
ok()   { echo "  PASS  $1"; }
bad()  { echo "  FAIL  $1"; fail=1; }

same_zone() { # label portA portB zone
	a=$(axfr_canon "$2" "$4"); b=$(axfr_canon "$3" "$4")
	if [ -z "$a" ]; then bad "$1 (no AXFR from port $2)"; return; fi
	if [ -z "$b" ]; then bad "$1 (no AXFR from port $3)"; return; fi
	if [ "$a" = "$b" ]; then ok "$1"; return; fi
	bad "$1 -- zones differ"
	# Temp files rather than process substitution: these rigs are /bin/sh.
	printf '%s\n' "$a" > "$RIG/run/.cmp-a"
	printf '%s\n' "$b" > "$RIG/run/.cmp-b"
	diff "$RIG/run/.cmp-a" "$RIG/run/.cmp-b" | head -12 | sed 's/^/          /'
}

same_serial() { # label portA portB zone
	a=$(soa "$2" "$4"); b=$(soa "$3" "$4")
	[ -n "$a" ] && [ "$a" = "$b" ] && ok "$1 (serial $a)" || bad "$1 (serials '$a' vs '$b')"
}

same_zonemd() { # label portA portB zone
	a=$(zonemd_of "$2" "$4"); b=$(zonemd_of "$3" "$4")
	if [ -z "$a" ]; then bad "$1 (no ZONEMD at port $2)"; return; fi
	[ "$a" = "$b" ] && ok "$1" || bad "$1 (ZONEMD differs)"
}

# The assertion the whole rig turns on. Every scenario here converges just as
# well over AXFR, so without this a completely broken delta path shows three
# green PASSes.
# Counts difference SEQUENCES, not transfers. One transfer can carry several:
# if the secondary polls less often than the primary changes, it gets a
# multi-sequence response covering every serial step since it last asked. That
# is the interesting path -- the one a single-step test never reaches -- and
# counting transfers would understate it. Every update must have travelled as
# a delta, so the floor is the number of updates made.
tdns_sequences() { # label zone min
	n=$(grep "ixfr: delta applied.*$2" "$RIG/log/tdns-auth-s.log" 2>/dev/null \
		| grep -o "sequences=[0-9]*" | awk -F= '{s+=$2} END {print s+0}')
	if [ "$n" -ge "$3" ]; then ok "$1 ($n difference sequences applied)"
	else bad "$1 (only $n sequences applied, wanted >= $3 -- the secondary is falling back to AXFR)"; fi
}

bind_deltas() { # label zone min
	n=$(grep -c "transfer of '$2/IN'.*: got incremental response" "$RIG/log/named.log" 2>/dev/null || echo 0)
	if [ "$n" -ge "$3" ]; then ok "$1 ($n incremental transfers)"
	else bad "$1 (only $n incremental transfers, wanted >= $3)"; fi
}

verify() {
	fail=0
	# Everything below compares two servers and passes when they agree. If the
	# comparison cannot report a difference, every PASS after it is worthless --
	# so prove first that it discriminates, on two zones known to differ.
	echo "0. the comparison discriminates"
	same_zone "self-comparison agrees" $P $P a.ixfr.test
	x=$(axfr_canon $P a.ixfr.test); y=$(axfr_canon $P casc.ixfr.test)
	if [ -n "$x" ] && [ "$x" != "$y" ]; then
		ok "different zones compare as different"
	else
		bad "different zones compared as EQUAL -- the oracle is broken and every assertion below is meaningless"
	fi

	echo "1. (a) tdns primary -> tdns secondary"
	same_serial "a: serials agree"  $P $S a.ixfr.test
	same_zone   "a: zones identical" $P $S a.ixfr.test
	same_zonemd "a: ZONEMD identical" $P $S a.ixfr.test
	tdns_sequences "a: transferred incrementally" "a.ixfr.test" $ROUNDS

	echo "2. (b) BIND primary -> tdns secondary"
	same_serial "b: serials agree"  $B $S b.ixfr.test
	same_zone   "b: zones identical" $B $S b.ixfr.test
	tdns_sequences "b: transferred incrementally" "b.ixfr.test" $ROUNDS

	echo "3. (c) tdns primary -> BIND secondary"
	same_serial "c: serials agree"  $P $B c.ixfr.test
	same_zone   "c: zones identical" $P $B c.ixfr.test
	same_zonemd "c: ZONEMD identical" $P $B c.ixfr.test
	bind_deltas "c: transferred incrementally" "c.ixfr.test" $(( ROUNDS / 2 ))

	echo "4. cascade: tdns primary -> tdns secondary -> BIND edge"
	same_serial "casc: primary and secondary agree" $P $S casc.ixfr.test
	same_serial "casc: secondary and edge agree"    $S $B casc.ixfr.test
	same_zone   "casc: primary and edge identical"  $P $B casc.ixfr.test
	same_zonemd "casc: ZONEMD survives two hops"    $P $B casc.ixfr.test
	tdns_sequences "casc: middle hop pulled deltas"    "casc.ixfr.test" $ROUNDS
	bind_deltas "casc: edge was RELAYED deltas"     "casc.ixfr.test" $(( ROUNDS / 2 ))

	echo
	[ $fail = 0 ] && echo "all assertions hold" || echo "FAILURES above"
	return $fail
}

case "${1:-status}" in
	start) start ;; stop) stop ;; restart) stop; start ;;
	status) status ;; churn) churn ;; verify) verify ;;
	full) start; churn; verify ;;
	*) echo "usage: $0 {start|stop|restart|status|churn|verify|full}"; exit 1 ;;
esac
