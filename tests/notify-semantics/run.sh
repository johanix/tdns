#!/bin/sh
# notify-semantics rig: start | stop | status | signing | mirror | full
# Run setup.sh once first. See README.md.
RIG="${RIG:-/var/tmp/notifysem}"
TDNS="${TDNS:-$(cd "$(dirname "$0")/../.." && pwd)}"
AUTH="$TDNS/cmdv2/auth/tdns-auth"
DEBUG="$TDNS/cmdv2/debug/tdns-debug"
DIG="${DIG:-dig}"
ROUNDS="${ROUNDS:-8}"
SETTLE="${SETTLE:-10s}"

S=5331   # the SUT

stop() {
	pkill -f "tdns-auth --config $RIG/tdns-auth" 2>/dev/null
	sleep 2; echo "stopped"
}

start() {
	[ -f "$RIG/tdns-auth/tdns-auth.yaml" ] || { echo "not seeded -- run setup.sh" >&2; exit 1; }
	[ -x "$AUTH" ]  || { echo "need tdns-auth at $AUTH" >&2; exit 1; }
	[ -x "$DEBUG" ] || { echo "need tdns-debug at $DEBUG (cd cmdv2/debug && make)" >&2; exit 1; }
	# Truncate the log a run is read from. The daemon appends, so without this
	# one run's evidence is mixed with every previous run's.
	: > "$RIG/log/tdns-auth.log"
	(cd "$TDNS/cmdv2/auth" && nohup ./tdns-auth --config "$RIG/tdns-auth/tdns-auth.yaml" \
		< /dev/null > "$RIG/log/tdns-auth.stdout" 2>&1 &)
	sleep 5; status
}

# +tries=1 +time=2: both zones are empty until their rig runs, and an unloaded
# zone draws no answer at all. With dig's defaults `status` then sits for 15s
# per zone before printing the blank it was always going to print.
soa() { $DIG +short +tries=1 +time=2 @127.0.0.1 -p "$S" "$1" SOA 2>/dev/null | awk '{print $3}'; }

status() {
	printf "%-16s %s\n" "zone" "SUT:$S"
	printf "  %-14s %s\n" "relay.test."  "$(soa relay.test.)"
	printf "  %-14s %s\n" "mirror.test." "$(soa mirror.test.)"
	echo "  (both are empty until the corresponding rig run: the rig IS their primary)"
}

# The rig's own listen ports differ per zone, matching tdns-auth.yaml, so the
# two profiles can be run in either order or at the same time.
signing() {
	"$DEBUG" test relay --zone relay.test. --sut 127.0.0.1:$S --profile signing \
		--upstream-listen 127.0.0.1:5361 --downstream-listen 127.0.0.1:5362 \
		--rounds "$ROUNDS" --settle "$SETTLE" "$@"
}

mirror() {
	"$DEBUG" test relay --zone mirror.test. --sut 127.0.0.1:$S --profile mirror \
		--upstream-listen 127.0.0.1:5371 --downstream-listen 127.0.0.1:5372 \
		--rounds "$ROUNDS" --settle "$SETTLE" "$@"
}

case "$1" in
	start)   start ;;
	stop)    stop ;;
	restart) stop; start ;;
	status)  status ;;
	signing) shift; signing "$@" ;;
	mirror)  shift; mirror "$@" ;;
	full)
		start
		# Both profiles run even if the first reports violations, because the
		# second answers a different question and a run that stopped early
		# would leave it unanswered rather than unasked.
		signing; rc1=$?
		mirror;  rc2=$?
		stop
		echo "signing exit $rc1, mirror exit $rc2"
		[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ]
		exit $?
		;;
	*) echo "usage: $0 {start|stop|restart|status|signing|mirror|full}" >&2; exit 2 ;;
esac
