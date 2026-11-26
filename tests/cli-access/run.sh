#!/bin/sh
# run.sh: the cli-access rig, run as root on the DAEMON host. See README.md.
#
#   use ARMDIR        install a build (tdns-auth tdns-imr tdns-ncli tdns-cli
#                     dog + BUILD) into /var/tmp/cli-access/bin
#   ship              copy the rig, the client binaries, the public certs and
#                     the CLI host's configs to the CLI host ($CLI_SSH)
#   start | stop | status
#   verify SUITE...   socket | roles | pins | all; one PASS/FAIL/SKIP line
#                     per assertion, exit 0 only if all passed and none skipped
#   clean             stop the daemons, remove the rig's sockets and state
#
# CLI_SSH is how this host reaches the CLI host as root, e.g.
#   CLI_SSH='ssh -o BatchMode=yes root@192.0.2.10'
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

need_root() { [ "$(id -u)" = 0 ] || die "run as root"; }
seeded() { [ -f "$RIG/auth/tdns-auth.yaml" ] || die "not seeded: run setup.sh DAEMON_ADDR"; }
build_id() { sed -n '1p' "$BIN/BUILD" 2>/dev/null; }

use() {
	[ -n "$1" ] && [ -d "$1" ] || die "usage: run.sh use ARMDIR"
	for b in tdns-auth tdns-imr tdns-ncli tdns-cli dog BUILD; do
		[ -e "$1/$b" ] || die "$1 has no $b"
	done
	daemon_stop auth; daemon_stop imr
	mkdir -p "$BIN"
	# ARMDIR may be $BIN itself: on a host short of disk the arm is unpacked
	# straight into it, and this only checks it.
	if [ "$(cd "$1" && pwd)" != "$BIN" ]; then
		for b in tdns-auth tdns-imr tdns-ncli tdns-cli dog BUILD; do cp "$1/$b" "$BIN/"; done
	fi
	chmod 0755 "$BIN" "$BIN"/tdns-* "$BIN/dog"
	echo "using: $(build_id)"
}

ship() {
	[ -n "$CLI_SSH" ] || die "set CLI_SSH"
	seeded
	tmp=$(mktemp -d /tmp/cli-access-ship.XXXXXX)
	mkdir -p "$tmp/cli-access/bin" "$tmp/cli-access/certs" "$tmp/cli-access/ncli" "$tmp/cli-access/home"
	cp -R "$SRC" "$tmp/cli-access/src"
	cp "$BIN/tdns-ncli" "$BIN/tdns-cli" "$BIN/dog" "$BIN/BUILD" "$tmp/cli-access/bin/"
	cp "$CERTS"/*.crt "$CERTS/pins.txt" "$tmp/cli-access/certs/"
	# Client keys only (raw.sh presents them); never the daemon's key.
	cp "$CERTS/ro.key" "$CERTS/rw.key" "$CERTS/off.key" "$CERTS/unknown.key" "$tmp/cli-access/certs/"
	for f in remote pins cert unknown dup cli; do cp "$RIG/ncli/$f.yaml" "$tmp/cli-access/ncli/"; done
	cp "$RIG/apikey" "$RIG/daemon-addr" "$tmp/cli-access/"
	(cd "$tmp" && tar cf - cli-access) | $CLI_SSH "
		set -e
		rm -rf $RIG; mkdir -p /var/tmp; cd /var/tmp; tar xf -
		[ -d /home ] || mkdir /home
		id $RIGUSER > /dev/null 2>&1 || useradd -m -s /bin/sh $RIGUSER
		chmod 0755 $RIG $RIG/bin $RIG/certs $RIG/ncli
		chown -R $RIGUSER $RIG/ncli $RIG/home $RIG/certs/ro.key $RIG/certs/rw.key $RIG/certs/off.key $RIG/certs/unknown.key
		chmod 0600 $RIG/ncli/*.yaml $RIG/certs/*.key
		echo shipped to \$(hostname): \$(sed -n 1p $RIG/bin/BUILD)"
	rc=$?
	rm -rf "$tmp"
	return $rc
}

start() {
	seeded
	_rc=0
	daemon_start auth || { echo "tdns-auth did not come up: see $LOG/tdns-auth.stdout"; _rc=1; }
	daemon_start imr || { echo "tdns-imr did not come up: see $LOG/tdns-imr.stdout"; _rc=1; }
	status
	return $_rc
}

stop() { daemon_stop auth; daemon_stop imr; echo "stopped"; }

status() {
	echo "build: $(build_id)"
	for d in auth imr; do
		p=$(pids_of $d)
		s=/var/run/tdns/tdns-$d.sock
		printf "tdns-%-4s pid %-7s socket %s\n" "$d" "${p:-none}" "$( [ -S $s ] && ls -l $s | cut -c1-10 || echo absent)"
	done
	if [ -n "$CLI_SSH" ]; then echo "CLI host: $(on_cli "hostname; sed -n 1p $RIG/bin/BUILD" | tr '\n' ' ')"; fi
}

clean() {
	daemon_stop auth; daemon_stop imr
	rm -f "$AUTH_SOCK" "$IMR_SOCK"
	rm -rf "$VDIR"
	rm -rf "$RIG/auth" "$RIG/imr" "$RIG/ncli" "$CERTS" "$LOG" "$RIG/home"
	echo "cleaned (bin/, src/ and runs/ kept)"
}

# ---- verify ----------------------------------------------------------------------
preflight() {
	need_root; seeded
	[ -x "$BIN/tdns-auth" ] && [ -s "$BIN/BUILD" ] || die "no build in $BIN: run.sh use ARMDIR"
	command -v openssl > /dev/null || die "openssl is needed (raw.sh)"
	# A daemon that is not the rig's, answering on the rig's socket paths,
	# would answer the root cases in its place.
	daemon_stop auth; daemon_stop imr
	for d in auth imr; do
		[ -S "/var/run/tdns/tdns-$d.sock" ] || continue
		ncli_root root $d ping > "$LOG/preflight-$d.out"
		[ "$(rc_of "$LOG/preflight-$d.out")" != 0 ] \
			|| die "another tdns-$d answers on /var/run/tdns/tdns-$d.sock: not starting"
	done
	CLIOK=0
	if [ -n "$CLI_SSH" ]; then
		cb=$(on_cli "sed -n 1p $RIG/bin/BUILD" 2>/dev/null)
		if [ "$cb" = "$(build_id)" ]; then
			CLIOK=1
		else
			echo "CLI host unreachable or on another build (\"$cb\"): run.sh ship" >&2
			exit 1
		fi
	fi
}

# remote_or_skip ID WHAT: true when the CLI host can be used; else SKIP.
remote_or_skip() { [ "$CLIOK" = 1 ] && return 0; skip "$1" "$2 (no CLI host: CLI_SSH unset)"; return 1; }

verify() {
	preflight
	[ $# -gt 0 ] || die "usage: run.sh verify socket|roles|pins|all ..."
	[ "$1" = all ] && set -- socket roles pins
	tag=$(build_id | awk '{print $1}')
	RUNDIR="$RIG/runs/$(date -u +%Y%m%d-%H%M%S)-$(echo "$*" | tr ' ' '+')-$tag"
	mkdir -p "$RUNDIR"; chmod 0755 "$RUNDIR"
	RES="$RUNDIR/results.txt"
	{
		echo "# cli-access rig, $(date -u +%FT%TZ)"
		echo "# build:       $(build_id)"
		echo "# rig:         $(cat "$SRC/REVISION" 2>/dev/null || echo "uncommitted: not a verdict")"
		echo "# daemon host: $(hostname) ($(uname -sr)), address $DAEMON_ADDR"
		[ "$CLIOK" = 1 ] && echo "# CLI host:    $(on_cli 'hostname; uname -sr' | tr '\n' ' ')"
		echo "# suites:      $*"
	} | tee "$RES"
	for s in "$@"; do
		[ -f "$SRC/suites/$s.sh" ] || die "no suite $s"
		. "$SRC/suites/$s.sh"
		echo "## suite $s" | tee -a "$RES"
		"suite_$s"
	done
	daemon_stop auth; daemon_stop imr
	cp "$LOG"/* "$RUNDIR/" 2>/dev/null
	verdict="PASS"
	[ "$NSKIP" -gt 0 ] && verdict="INCOMPLETE ($NSKIP skipped: not a verdict)"
	[ -s "$SRC/REVISION" ] || verdict="$verdict (rig not from a commit: not a verdict)"
	[ "$NFAIL" -gt 0 ] && verdict="FAIL"
	echo "# $verdict: $NPASS passed, $NFAIL failed, $NSKIP skipped; evidence in $RUNDIR" | tee -a "$RES"
	[ "$NFAIL" -eq 0 ] || exit 1
	[ "$NSKIP" -eq 0 ] || exit 2
	exit 0
}

case "$1" in
	use)    need_root; shift; use "$@" ;;
	ship)   need_root; ship ;;
	start)  need_root; start ;;
	stop)   need_root; stop ;;
	status) status ;;
	verify) shift; verify "$@" ;;
	clean)  need_root; clean ;;
	*) echo "usage: $0 {use ARMDIR|ship|start|stop|status|verify SUITE...|clean}" >&2; exit 2 ;;
esac
