# lib.sh: shared by setup.sh, run.sh and the suites. Sourced, not run.
#
# Everything lives under one fixed work root. The committed configs name
# absolute paths under it, so they read as they run.

RIG=/var/tmp/cli-access
SRC=$RIG/src                 # the rig's own files, as copied to each host
BIN=$RIG/bin                 # the build under test (run.sh use <arm>)
CERTS=$RIG/certs
LOG=$RIG/log

# The ordinary (non-root) user that runs tdns-ncli on both hosts.
RIGUSER="${RIGUSER:-cliacc}"

AUTH_API=8991   # tdns-auth management API, TLS
IMR_API=8992    # tdns-imr management API, plain http
AUTH_DNS=5391
IMR_DNS=5392
AUTH_SOCK=/var/run/tdns/tdns-auth.sock
IMR_SOCK=/var/run/tdns/tdns-imr.sock
ZONE=cli-access.test.

# Variant socket paths live under a directory of the rig's own, so a variant
# that needs a bad directory never touches /var/run/tdns.
VDIR=/var/run/cli-access-rig

# How to reach the CLI host, as root, without a password. Unset: every case
# that needs the CLI host is SKIP, and a suite with a SKIP is not a verdict.
CLI_SSH="${CLI_SSH:-}"
# The daemon host's address as the CLI host reaches it (setup.sh records it).
DAEMON_ADDR="${DAEMON_ADDR:-$(cat $RIG/daemon-addr 2>/dev/null || :)}"   # || : for set -e callers

die() { echo "error: $*" >&2; exit 1; }

# ---- results ----------------------------------------------------------------
# One line per assertion: PASS|FAIL|SKIP <id> <what>. A FAIL is followed by
# the evidence (indented "| " lines): the command's output, and where useful
# the daemon log lines of the moment.
NPASS=0 NFAIL=0 NSKIP=0
RES=/dev/null

pass() { echo "PASS $1 $2" | tee -a "$RES"; NPASS=$((NPASS + 1)); }
skip() { echo "SKIP $1 $2" | tee -a "$RES"; NSKIP=$((NSKIP + 1)); }
fail() {
	echo "FAIL $1 $2" | tee -a "$RES"
	NFAIL=$((NFAIL + 1))
	shift 2
	for f in "$@"; do
		[ -s "$f" ] && sed -n '1,25s/^/    | /p' "$f" | tee -a "$RES"
	done
	return 0
}
# judge ID WHAT RESULT [evidence files...]: RESULT is 0 for pass.
judge() {
	_id=$1 _what=$2 _r=$3; shift 3
	if [ "$_r" -eq 0 ]; then pass "$_id" "$_what"; else fail "$_id" "$_what" "$@"; fi
}

# A scratch file per case, kept with the run.
out() { echo "$RUNDIR/$1.out"; }

# ---- running things ------------------------------------------------------------
# ncli.sh prints the command's output and then "RC=<exit status>".
rc_of() { sed -n 's/^RC=//p' "$1" | tail -1; }

# Local tdns-ncli/tdns-cli as root, or as the ordinary user.
ncli_root() { sh "$SRC/ncli.sh" "$@"; }
ncli_user() { su "$RIGUSER" -c "sh $SRC/ncli.sh $*"; }

# The same on the CLI host (always as the ordinary user: a remote operator).
on_cli() { [ -n "$CLI_SSH" ] || return 97; $CLI_SSH "$*"; }
ncli_remote() { on_cli "su $RIGUSER -c 'sh $SRC/ncli.sh $*'"; }
raw_remote() { on_cli "su $RIGUSER -c 'sh $SRC/raw.sh $*'"; }
raw_local() { su "$RIGUSER" -c "sh $SRC/raw.sh $*"; }

# HTTP status from raw.sh output ("STATUS 403").
status_of() { sed -n 's/^STATUS //p' "$1" | head -1; }

# ---- daemons --------------------------------------------------------------------
# [t]dns-...: the pattern does not match the command line it is written on.
pids_of() { pgrep -f "[t]dns-$1 --config $RIG/" 2>/dev/null; }

daemon_stop() {   # daemon_stop auth|imr [KILL]
	_p=$(pids_of "$1")
	[ -n "$_p" ] || return 0
	kill ${2:+-9} $_p 2>/dev/null
	for _i in 1 2 3 4 5 6 7 8 9 10; do
		[ -z "$(pids_of "$1")" ] && return 0
		sleep 1
	done
	kill -9 $(pids_of "$1") 2>/dev/null
	sleep 1
}

# daemon_start auth|imr [config]: starts it from its own directory and waits
# until it answers DNS (up to 20 s). Returns 1 if the process is gone by then.
daemon_start() {
	_d=$1 _cfg=${2:-$RIG/$1/tdns-$1.yaml}
	[ -z "$(pids_of "$_d")" ] || die "tdns-$_d is already running: stop it first"
	: > "$LOG/tdns-$_d.log"
	echo "=== $(date -u +%FT%TZ) start $_cfg" >> "$LOG/tdns-$_d.stdout"
	(cd "$RIG/$_d" && nohup "$BIN/tdns-$_d" --config "$_cfg" \
		< /dev/null >> "$LOG/tdns-$_d.stdout" 2>&1 &)
	_port=$AUTH_DNS; [ "$_d" = imr ] && _port=$IMR_DNS
	for _i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		sleep 1
		[ -n "$(pids_of "$_d")" ] || return 1
		dns_answers "$_d" && { sleep 1; return 0; }
	done
	[ -n "$(pids_of "$_d")" ]
}

# DNS still served: auth answers its zone's SOA, imr answers anything at all
# (it may have no route to the root servers; SERVFAIL is still an answer).
dns_answers() {
	if [ "$1" = auth ]; then
		"$BIN/dog" @127.0.0.1:$AUTH_DNS $ZONE SOA 2>/dev/null | grep -q SOA
	else
		"$BIN/dog" @127.0.0.1:$IMR_DNS . NS 2>/dev/null | grep -qi 'status\|rcode\|NS'
	fi
}

# The daemon log lines written since a mark, for evidence.
log_mark() { wc -l < "$LOG/tdns-$1.log" 2>/dev/null | tr -d ' '; }
log_since() {   # log_since auth MARK > file
	tail -n +"$(( ${2:-0} + 1 ))" "$LOG/tdns-$1.log" 2>/dev/null
}
