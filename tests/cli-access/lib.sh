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
	for _f in "$@"; do   # not $f: the suites use f for the file under test
		[ -s "$_f" ] && sed -n '1,25s/^/    | /p' "$_f" | tee -a "$RES"
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

# flat FILE: FILE as one line, runs of blanks squeezed: for phrases that
# tdns-ncli's output may wrap (#1184 wraps at 72 columns).
flat() { tr '\n' ' ' < "$1" | tr -s ' '; }

# HTTP status from raw.sh output ("STATUS 403").
status_of() { sed -n 's/^STATUS //p' "$1" | head -1; }

# newcli: the build under test has #1168's revised routing (tdns-ncli --tcp,
# 2026-11-23): every daemon serves an admin socket unless told "socket: none",
# by default named after its config file's whole path; root's TCP entry with
# config-file: reaches the daemon over that socket; config add always writes
# the TCP entry; ping says on one line how it got in, over the socket the
# socket's path alone ("pong (/var/run/tdns/x.sock) from ..."). The rig
# follows #1168 heads from 2bab8aa3 on; a build between 6afcc580 and
# 2bab8aa3 is neither.
newcli() { "$BIN/tdns-ncli" --help 2>&1 | grep -q -- '--tcp'; }
# defcert: the build has #1182's default API certificate: with neither
# apiserver.certfile nor keyfile, the daemon writes {confdir}/certs/{config
# name}-api.{crt,key} at its first start. certadd: the build has #1200's
# config add (the cert setup design, section 4): run as root on the daemon's
# host, for a running daemon it makes the operator's client pair, has the
# daemon enrol its pin over the local socket, checks it over TCP and writes
# one certificate entry (pins, config-file:, no key); a stopped daemon gets an
# entry with config-file: only; an entry already there is left alone. It needs
# the socket and an access file. Both are asked of tdns-ncli's own messages.
# (#1184's earlier config add, closed unmerged, is no longer recognised.)
defcert() { grep -q 'the daemon writes a self-signed pair' "$BIN/tdns-ncli"; }
certadd() { grep -q 'config update <entry> --cert' "$BIN/tdns-ncli"; }
# certupdate: the build has #1202's config update <entry> (--cert | --repin)
# (the design, section 5): root, daemon running; --cert turns an entry into a
# certificate entry in place, --repin replaces its pins with the served ones.
certupdate() { grep -q 'update <entry> (--cert | --repin)' "$BIN/tdns-ncli"; }
# firstenrol: the daemon knows the first enrolment (from #1198 ee2d40b6): its
# config names an access file that is not there yet, and the list says so
# and that client add creates it (config add goes on to that add).
firstenrol() { grep -q 'which does not exist yet: client add creates it' "$BIN/tdns-auth"; }
# ncli_bare OUT ARGS...: tdns-ncli as root with no CLI config (from a directory
# without one), its output and an RC= line in OUT.
ncli_bare() { _o=$1; shift; { (cd /var/tmp && "$BIN/tdns-ncli" "$@"); echo "RC=$?"; } > "$_o" 2>&1; }
# The pin of one of the rig's certificates, by name (setup.sh's pins.txt).
# Here, not in a suite, since run.sh sources each suite just before it runs:
# the socket suite runs before pins.
pinof() { awk -v n="$1" '$1==n{print $2}' "$CERTS/pins.txt"; }
# The SPKI pin of a certificate file, as the rig computes it (setup.sh).
pin_of_cert() { "$BIN/tdns-cli" cert pin "$1" 2>/dev/null | tail -1; }
# client_block FILE CERT KEY: a CLI config holding only a client: block. On a
# certadd build every config add the rig runs starts from one, so the client
# pair it makes is the rig's (root's default pair would go under /etc/tdns).
client_block() {
	printf 'client:\n   cert:          %s\n   key:           %s\n' "$2" "$3" > "$1"
	chmod 0600 "$1"
}
# addfile FILE [user]: before a config add into FILE (which it removes): on a
# certadd build, FILE starts as a client: block on the rig's paths.
addfile() {
	rm -f "$1"
	certadd || return 0
	if [ "$2" = user ]; then
		client_block "$1" "$RIG/home/user-client.crt" "$RIG/home/user-client.key"; chown "$RIGUSER" "$1"
	else
		client_block "$1" "$RIG/ncli/root-client.crt" "$RIG/ncli/root-client.key"
	fi
}
# The default socket of a config file (tdns.ApiSocketPath, for the rig's
# paths: letters, digits, ".", "-" and "/" only).
default_sock() { echo "/var/run/tdns/$(echo "$1" | sed 's|^/||; s|/|_|g').sock"; }

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
