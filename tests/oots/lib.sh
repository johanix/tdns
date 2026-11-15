# Shared code for the OOTS transport-signal rig. Sourced by run.sh and by
# every suite. See README.md.
#
# Everything here runs INSIDE the rig's network namespace (run.sh enters it),
# where the whole of 127.0.0.0/8 is local and port 53 needs no privilege.

WORK="${WORK:-/var/tmp/oots-rig}"
APIKEY="oots-rig"

# ---------------------------------------------------------------------------
# Binaries. BIN is a directory holding tdns-auth, tdns-imr, tdns-cli and dog;
# each role can be pointed elsewhere on its own, so one run can mix versions:
#   AUTH      every authoritative server the rig starts, unless overridden
#   AUTH_PUB  publishers: the primary servers whose signal is under test
#   AUTH_SEC  secondaries: servers that re-serve a zone they transferred
#   AUTH_INFRA the rig's own root server
#   IMR       the resolver under test
#   CLI, DOG  the observers; CLI_IMR and CLI_PUB, the CLIs that talk to the
#             resolver and to the publishers, default to their daemons' builds
# A run on a step's base is the same suite with one role pointed at the base
# build, for example IMR=/path/to/main/tdns-imr.
# ---------------------------------------------------------------------------
BIN="${BIN:-}"
_bin() { # name -> default path
	if [ -n "$BIN" ]; then echo "$BIN/$1"; else command -v "$1" || echo "$1"; fi
}
AUTH="${AUTH:-$(_bin tdns-auth)}"
AUTH_PUB="${AUTH_PUB:-$AUTH}"
AUTH_SEC="${AUTH_SEC:-$AUTH}"
AUTH_INFRA="${AUTH_INFRA:-$AUTH}"
IMR="${IMR:-$(_bin tdns-imr)}"
CLI="${CLI:-$(_bin tdns-cli)}"
# The CLI that talks to a daemon comes from that daemon's build. The API
# between them has no compatibility promise, and tdns-cli decodes a report into
# its own types: an older CLI drops a newer daemon's fields without a word.
# Each defaults to the tdns-cli beside the daemon's binary, else to CLI.
_cli_of() { # daemon binary -> its tdns-cli
	if [ -x "$(dirname "$1")/tdns-cli" ]; then echo "$(dirname "$1")/tdns-cli"; else echo "$CLI"; fi
}
CLI_IMR="${CLI_IMR:-$(_cli_of "$IMR")}"
CLI_PUB="${CLI_PUB:-$(_cli_of "$AUTH_PUB")}"
DOG="${DOG:-$(_bin dog)}"

# ---------------------------------------------------------------------------
# Verdicts. One line per assertion. SKIP is a precondition that did not hold;
# it is never counted as a pass.
# ---------------------------------------------------------------------------
NPASS=0; NFAIL=0; NSKIP=0
pass() { NPASS=$((NPASS + 1)); echo "PASS  $*"; }
fail() { NFAIL=$((NFAIL + 1)); echo "FAIL  $*"; }
skip() { NSKIP=$((NSKIP + 1)); echo "SKIP  $*"; }
check() { # id text cmd... : PASS when cmd succeeds
	local _id _txt
	_id="$1"; _txt="$2"; shift 2
	if "$@"; then pass "$_id $_txt"; else fail "$_id $_txt"; fi
}
note() { printf "      %s\n" "$*"; }
die() { echo "rig: $*" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Processes. Every daemon the rig starts is recorded in $WORK/pids, so a suite
# can stop exactly what it started, and run.sh can refuse to start over a
# daemon that is still running.
# ---------------------------------------------------------------------------
PIDS="$WORK/pids"

start_daemon() { # name binary config
	local _n _b _c
	_n="$1"; _b="$2"; _c="$3"
	[ -x "$_b" ] || die "not executable: $_b"
	( cd "$WORK/$_n" && exec "$_b" --config "$_c" ) > "$WORK/$_n/stdout.log" 2>&1 &
	echo "$! $_n" >> "$PIDS"
}

stop_daemons() {
	local _p _n
	[ -f "$PIDS" ] || return 0
	while read -r _p _n; do kill "$_p" 2>/dev/null; done < "$PIDS"
	sleep 1
	while read -r _p _n; do kill -9 "$_p" 2>/dev/null; done < "$PIDS"
	rm -f "$PIDS"
}

# One daemon, by name, out of $PIDS, so a suite can restart a party while the
# rig root keeps running.
stop_daemon() { # name
	local _p
	[ -f "$PIDS" ] || return 0
	for _p in $(awk -v n="$1" '$2 == n { print $1 }' "$PIDS"); do kill "$_p" 2>/dev/null; done
	sleep 1
	for _p in $(awk -v n="$1" '$2 == n { print $1 }' "$PIDS"); do kill -9 "$_p" 2>/dev/null; done
	awk -v n="$1" '$2 != n' "$PIDS" > "$PIDS.new" && mv "$PIDS.new" "$PIDS"
}

alive() { # name: the daemon of that name is running
	local _p
	[ -f "$PIDS" ] || return 1
	_p=$(awk -v n="$1" '$2 == n { print $1 }' "$PIDS" | tail -1)
	[ -n "$_p" ] && kill -0 "$_p" 2>/dev/null
}

wait_for() { # seconds cmd... : poll until cmd succeeds
	local _t
	_t="$1"; shift
	while [ "$_t" -gt 0 ]; do
		"$@" >/dev/null 2>&1 && return 0
		sleep 1; _t=$((_t - 1))
	done
	return 1
}

# ---------------------------------------------------------------------------
# Queries.
# ---------------------------------------------------------------------------
dogq() { # server name type [opts...]
	local _s _q _t
	_s="$1"; _q="$2"; _t="$3"; shift 3
	"$DOG" "@$_s" "$_q" "$_t" +time=3 +tries=1 "$@" 2>&1
}

# The RDATA of the answer's RRs of one type, one per line, sorted: the part of
# each answer line after "IN <TYPE>". Order-free, so it compares sets.
rdata() { # server name type [opts...]
	local _t
	_t="$3"
	dogq "$@" | awk -v t="$_t" '
		$1 ~ /^;/ { next }
		{ for (i = 1; i <= NF; i++) if ($i == "IN" && $(i + 1) == t) {
			s = ""; for (j = i + 2; j <= NF; j++) s = s (s == "" ? "" : " ") $j
			print s; break } }' | sort
}

# The same, in the order the server sent them.
rdata_ordered() { # server name type [opts...]
	local _t
	_t="$3"
	dogq "$@" | awk -v t="$_t" '
		$1 ~ /^;/ { next }
		{ for (i = 1; i <= NF; i++) if ($i == "IN" && $(i + 1) == t) {
			s = ""; for (j = i + 2; j <= NF; j++) s = s (s == "" ? "" : " ") $j
			print s; break } }'
}

answers() { # server name type: zero when the server answers NOERROR with data
	[ -n "$(rdata "$@")" ]
}

# ---------------------------------------------------------------------------
# The resolver's view: tdns-cli imr stats auth-transports --json, read with
# python3. at_get server expr prints one value, empty when absent.
#   expr: counts.dot | failed.dot | signal.dot | signal_ports.dot | total
# ---------------------------------------------------------------------------
cli_imr() { "$CLI_IMR" --config "$WORK/q/tdns-cli.yaml" imr "$@"; }

at_json() { cli_imr stats auth-transports --json 2>/dev/null; }

at_get() { # server expr
	at_json | python3 -I -c '
import json, sys
srv, expr = sys.argv[1], sys.argv[2]
try:
    rep = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for row in rep.get("rows") or []:
    if row.get("server") != srv:
        continue
    v = row
    for part in expr.split("."):
        v = v.get(part) if isinstance(v, dict) else None
        if v is None:
            break
    if v is not None:
        print(v)
    break
' "$1" "$2"
}

num() { # value -> integer, empty as 0
	case "$1" in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac
}

# The resolver must have learnt a signal before a suite counts transports:
# a lookup of _dns.<ns> runs off the query path.
has_signal() { [ -n "$(at_get "$1" signal)" ]; }
wait_signal() { wait_for "$2" has_signal "$1"; }

# ---------------------------------------------------------------------------
# Config writers. A suite composes a daemon's config from these fragments,
# so each one shows exactly the knobs it sets.
# ---------------------------------------------------------------------------
y_service() { # name identities [type signal [ports]]
	local _kv
	echo "service:"
	echo "   name:       $1"
	echo "   identities: [ $2 ]"
	echo "   verbose:    true"
	if [ -n "$3" ]; then
		echo "   transport:"
		echo "      type:   $3"
		echo "      signal: \"$4\""
		if [ -n "$5" ]; then
			echo "      ports:"
			for _kv in $5; do echo "         ${_kv%%:*}: ${_kv#*:}"; done
		fi
	fi
}

y_listeners() { # "addr ..." "transport ..." "transport:port ..."
	local _a _t _x _kv
	_a=""; for _x in $1; do _a="$_a${_a:+, }$_x:53"; done
	_t="do53"; for _x in $2; do _t="$_t, $_x"; done
	echo "listeners:"
	echo "   addresses:  [ $_a ]"
	echo "   transports: [ $_t ]"
	if [ -n "$3" ]; then
		echo "   ports:"
		for _kv in $3; do echo "      ${_kv%%:*}: [ ${_kv#*:} ]"; done
	fi
	echo "   certfile:   $WORK/certs/rig.crt"
	echo "   keyfile:    $WORK/certs/rig.key"
}

y_common() { # name api-address
	cat <<EOF
apiserver:
   addresses:  [ $2:8080 ]
   apikey:     $APIKEY
   certfile:   $WORK/certs/rig.crt
   keyfile:    $WORK/certs/rig.key

imrengine:
   active:     false

db:
   file:       $WORK/$1/auth.db

log:
   file:       $WORK/$1/tdns-auth.log
   level:      ${LOGLEVEL:-info}

dnssec:
   policies:
      rig:
         algorithm:  ED25519
         ksk:
            lifetime:  forever
         zsk:
            lifetime:  forever
         csk:
            lifetime:  none
         sigvalidity:
            default:  14d
            dnskey:   30d
            ds:       14d

EOF
}

y_zones() { echo "zones:"; }

y_primary() { # zone [options] [notify-addr] : unsigned unless options name online-signing
	echo "   - name:      $1"
	echo "     type:      primary"
	echo "     zonefile:  $ZDIR/$1zone"
	echo "     store:     map"
	if [ -n "$2" ]; then
		echo "     options:   [ $2 ]"
		case "$2" in *online-signing*) echo "     dnssecpolicy: rig" ;; esac
	fi
	if [ -n "$3" ]; then
		echo "     notify:"
		echo "        - addr: \"$3:53\""
		echo "          key:  NOKEY"
	fi
	echo "     downstreams:"
	echo "        - prefix: \"127.0.0.0/8\""
	echo "          key:    NOKEY"
}

y_secondary() { # zone primary-addr
	echo "   - name:      $1"
	echo "     type:      secondary"
	echo "     store:     map"
	echo "     upstreams:"
	echo "        - addr: \"$2:53\""
	echo "          key:  NOKEY"
	echo "     allow-notify:"
	echo "        - prefix: \"127.0.0.0/8\""
	echo "          key:    NOKEY"
	echo "     downstreams:"
	echo "        - prefix: \"127.0.0.0/8\""
	echo "          key:    NOKEY"
}

cli_conf() { # name api-address role
	cat > "$WORK/$1/tdns-cli.yaml" <<EOF
apiservers:
   - name:        $3
     baseurl:     https://$2:8080/api/v1
     authmethod:  X-API-Key
     apikey:      $APIKEY
     # The rig's own loopback, inside its own namespace: no CA to check.
     rootca:      insecure
EOF
}

# A zone file with an SOA, the NS set and their addresses. Extra lines from
# stdin follow. Names are relative to the origin.
zonefile() { # zone "nsname=addr ..." [ttl]
	local _z _ttl _ns
	_z="$1"; _ttl="${3:-60}"
	echo "\$ORIGIN $_z"
	echo "\$TTL $_ttl"
	echo "@ IN SOA ${2%%=*} hostmaster ${SERIAL:-1} 60 30 3600 30"
	for _ns in $2; do echo "@ IN NS ${_ns%%=*}"; done
	for _ns in $2; do
		case "${_ns%%=*}" in *.$_z) echo "${_ns%%=*} IN A ${_ns#*=}" ;; esac
	done
	cat
}

# One auth daemon: dir, config from stdin, start, wait until it answers the SOA
# of the zone named.
auth_up() { # name binary address zone
	mkdir -p "$WORK/$1"
	cat > "$WORK/$1/tdns-auth.yaml"
	cli_conf "$1" "$3" tdns-auth
	start_daemon "$1" "$2" "$WORK/$1/tdns-auth.yaml"
	if ! wait_for 20 answers "$3" "$4" SOA; then
		echo "rig: $1 did not answer $4 SOA at $3; its log:" >&2
		tail -15 "$WORK/$1/tdns-auth.log" "$WORK/$1/stdout.log" >&2 2>/dev/null
		return 1
	fi
}

# The resolver. Fresh state for every suite: its cache and every signal it
# learnt are gone with the process.
imr_up() {
	mkdir -p "$WORK/q"
	cat > "$WORK/q/tdns-imr.yaml" <<EOF
listeners:
   addresses:  [ 127.0.0.100:53 ]
   transports: [ do53 ]

imrengine:
   root-hints:        $WORK/infra/root.hints
   trust-anchor-file: $WORK/infra/root.ta
   outbound-address-families: [ ipv4 ]
   options: [ always-query-for-transport, allow-loopback-nameservers ]

apiserver:
   addresses:  [ 127.0.0.100:8080 ]
   apikey:     $APIKEY
   certfile:   $WORK/certs/rig.crt
   keyfile:    $WORK/certs/rig.key

log:
   file:       $WORK/q/tdns-imr.log
   level:      ${LOGLEVEL:-info}
EOF
	cli_conf q 127.0.0.100 tdns-imr
	start_daemon q "$IMR" "$WORK/q/tdns-imr.yaml"
	if ! wait_for 20 answers 127.0.0.100 . SOA; then
		echo "rig: the resolver does not answer; its log:" >&2
		tail -15 "$WORK/q/tdns-imr.log" "$WORK/q/stdout.log" >&2 2>/dev/null
		return 1
	fi
}

# The rig's root server. setup.sh made its zone and keys.
infra_up() {
	cp "$WORK/infra/root.zone.src" "$WORK/infra/zones/.zone"
	start_daemon infra "$AUTH_INFRA" "$WORK/infra/tdns-auth.yaml"
	wait_for 20 answers 127.0.0.2 . SOA || die "the rig root does not answer"
}

# Queries through the resolver, each for a name not asked before, so each one
# reaches the authoritative server.
load() { # zone count [prefix]
	local _i
	_i=1
	while [ "$_i" -le "$2" ]; do
		dogq 127.0.0.100 "${3:-q}$_i.$1" A >/dev/null
		_i=$((_i + 1))
	done
}
