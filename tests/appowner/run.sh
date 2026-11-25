#!/bin/sh
# tests/appowner/run.sh [TDNS_AUTH [TDNS_NCLI]]
#
# An application client of tdns-auth's management API, checking the API
# ownership model end to end (docs/2026-11-23-tdns-api-ownership-design.md).
# Self-contained: everything lives in one temporary directory, the daemon
# runs on ports the kernel hands out, and nothing is left running.
#
#   TDNS_AUTH, TDNS_NCLI  the binaries under test (default: what `make` builds
#                         in cmdv2/auth and cmdv2/ncli of this tree)
#   APPOWNER_KEEP=1       keep the temporary directory after a passing run
#                         (a failing run always keeps it, for its logs)
#
# Prints one PASS/FAIL line per check, then a summary. Exit status: 0 when
# every check passed, 1 on any FAIL, 2 when the rig could not be set up.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
TREE=$(cd "$HERE/../.." && pwd)
AUTH=${1:-$TREE/cmdv2/auth/tdns-auth}
NCLI=${2:-$TREE/cmdv2/ncli/tdns-ncli}

die() { echo "run.sh: $*" >&2; exit 2; }

abspath() { (cd "$(dirname "$1")" && echo "$(pwd -P)/$(basename "$1")"); }
[ -x "$AUTH" ] || die "no tdns-auth at $AUTH (build it: cd cmdv2/auth && make)"
[ -x "$NCLI" ] || die "no tdns-ncli at $NCLI (build it: cd cmdv2/ncli && make)"
AUTH=$(abspath "$AUTH")
NCLI=$(abspath "$NCLI")

# The temporary directory. Resolved (pwd -P) because the daemon reports its
# config file by its real path, and tdns-ncli compares the two. Short enough
# for the socket path's limit (104 bytes on macOS).
T=$(mktemp -d "${TMPDIR:-/tmp}/appowner.XXXXXX") || die "mktemp failed"
T=$(cd "$T" && pwd -P)
PID=""
cleanup() {
	rc=$?
	if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
		kill "$PID" 2>/dev/null
		i=0
		while kill -0 "$PID" 2>/dev/null && [ $i -lt 20 ]; do
			sleep 0.5
			i=$((i + 1))
		done
		kill -9 "$PID" 2>/dev/null
		wait "$PID" 2>/dev/null
	fi
	if [ "$rc" -eq 0 ] && [ -z "${APPOWNER_KEEP:-}" ]; then
		rm -rf "$T"
	else
		echo "run.sh: kept $T (transcript: $T/log/transcript.log, daemon log: $T/log/tdns-auth.log)"
	fi
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 2' INT TERM HUP

mkdir -p "$T/bin" "$T/certs" "$T/clients" "$T/auth" "$T/zones/dynamic" "$T/log" "$T/ncli" "$T/s" "$T/scratch" ||
	die "cannot populate $T"
chmod 700 "$T/s" # the admin socket's directory must be the daemon's alone
SETUPLOG=$T/log/setup.log
step() { # step WHAT CMD...: run CMD, logged; on failure show the log and stop
	_what=$1
	shift
	echo "\$ $*" >>"$SETUPLOG"
	if ! "$@" >>"$SETUPLOG" 2>&1; then
		echo "run.sh: setup failed: $_what" >&2
		tail -20 "$SETUPLOG" >&2
		exit 2
	fi
}

# ---- the application program, built into the temporary directory ----------
APP=$T/bin/appowner
step "build appowner" make -s -C "$HERE" BIN="$APP"

# ---- ports: DNS, the management API, and two primaries nobody answers on ----
set -- $("$APP" ports 4)
[ $# -eq 4 ] || die "could not get four free ports"
DNSPORT=$1 APIPORT=$2 PRIM1=$3 PRIM2=$4

# ---- the daemon's certificate; the applications pin it ----------------------
step "make a CA" "$NCLI" cert ca --name ca --out-dir "$T/certs"
step "make the daemon's certificate" "$NCLI" cert leaf --ca "$T/certs/ca.crt" --ca-key "$T/certs/ca.key" \
	--name daemon --dns localhost --ip 127.0.0.1 --out-dir "$T/certs"
rm -f "$T/certs/ca.key"
PIN=$("$NCLI" cert pin "$T/certs/daemon.crt" 2>>"$SETUPLOG" | tail -1)
[ -n "$PIN" ] || die "no pin for the daemon's certificate"

# ---- static zones -------------------------------------------------------------
# s1: a service zone granted to app1. s2: the config's. signed: the config's,
# signed here. cat1: a catalog zone granted to app1. cat2: the config's
# catalog zone.
for z in s1 s2 signed; do
	cat >"$T/zones/$z.test.zone" <<EOF
\$TTL 300
$z.test.		IN SOA	ns1.$z.test. hostmaster.$z.test. 2026112401 3600 600 86400 300
$z.test.		IN NS	ns1.$z.test.
ns1.$z.test.	IN A	127.0.0.1
www.$z.test.	IN A	192.0.2.10
EOF
done
for z in cat1 cat2; do
	cat >"$T/zones/$z.test.zone" <<EOF
\$TTL 300
$z.test.		IN SOA	invalid. hostmaster.invalid. 1 3600 600 86400 300
$z.test.		IN NS	invalid.
version.$z.test.	IN TXT	"2"
EOF
done

# ---- the daemon config -----------------------------------------------------------
# The access file is named but not there yet: the daemon then serves DNS and
# the socket, and the TCP API answers 503 until `client add` creates the file
# and reloads (guide/config-tdns-auth.md).
CFG=$T/auth/tdns-auth.yaml
cat >"$CFG" <<EOF
# appowner rig: written by tests/appowner/run.sh
service:
   name:       TDNS-AUTH
   verbose:    true
   debug:      false

log:
   file:       $T/log/tdns-auth.log
   level:      info

db:
   file:       $T/auth/auth.db

listeners:
   addresses:  [ 127.0.0.1:$DNSPORT ]
   transports: [ do53 ]

apiserver:
   addresses:   [ 127.0.0.1:$APIPORT ]
   apikey:      appowner-rig-test-key
   usetls:      true
   certfile:    $T/certs/daemon.crt
   keyfile:     $T/certs/daemon.key
   socket:      $T/s/auth.sock
   access-file: $T/auth/access.yaml
   app-clients: [ app1, app2 ]

imrengine:
   active:     false

dynamiczones:
   configfile:     $T/auth/dynamic-zones.yaml
   zonedirectory:  $T/zones/dynamic
   dynamic:
      allowed:  [ secondary, primary ]
      storage:  persistent

templates:
   - name:          app-primary
     type:          primary
     dynamiczones:  true
     store:         map
     zonefile:      $T/zones/dynamic/%szone
     downstreams:
        - { prefix: 127.0.0.1/32, key: NOKEY }

zones:
   - name:      s1.test.
     type:      primary
     store:     map
     zonefile:  $T/zones/s1.test.zone
     options:   [ allow-api-updates ]
     api-owner: cert:app1

   - name:      s2.test.
     type:      primary
     store:     map
     zonefile:  $T/zones/s2.test.zone
     options:   [ allow-api-updates ]

   - name:      signed.test.
     type:      primary
     store:     map
     zonefile:  $T/zones/signed.test.zone
     dnssecpolicy: default
     options:   [ online-signing ]

   - name:      cat1.test.
     type:      primary
     store:     map
     zonefile:  $T/zones/cat1.test.zone
     options:   [ catalog-zone ]
     api-owner: cert:app1

   - name:      cat2.test.
     type:      primary
     store:     map
     zonefile:  $T/zones/cat2.test.zone
     options:   [ catalog-zone ]
EOF

# ---- tdns-ncli's own config: the daemon's entry --------------------------------
NCFG=$T/ncli/tdns-ncli.yaml
ncli() { "$NCLI" --config "$NCFG" "$@"; }
step "tdns-ncli config add" ncli config add "$CFG"

# ---- start the daemon ---------------------------------------------------------------
# From the temporary directory, so that nothing the daemon writes relative to
# its working directory lands anywhere else. exec: $! is the daemon itself.
(cd "$T" && exec "$AUTH" --config "$CFG") </dev/null >"$T/log/tdns-auth.stdout" 2>&1 &
PID=$!
i=0
until ncli auth ping >>"$SETUPLOG" 2>&1; do
	kill -0 "$PID" 2>/dev/null || { tail -20 "$T/log/tdns-auth.stdout" >&2; die "tdns-auth exited"; }
	i=$((i + 1))
	[ $i -lt 60 ] || die "tdns-auth did not answer on its socket in 30s"
	sleep 0.5
done

# ---- the clients ---------------------------------------------------------------------
# Each makes its own pair, as an application does as its service account on
# its own host (design section 5, step 2), and the operator enrols it by its
# certificate on the daemon's host (step 3). app1 and app2 are named in
# apiserver.app-clients above; op is an operator.
for c in app1 app2 op; do
	step "client init $c" ncli client init --name "$c" --cert "$T/clients/$c.crt" --key "$T/clients/$c.key"
	step "client add $c" ncli auth client add "$c" --cert "$T/clients/$c.crt" --role read-write \
		--comment "appowner rig"
done

# ---- the checks ------------------------------------------------------------------------
"$APP" run \
	--api "https://127.0.0.1:$APIPORT/api/v1" \
	--pin "$PIN" \
	--clients "$T/clients" \
	--apikey appowner-rig-test-key \
	--socket "$T/s/auth.sock" \
	--daemon-config "$CFG" \
	--ncli "$NCLI" \
	--ncli-config "$NCFG" \
	--primary "127.0.0.1:$PRIM1" \
	--primary2 "127.0.0.1:$PRIM2" \
	--template app-primary \
	--transcript "$T/log/transcript.log" \
	--daemon-log "$T/log/tdns-auth.log" \
	--scratch "$T/scratch" \
	--dns "127.0.0.1:$DNSPORT"
exit $?
