#!/bin/sh
# setup.sh DAEMON_ADDR: seed the cli-access rig on the DAEMON host, as root.
#
# DAEMON_ADDR is this host's address as the CLI host reaches it. It goes into
# the daemons' apiserver.addresses and the server certificate, never into the
# repository.
#
# Needs the build under test in /var/tmp/cli-access/bin first (run.sh use
# ARMDIR): tdns-cli mints the certificates. Mints a CA, the daemon's
# certificate, a second server certificate (for the wrong-pin case) and four
# client certificates, and writes the configs with the pins filled in. No
# key material is committed: it is made here, per host.
#
# Re-running wipes the daemons' state, the CLI configs and the certificates;
# the binaries and earlier runs/ are kept. The CLI host is seeded from here
# by "run.sh ship".
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

[ "$(id -u)" = 0 ] || die "run as root (the daemons and the socket are root's)"
[ $# -eq 1 ] || die "usage: setup.sh DAEMON_ADDR"
ADDR=$1
case $ADDR in *:*) HP="[$ADDR]" ;; *) HP=$ADDR ;; esac
CLI="$BIN/tdns-cli"
[ -x "$CLI" ] || die "no $CLI: run.sh use ARMDIR first"

# The rig's own files, wherever this was run from. $SRC is replaced, not
# merged into: a REVISION left from an earlier copy would label this one.
if [ "$HERE" != "$SRC" ]; then
	rm -rf "$SRC"
	mkdir -p "$SRC"
	cp -R "$HERE"/. "$SRC"/
fi

rm -rf "$RIG/auth" "$RIG/imr" "$RIG/ncli" "$CERTS" "$LOG" "$RIG/home"
mkdir -p "$RIG/auth" "$RIG/imr" "$RIG/ncli" "$CERTS" "$LOG" "$RIG/runs" "$RIG/home"
chmod 0755 "$RIG" "$RIG/auth" "$RIG/imr" "$RIG/ncli" "$CERTS" "$LOG" "$RIG/runs"
echo "$ADDR" > "$RIG/daemon-addr"
echo "cli-access-rig-test-key" > "$RIG/apikey"   # the test key; it is in the configs too
chmod 0644 "$RIG/apikey" "$RIG/daemon-addr"

# The ordinary user.
if ! id "$RIGUSER" > /dev/null 2>&1; then
	[ -d /home ] || mkdir /home
	useradd -m -s /bin/sh "$RIGUSER"
	echo "created user $RIGUSER"
fi
chown "$RIGUSER" "$RIG/home"

# ---- PKI --------------------------------------------------------------------
"$CLI" cert ca --name ca --out-dir "$CERTS" > /dev/null
leaf() {   # leaf NAME [extra args]
	_n=$1; shift
	"$CLI" cert leaf --ca "$CERTS/ca.crt" --ca-key "$CERTS/ca.key" --name "$_n" \
		--out-dir "$CERTS" "$@" > /dev/null
}
leaf daemon --dns localhost --ip 127.0.0.1 --ip "$ADDR"
leaf other --dns localhost --ip 127.0.0.1 --ip "$ADDR"   # same names, another key
for c in ro rw off unknown; do leaf "$c" --client; done
rm -f "$CERTS/ca.key"   # nothing else is ever signed
pin() { "$CLI" cert pin "$CERTS/$1.crt" | tail -1; }
PIN_DAEMON=$(pin daemon) PIN_OTHER=$(pin other)
PIN_RO=$(pin ro) PIN_RW=$(pin rw) PIN_OFF=$(pin off) PIN_UNKNOWN=$(pin unknown)
# The daemon's key is root's; the client keys are for raw.sh, run as the user.
chmod 0644 "$CERTS"/*.crt
chmod 0600 "$CERTS"/*.key
chown "$RIGUSER" "$CERTS/ro.key" "$CERTS/rw.key" "$CERTS/off.key" "$CERTS/unknown.key"
{
	echo "daemon  $PIN_DAEMON"; echo "other   $PIN_OTHER"
	echo "ro      $PIN_RO"; echo "rw      $PIN_RW"
	echo "off     $PIN_OFF"; echo "unknown $PIN_UNKNOWN"
} > "$CERTS/pins.txt"

# ---- configs ------------------------------------------------------------------
subst() {
	sed -e "s|@DAEMON@|$HP|g" -e "s|@PIN_DAEMON@|$PIN_DAEMON|g" -e "s|@PIN_OTHER@|$PIN_OTHER|g" \
	    -e "s|@PIN_RO@|$PIN_RO|g" -e "s|@PIN_RW@|$PIN_RW|g" -e "s|@PIN_OFF@|$PIN_OFF|g" "$1"
}
subst "$SRC/tdns-auth.yaml" > "$RIG/auth/tdns-auth.yaml"
subst "$SRC/tdns-imr.yaml"  > "$RIG/imr/tdns-imr.yaml"
cp "$SRC/cli-access.test.zone" "$RIG/auth/"
subst "$SRC/access.yaml" > "$RIG/auth/access.seed"
# config add, run as the user, reads the daemon configs (the key and, from
# #1168, the certificate for the pin). In this rig they hold only test values.
chmod 0644 "$RIG/auth/tdns-auth.yaml" "$RIG/imr/tdns-imr.yaml" "$RIG/auth/access.seed"

cp "$SRC/ncli-root.yaml" "$RIG/ncli/root.yaml"
subst "$SRC/ncli-local.yaml" > "$RIG/ncli/local.yaml"
cp "$SRC/ncli-root.yaml" "$RIG/ncli/usersock.yaml"   # the user, pointed at the socket
for f in remote pins cert unknown dup; do subst "$SRC/ncli-$f.yaml" > "$RIG/ncli/$f.yaml"; done
subst "$SRC/cli-remote.yaml" > "$RIG/ncli/cli.yaml"
chmod 0600 "$RIG/ncli"/*.yaml
chown "$RIGUSER" "$RIG/ncli/local.yaml" "$RIG/ncli/usersock.yaml"

# /var/run/tdns: the daemon creates it 0700 when missing. One that is there
# already and open to others would make every socket case fail for a reason
# that is not the build's, so say so now.
if [ -d /var/run/tdns ]; then
	m=$(ls -ld /var/run/tdns | cut -c1-10)
	[ "$m" = drwx------ ] || echo "WARNING: /var/run/tdns is $m; the daemons will refuse it (0700 needed)"
fi

echo "seeded $RIG for daemon address $ADDR"
sed 's/^/  pin /' "$CERTS/pins.txt"
echo "next: CLI_SSH='ssh root@<cli-host>' sh $SRC/run.sh ship"
