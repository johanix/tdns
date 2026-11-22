#!/bin/sh
# raw.sh [options] HOST:PORT PATH: one HTTPS request, sent with openssl
# s_client, so the rig can send what tdns-ncli never would: a client
# certificate tdns-ncli of this build cannot present, no key at all, spoofed
# headers, a body over the daemon's limit. Prints "STATUS <code>" and the
# response.
#
#   -c NAME        present $RIG/certs/NAME.crt and .key as the client cert
#   -k             send the rig's API key (X-API-Key)
#   -K VALUE       send X-API-Key: VALUE
#   -H NAME=VALUE  one more header (no spaces in VALUE)
#   -b SPEC        JSON body: empty | cmd:COMMAND | cmd:COMMAND:ZONE
#   -B BYTES       a body of BYTES spaces (the size checks)
#
# Plain words only, as with ncli.sh. The server is not verified here: what
# is under test is the daemon's decision, not the CLI's.
RIG=/var/tmp/cli-access
cert="" hdrs="" body="" bigsize="" host=""
while getopts c:kK:H:b:B: o; do
	case $o in
	c) cert=$OPTARG ;;
	k) hdrs="$hdrs
X-API-Key: $(cat $RIG/apikey)" ;;
	K) hdrs="$hdrs
X-API-Key: $OPTARG" ;;
	H) case ${OPTARG%%=*} in
	   [Hh]ost) host=${OPTARG#*=} ;;   # replaces Host:, a second one is a 400
	   *) hdrs="$hdrs
${OPTARG%%=*}: ${OPTARG#*=}" ;;
	   esac ;;
	b) case $OPTARG in
	   empty) body='{}' ;;
	   cmd:*:*) c=${OPTARG#cmd:}; body="{\"Command\":\"${c%%:*}\",\"Zone\":\"${c#*:}\"}" ;;
	   cmd:*) body="{\"Command\":\"${OPTARG#cmd:}\"}" ;;
	   *) echo "raw.sh: bad body spec $OPTARG" >&2; exit 2 ;;
	   esac ;;
	B) bigsize=$OPTARG ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 2 ] || { echo "usage: raw.sh [-c cert] [-k] [-H n=v] [-b spec] [-B n] host:port path" >&2; exit 2; }
hp=$1 path=$2
[ -n "$host" ] || host=$hp

# In the user's own rig directory, not /tmp: the size case writes 64 MiB.
tmp=$(mktemp -d "$RIG/home/raw.XXXXXX" 2>/dev/null || mktemp -d /tmp/raw.XXXXXX) || exit 1
trap 'rm -rf "$tmp"' EXIT
if [ -n "$bigsize" ]; then
	head -c "$bigsize" /dev/zero | tr '\0' ' ' > "$tmp/body"
else
	printf '%s' "$body" > "$tmp/body"
fi
len=$(wc -c < "$tmp/body" | tr -d ' ')
{
	printf 'POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n' "$path" "$host"
	printf 'Content-Length: %s\r\nConnection: close\r\n' "$len"
	[ -n "$hdrs" ] && printf '%s\n' "$hdrs" | sed '/^$/d' | while IFS= read -r h; do printf '%s\r\n' "$h"; done
	printf '\r\n'
} > "$tmp/hdr"

certargs=""
[ -n "$cert" ] && certargs="-cert $RIG/certs/$cert.crt -key $RIG/certs/$cert.key"
# -ign_eof: keep reading after our request is sent, until the daemon closes.
cat "$tmp/hdr" "$tmp/body" | openssl s_client -connect "$hp" -quiet -ign_eof $certargs > "$tmp/resp" 2> "$tmp/err"
code=$(sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$tmp/resp" | tr -d '\r')
echo "STATUS ${code:-none}"
tr -d '\r' < "$tmp/resp" | sed -n '1,12p'
[ -n "$code" ] || sed -n '1,5s/^/tls: /p' "$tmp/err"
