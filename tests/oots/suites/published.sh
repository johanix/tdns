# Suite published: what tdns-auth publishes from service.transport. Scenarios
# K1 and M3.
#
# Parties, each a tdns-auth serving pub.test. as ns1.pub.test. on an address
# of its own, its signal synthesized by add-transport-signal:
#   pub-a     127.0.0.51  AUTH_PUB, signal "doq:20,dot:10", no ports
#   pub-b     127.0.0.52  AUTH_PUB, signal "dot:10,doh:5,doq:20", ports dot 1234,
#                         doh 8443
#   pub-c     127.0.0.53  AUTH_PUB, pub-a's signal with ports dot 853: the
#                         standard port, which counts as absent
#   pub-d     127.0.0.55  AUTH_PUB, signal "do53:100,tcp:30,dot:10", no ports
#                         (PUB_DO53=omitted only: the build knows udp and tcp)
#   pub-base  127.0.0.54  AUTH_BASE (when set), pub-a's config
#
# PUB_DO53 says what the publisher under test does with a do53 its config
# does not name:
#   written   (default) builds before OOTS S5: the default do53:100 is written
#             out in the record without a port
#   omitted   S5 and later: absent means 100, so nothing is written for it; a
#             named do53 is written as udp and tcp
#
# Done: ask each for _dns.ns1.pub.test. SVCB. No resolver.
#
# Observed:
#   K1  pub-b publishes one record per ported transport and one record without
#       a port for the rest; every transport is in exactly one record. pub-c
#       publishes exactly what pub-a does. With PUB_DO53=written the record
#       without a port states do53:100; with omitted it has no do53, and pub-d
#       publishes udp:100 and tcp:30 (the named tcp wins over do53's 100). No
#       record names do53 beside udp or tcp.
#   M3  pub-a publishes what the same config publishes on AUTH_BASE (the base
#       build, e.g. main): byte for byte with PUB_DO53=written; with omitted,
#       the base's records with their do53 entry taken out.
#
# Negative: a publisher that ignored ports would fail K1, one that changed the
# default layout would fail M3, and one that wrote the default do53 out (or
# left it out) against PUB_DO53 fails both. SKIP for M3 when AUTH_BASE is not
# set.

PUB_DO53="${PUB_DO53:-written}"

suite_published() {
	case "$PUB_DO53" in
	written|omitted) ;;
	*) fail "published: PUB_DO53 is '$PUB_DO53'; it must be written or omitted"; return ;;
	esac
	note "PUB_DO53=$PUB_DO53"

	_pub_up pub-a 127.0.0.51 "$AUTH_PUB" "doq:20,dot:10" "" || return
	_pub_up pub-b 127.0.0.52 "$AUTH_PUB" "dot:10,doh:5,doq:20" "dot:1234 doh:8443" || return
	_pub_up pub-c 127.0.0.53 "$AUTH_PUB" "doq:20,dot:10" "dot:853" || return

	a=$(rdata 127.0.0.51 _dns.ns1.pub.test. SVCB)
	b=$(rdata 127.0.0.52 _dns.ns1.pub.test. SVCB)
	c=$(rdata 127.0.0.53 _dns.ns1.pub.test. SVCB)
	note "pub-a: $(echo "$a" | tr '\n' '|')"
	note "pub-b: $(echo "$b" | tr '\n' '|')"
	note "pub-c: $(echo "$c" | tr '\n' '|')"

	if [ "$PUB_DO53" = omitted ]; then
		portless='1 . oots="doq:20"'
	else
		portless='1 . oots="do53:100,doq:20"'
	fi
	want_b=$(printf '%s\n' "$portless" '1 . port="1234" oots="dot:10"' '1 . port="8443" oots="doh:5"' | sort)
	check K1 "ports dot 1234, doh 8443: one record per ported transport, the rest in one ($portless)" [ "$b" = "$want_b" ]
	check K1 "every transport in exactly one record" _pub_each_once "$b"
	check K1 "a standard port (dot 853) publishes what no port does" [ -n "$a" -a "$c" = "$a" ]
	check K1 "without ports: one record, no port key" _pub_one_portless "$a"

	d=""
	if [ "$PUB_DO53" = omitted ] && _pub_up pub-d 127.0.0.55 "$AUTH_PUB" "do53:100,tcp:30,dot:10" ""; then
		d=$(rdata 127.0.0.55 _dns.ns1.pub.test. SVCB)
		note "pub-d: $(echo "$d" | tr '\n' '|')"
		check K1 "do53:100 beside tcp:30 publishes udp:100 and tcp:30" [ "$(_pub_tokens "$d")" = "dot:10 tcp:30 udp:100" ]
	fi
	check K1 "no record names do53 beside udp or tcp" _pub_no_do53_beside "$a" "$b" "$c" "$d"

	if [ -n "$AUTH_BASE" ]; then
		_pub_up pub-base 127.0.0.54 "$AUTH_BASE" "doq:20,dot:10" "" || return
		base=$(rdata 127.0.0.54 _dns.ns1.pub.test. SVCB)
		note "pub-base: $(echo "$base" | tr '\n' '|')"
		if [ "$PUB_DO53" = omitted ]; then
			want_a=$(echo "$base" | _pub_drop_do53)
			check M3 "a default config publishes what the base build does, without its do53 ($want_a)" [ -n "$base" -a "$a" = "$want_a" ]
		else
			check M3 "a default config publishes what the base build does" [ -n "$base" -a "$a" = "$base" ]
		fi
	else
		skip "M3 a default config against the base build: AUTH_BASE not set"
	fi
}

_pub_up() { # name address binary signal ports
	ZDIR="$WORK/$1/zones"; mkdir -p "$ZDIR"
	zonefile pub.test. "ns1.pub.test.=$2" </dev/null > "$ZDIR/pub.test.zone"
	{ y_service "$1" "ns1.pub.test." svcb "$4" "$5"
	  y_listeners "$2" "dot doq doh" "$5"
	  y_common "$1" "$2"
	  y_zones; y_primary pub.test. add-transport-signal
	} | auth_up "$1" "$3" "$2" pub.test. || { fail "published: $1 did not start"; return 1; }
}

# The oots entries of rdata lines, one per line.
_pub_entries() { echo "$1" | sed -n 's/.*oots="\([^"]*\)".*/\1/p' | tr ',' '\n'; }

_pub_tokens() { # rdata lines -> their oots entries, sorted, on one line
	_pub_entries "$1" | sort | tr '\n' ' ' | sed 's/ $//'
}

_pub_each_once() { # rdata lines: each oots token appears once across them
	_pub_entries "$1" | sed 's/:.*//' | sort | uniq -d | grep -q . && return 1
	return 0
}

_pub_one_portless() {
	[ "$(echo "$1" | grep -c .)" -eq 1 ] && ! echo "$1" | grep -q 'port='
}

# Each argument is one publisher's rdata lines: none may name do53 when it
# also names udp or tcp, in the same record or another.
_pub_no_do53_beside() {
	local _r _t
	for _r in "$@"; do
		_t=$(_pub_entries "$_r" | sed 's/:.*//')
		echo "$_t" | grep -qx do53 && echo "$_t" | grep -qx -e udp -e tcp && return 1
	done
	return 0
}

# rdata lines on stdin, with any do53 entry taken out of each oots value.
_pub_drop_do53() { sed -e 's/oots="do53:[0-9]*,/oots="/' -e 's/,do53:[0-9]*//'; }
