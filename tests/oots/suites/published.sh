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
#   pub-base  127.0.0.54  AUTH_BASE (when set), pub-a's config
#
# Done: ask each for _dns.ns1.pub.test. SVCB. No resolver.
#
# Observed:
#   K1  pub-b publishes one record per ported transport and one record without
#       a port for the rest, with do53 stated once; every transport is in
#       exactly one record. pub-c publishes exactly what pub-a does.
#   M3  pub-a publishes exactly what the same config publishes on AUTH_BASE
#       (the base build, e.g. main): a default config is byte-identical.
#
# Negative: pub-a and pub-base must agree, and pub-b must differ from pub-a; a
# publisher that ignored ports would fail K1, one that changed the default
# layout would fail M3. SKIP for M3 when AUTH_BASE is not set.

suite_published() {
	_pub_up pub-a 127.0.0.51 "$AUTH_PUB" "doq:20,dot:10" "" || return
	_pub_up pub-b 127.0.0.52 "$AUTH_PUB" "dot:10,doh:5,doq:20" "dot:1234 doh:8443" || return
	_pub_up pub-c 127.0.0.53 "$AUTH_PUB" "doq:20,dot:10" "dot:853" || return

	a=$(rdata 127.0.0.51 _dns.ns1.pub.test. SVCB)
	b=$(rdata 127.0.0.52 _dns.ns1.pub.test. SVCB)
	c=$(rdata 127.0.0.53 _dns.ns1.pub.test. SVCB)
	note "pub-a: $(echo "$a" | tr '\n' '|')"
	note "pub-b: $(echo "$b" | tr '\n' '|')"
	note "pub-c: $(echo "$c" | tr '\n' '|')"

	want_b=$(printf '%s\n' '1 . oots="do53:100,doq:20"' '1 . port="1234" oots="dot:10"' '1 . port="8443" oots="doh:5"' | sort)
	check K1 "ports dot 1234, doh 8443: one record per ported transport, the rest in one" [ "$b" = "$want_b" ]
	check K1 "every transport in exactly one record" _pub_each_once "$b"
	check K1 "a standard port (dot 853) publishes what no port does" [ -n "$a" -a "$c" = "$a" ]
	check K1 "without ports: one record, no port key" _pub_one_portless "$a"

	if [ -n "$AUTH_BASE" ]; then
		_pub_up pub-base 127.0.0.54 "$AUTH_BASE" "doq:20,dot:10" "" || return
		base=$(rdata 127.0.0.54 _dns.ns1.pub.test. SVCB)
		note "pub-base: $(echo "$base" | tr '\n' '|')"
		check M3 "a default config publishes what the base build does" [ -n "$base" -a "$a" = "$base" ]
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

_pub_each_once() { # rdata lines: each oots token appears once across them
	echo "$1" | sed -n 's/.*oots="\([^"]*\)".*/\1/p' | tr ',' '\n' | sed 's/:.*//' |
		sort | uniq -d | grep -q . && return 1
	return 0
}

_pub_one_portless() {
	[ "$(echo "$1" | grep -c .)" -eq 1 ] && ! echo "$1" | grep -q 'port='
}
