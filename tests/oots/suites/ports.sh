# Suite ports: a port on a record with TargetName "." moves the transport, on
# the nameserver's own address. Scenarios P1, P2, P6 and K2.
#
# Parties
#   ns1.ports.test  127.0.0.11  AUTH_PUB. Its signal comes from its config:
#                   signal "do53:0,dot:40,doq:40,doh:20", ports dot 8853,
#                   doq 8853, doh 8443 (K2, P1). It listens for DoT and DoQ on
#                   8853 and DoH on 8443, and nowhere else.
#   ns.p2.test      127.0.0.12  AUTH_PUB, one operator record naming two
#                   transports, DoH among them: 1 . port=8853 oots="doq:50,doh:50"
#                   (P2). DoQ (UDP) and DoH (TCP) on 8853 only. #994 applied a
#                   port to DoH only when DoH was alone in its record.
#   ns.p6.test      127.0.0.13  AUTH_PUB, an ALPN-only record with a port:
#                   1 . alpn=dot,doq port=8853 (P6). DoT and DoQ on 8853 only.
#   the resolver    127.0.0.100 IMR.
#
# Done: one query to each zone, so the resolver meets the server and looks up
# its signal; then 60 queries for new names in each zone.
#
# Observed: the signal and its ports as the resolver holds them, and the
# answers it got per transport (tdns-cli imr stats auth-transports).
#
# Negative: the servers listen only on the signalled ports. A resolver that
# ignores a port tries the transport's standard port, fails, and falls back to
# Do53, so its counts stay at zero and its failures do not. Red on a resolver
# without port support (main before #1045); P2 and P6 red on #994's head.

suite_ports() {
	ZDIR="$WORK/ports-n1/zones"; mkdir -p "$ZDIR"
	zonefile ports.test. "ns1.ports.test.=127.0.0.11" > "$ZDIR/ports.test.zone" <<EOF
* IN A 192.0.2.1
EOF
	{ y_service ports-n1 "ns1.ports.test." svcb "do53:0,dot:40,doq:40,doh:20" "dot:8853 doq:8853 doh:8443"
	  y_listeners 127.0.0.11 "dot doq doh" "dot:8853 doq:8853 doh:8443"
	  y_common ports-n1 127.0.0.11
	  y_zones; y_primary ports.test. add-transport-signal
	} | auth_up ports-n1 "$AUTH_PUB" 127.0.0.11 ports.test. || { fail "ports: ns1.ports.test did not start"; return; }

	ZDIR="$WORK/ports-p2/zones"; mkdir -p "$ZDIR"
	zonefile p2.test. "ns.p2.test.=127.0.0.12" > "$ZDIR/p2.test.zone" <<EOF
_dns.ns IN SVCB 1 . port=8853 oots="doq:50,doh:50"
* IN A 192.0.2.1
EOF
	{ y_service ports-p2 "ns.p2.test."
	  y_listeners 127.0.0.12 "doq doh" "doq:8853 doh:8853"
	  y_common ports-p2 127.0.0.12
	  y_zones; y_primary p2.test.
	} | auth_up ports-p2 "$AUTH_PUB" 127.0.0.12 p2.test. || { fail "ports: ns.p2.test did not start"; return; }

	ZDIR="$WORK/ports-p6/zones"; mkdir -p "$ZDIR"
	zonefile p6.test. "ns.p6.test.=127.0.0.13" > "$ZDIR/p6.test.zone" <<EOF
_dns.ns IN SVCB 1 . alpn=dot,doq port=8853
* IN A 192.0.2.1
EOF
	{ y_service ports-p6 "ns.p6.test."
	  y_listeners 127.0.0.13 "dot doq" "dot:8853 doq:8853"
	  y_common ports-p6 127.0.0.13
	  y_zones; y_primary p6.test.
	} | auth_up ports-p6 "$AUTH_PUB" 127.0.0.13 p6.test. || { fail "ports: ns.p6.test did not start"; return; }

	# What ns1.ports.test publishes from its config (K2). One record per ported
	# transport, one without a port for the rest.
	note "published by ns1.ports.test:"
	rdata 127.0.0.11 _dns.ns1.ports.test. SVCB | sed 's/^/        /'

	imr_up || { fail "ports: the resolver did not start"; return; }

	for z in ports.test. p2.test. p6.test.; do dogq 127.0.0.100 "first.$z" A >/dev/null; done
	for s in ns1.ports.test. ns.p2.test. ns.p6.test.; do
		wait_signal "$s" 15 || note "no signal learnt for $s within 15 s"
	done
	for z in ports.test. p2.test. p6.test.; do load "$z" 60; done

	_ports_check K2 ns1.ports.test. "dot:8853 doq:8853 doh:8443"
	_ports_check P2 ns.p2.test. "doq:8853 doh:8853"
	_ports_check P6 ns.p6.test. "dot:8853 doq:8853"
	check P6 "ns.p6.test.: the signal is ALPN-only" [ "$(at_get ns.p6.test. signal_source)" = alpn ]
}

# For each transport:port, the resolver holds the port, used the transport,
# and saw no failure on it.
_ports_check() { # id server "t:port ..."
	note "$2 signal=$(at_get "$2" signal) ports=$(at_get "$2" signal_ports) counts=$(at_get "$2" counts) failed=$(at_get "$2" failed)"
	for tp in $3; do
		t="${tp%%:*}"; p="${tp#*:}"
		check "$1" "$2 holds $t on port $p" [ "$(at_get "$2" "signal_ports.$t")" = "$p" ]
		check "$1" "$2 answered over $t" [ "$(num "$(at_get "$2" "counts.$t")")" -gt 0 ]
		check "$1" "$2 no $t failures" [ "$(num "$(at_get "$2" "failed.$t")")" -eq 0 ]
	done
}
