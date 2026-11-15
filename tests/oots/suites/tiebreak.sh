# Suite tiebreak: a transport named in two records takes one of them, the same
# one whatever order the records arrive in. Scenario P5.
#
# Parties: one tdns-auth (AUTH_PUB) on two addresses, operator records only,
# the same two records in opposite order:
#   ns.tb1.test   127.0.0.31  A then B
#   ns.tb2.test   127.0.0.32  B then A
#     A = 1 . oots="dot:50,doh:20"
#     B = 1 . port=8853 oots="dot:10"
#   Equal SvcPriority, so the lower RDATA in DNSSEC canonical order wins dot.
#   That is B: its first SvcParam key, port (3), sorts before oots (12). doh is
#   only in A, which keeps it although it lost dot.
#   The server listens for DoT on 8853 only, and for DoH on 443.
#   the resolver  127.0.0.100 IMR.
#
# Precondition: the two servers send the records in different orders (dog).
# Otherwise the suite cannot tell order-free from lucky: SKIP.
#
# Observed: both servers hold dot:10 on 8853 and doh:20 with no port, and both
# answered over DoT and DoH without failures.
#
# Negative: DoT listens on 8853 only, so taking dot from A (port 853) fails.
# Red on #994's head, where the last record read wins: one of the two orders
# takes A's dot.

suite_tiebreak() {
	A='1 . oots="dot:50,doh:20"'
	B='1 . port=8853 oots="dot:10"'
	ZDIR="$WORK/tb/zones"; mkdir -p "$ZDIR"
	zonefile tb1.test. "ns.tb1.test.=127.0.0.31" > "$ZDIR/tb1.test.zone" <<EOF
_dns.ns IN SVCB $A
_dns.ns IN SVCB $B
* IN A 192.0.2.1
EOF
	zonefile tb2.test. "ns.tb2.test.=127.0.0.32" > "$ZDIR/tb2.test.zone" <<EOF
_dns.ns IN SVCB $B
_dns.ns IN SVCB $A
* IN A 192.0.2.1
EOF
	{ y_service tb "ns.tb1.test., ns.tb2.test."
	  y_listeners "127.0.0.31 127.0.0.32" "dot doh" "dot:8853 doh:443"
	  y_common tb 127.0.0.31
	  y_zones; y_primary tb1.test.; y_primary tb2.test.
	} | auth_up tb "$AUTH_PUB" 127.0.0.31 tb1.test. || { fail "tiebreak: the server did not start"; return; }

	o1=$(rdata_ordered 127.0.0.31 _dns.ns.tb1.test. SVCB | head -1)
	o2=$(rdata_ordered 127.0.0.32 _dns.ns.tb2.test. SVCB | head -1)
	note "first record from ns.tb1: $o1"
	note "first record from ns.tb2: $o2"
	if [ -z "$o1" ] || [ "$o1" = "$o2" ]; then
		skip "P5 the server sends both RRsets in the same order; order-freedom cannot be judged"
		return
	fi

	imr_up || { fail "tiebreak: the resolver did not start"; return; }
	for z in tb1.test. tb2.test.; do dogq 127.0.0.100 "first.$z" A >/dev/null; done
	for s in ns.tb1.test. ns.tb2.test.; do wait_signal "$s" 15 || note "no signal for $s within 15 s"; done
	for z in tb1.test. tb2.test.; do load "$z" 60; done

	for s in ns.tb1.test. ns.tb2.test.; do
		note "$s signal=$(at_get $s signal) ports=$(at_get $s signal_ports) counts=$(at_get $s counts) failed=$(at_get $s failed)"
		check P5 "$s holds dot:10 (from B)" [ "$(at_get $s signal.dot)" = 10 ]
		check P5 "$s holds dot on port 8853" [ "$(at_get $s signal_ports.dot)" = 8853 ]
		check P5 "$s holds doh:20 (A keeps what it did not lose)" [ "$(at_get $s signal.doh)" = 20 ]
		check P5 "$s holds no port for doh" [ -z "$(at_get $s signal_ports.doh)" ]
		check P5 "$s answered over dot, no failures" [ "$(num "$(at_get $s counts.dot)")" -gt 0 -a "$(num "$(at_get $s failed.dot)")" -eq 0 ]
		check P5 "$s answered over doh, no failures" [ "$(num "$(at_get $s counts.doh)")" -gt 0 -a "$(num "$(at_get $s failed.doh)")" -eq 0 ]
	done
	check P5 "both orders give the same signal" [ "$(at_get ns.tb1.test. signal)" = "$(at_get ns.tb2.test. signal)" ]
	check P5 "both orders give the same ports" [ "$(at_get ns.tb1.test. signal_ports)" = "$(at_get ns.tb2.test. signal_ports)" ]
}
