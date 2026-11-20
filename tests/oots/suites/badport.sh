# Suite badport: a port on the bad-port list is refused. Any port may carry a
# transport except those on the Fetch Standard's bad-port list (section 2.9,
# less 53); 53, 853 and 443 are never refused. A record with such a port is
# used without it, so its transports go to the nameserver on their default
# ports. Scenario P7.
#
# Parties
#   ns.p22.test   127.0.0.14  AUTH_PUB, one operator record with port 22:
#                 1 . port=22 oots="dot:50,doq:50" (P7). DoT and DoQ on their
#                 default port 853 only.
#   the resolver  127.0.0.100 IMR.
#
# Done: one query to the zone, so the resolver meets the server and looks up
# its signal; then 60 queries for new names.
#
# Observed: the signal and its ports as the resolver holds them, and the
# answers it got per transport (tdns-cli imr stats auth-transports).
#
# Negative: nothing listens on port 22. A resolver that keeps the port holds
# dot and doq on 22, fails there, and falls back to Do53, so its counts stay
# at zero and its failures do not. Red on a resolver before #1069.

suite_badport() {
	ZDIR="$WORK/badport/zones"; mkdir -p "$ZDIR"
	zonefile p22.test. "ns.p22.test.=127.0.0.14" > "$ZDIR/p22.test.zone" <<EOF
_dns.ns IN SVCB 1 . port=22 oots="dot:50,doq:50"
* IN A 192.0.2.1
EOF
	{ y_service badport "ns.p22.test."
	  y_listeners 127.0.0.14 "dot doq"
	  y_common badport 127.0.0.14
	  y_zones; y_primary p22.test.
	} | auth_up badport "$AUTH_PUB" 127.0.0.14 p22.test. || { fail "badport: ns.p22.test did not start"; return; }

	# The server answers where the record, with its port refused, sends the
	# resolver: DoT and DoQ on 853.
	check P7 "ns.p22.test. answers over dot on 853" answers "tls://127.0.0.14" p22.test. SOA
	check P7 "ns.p22.test. answers over doq on 853" answers "doq://127.0.0.14" p22.test. SOA

	imr_up || { fail "badport: the resolver did not start"; return; }

	dogq 127.0.0.100 first.p22.test. A >/dev/null
	wait_signal ns.p22.test. 15 || note "no signal learnt for ns.p22.test. within 15 s"
	load p22.test. 60

	note "ns.p22.test. signal=$(at_get ns.p22.test. signal) ports=$(at_get ns.p22.test. signal_ports) counts=$(at_get ns.p22.test. counts) failed=$(at_get ns.p22.test. failed)"
	for t in dot doq; do
		check P7 "ns.p22.test. holds no port for $t" [ -z "$(at_get ns.p22.test. "signal_ports.$t")" ]
		check P7 "ns.p22.test. answered over $t" [ "$(num "$(at_get ns.p22.test. "counts.$t")")" -gt 0 ]
		check P7 "ns.p22.test. no $t failures" [ "$(num "$(at_get ns.p22.test. "failed.$t")")" -eq 0 ]
	done
}
