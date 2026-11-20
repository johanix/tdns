# Suite ignore: records a resolver cannot honour are ignored. Scenario P3.
#
# Parties: one tdns-auth (AUTH_PUB) on two addresses, operator records only.
# It listens for DoQ on 853 and for DoT on 1234 only.
#   ns.ign.test   127.0.0.21  1 . oots="do53:100,doq:50"
#                             1 alt.ign.test. port=1234 oots="dot:100"
#   ns.ign2.test  127.0.0.22  1 alt.ign2.test. port=1234 oots="dot:100" alone
#   alt.*         127.0.0.29  nothing listens there
#   the resolver  127.0.0.100 IMR.
#
# Done: one query to each zone, so the resolver looks up each signal; then 40
# queries for new names in each zone.
#
# Observed (tdns-cli imr stats auth-transports):
#   P3  ns.ign.test holds doq:50 and nothing about dot; it answered over DoQ;
#       it never answered over DoT and never failed on it. ns.ign2.test holds
#       no DoT and never used it.
#
# Negative: the trap. The server listens for DoT on 1234 of its own address,
# where a resolver that reads the target record as if it were "." would go,
# and it would succeed there: a DoT count above zero is a FAIL. ns.ign.test's
# DoQ is the paired positive: it shows the resolver did look the RRset up. Red
# on main and on #994's head, which apply the target record.
#
# Not here: P4, the ServiceMode siblings of an AliasMode record, which a
# resolver ignores (RFC 9460 section 2.4.1). tdns-auth has refused to publish
# an SVCB RRset that mixes the two modes since c4708512, so P4 never ran on any
# build this rig has run, main included: its zone was never served, and its
# checks passed on nothing. The rule is covered by TestOOTSAliasSetIsIgnored
# (v2/oots_resolver_test.go).

suite_ignore() {
	ZDIR="$WORK/ign/zones"; mkdir -p "$ZDIR"
	zonefile ign.test. "ns.ign.test.=127.0.0.21" > "$ZDIR/ign.test.zone" <<EOF
_dns.ns IN SVCB 1 . oots="do53:100,doq:50"
_dns.ns IN SVCB 1 alt.ign.test. port=1234 oots="dot:100"
alt IN A 127.0.0.29
* IN A 192.0.2.1
EOF
	zonefile ign2.test. "ns.ign2.test.=127.0.0.22" > "$ZDIR/ign2.test.zone" <<EOF
_dns.ns IN SVCB 1 alt.ign2.test. port=1234 oots="dot:100"
alt IN A 127.0.0.29
* IN A 192.0.2.1
EOF
		{ y_service ign "ns.ign.test., ns.ign2.test."
	  y_listeners "127.0.0.21 127.0.0.22" "dot doq" "dot:1234 doq:853"
	  y_common ign 127.0.0.21
	  y_zones; y_primary ign.test.; y_primary ign2.test.
	} | auth_up ign "$AUTH_PUB" 127.0.0.21 ign.test. || { fail "ignore: the server did not start"; return; }

	imr_up || { fail "ignore: the resolver did not start"; return; }
	for z in ign.test. ign2.test.; do dogq 127.0.0.100 "first.$z" A >/dev/null; done
	wait_signal ns.ign.test. 15 || note "no signal learnt for ns.ign.test. within 15 s"
	sleep "${SETTLE:-3}"
	for z in ign.test. ign2.test.; do load "$z" 40; done

	for s in ns.ign.test. ns.ign2.test.; do
		note "$s signal=$(at_get $s signal) ports=$(at_get $s signal_ports) counts=$(at_get $s counts) failed=$(at_get $s failed)"
	done
	check P3 "ns.ign.test. holds doq:50 from the . record" [ "$(at_get ns.ign.test. signal.doq)" = 50 ]
	check P3 "ns.ign.test. answered over doq" [ "$(num "$(at_get ns.ign.test. counts.doq)")" -gt 0 ]
	check P3 "ns.ign.test. holds nothing about dot" [ -z "$(at_get ns.ign.test. signal.dot)" -a -z "$(at_get ns.ign.test. signal_ports.dot)" ]
	check P3 "ns.ign.test. never used dot (the trap on its own :1234)" [ "$(num "$(at_get ns.ign.test. counts.dot)")" -eq 0 -a "$(num "$(at_get ns.ign.test. failed.dot)")" -eq 0 ]
	check P3 "ns.ign2.test. (target record alone) holds no dot" [ -z "$(at_get ns.ign2.test. signal.dot)" ]
	check P3 "ns.ign2.test. never used dot (the trap)" [ "$(num "$(at_get ns.ign2.test. counts.dot)")" -eq 0 -a "$(num "$(at_get ns.ign2.test. failed.dot)")" -eq 0 ]
}
