# Suite customer: a server includes transport signals by zone data and writes
# a signal only into its own zone, never into a zone it hosts for a customer.
# Scenarios Z1-Z8 (the maintainer's three rules for plan step S2).
#
# Parties
#   cust          127.0.0.61  AUTH_PUB, signs and serves six zones, every one
#                 127.0.0.62  with add-transport-signal; DoT and DoQ on 853 on
#                             both addresses (.62 is the DoT target's).
#     provider.test.  our own zone. Run 1: the operator writes the signal at
#                     _dns.ns1.provider.test: 1 . oots="do53:0,doq:50" and
#                     1 dot.provider.test. oots="dot:50" (DoT at a target,
#                     dot.provider.test. A 127.0.0.62). Both runs: a second
#                     server, ns2.provider.test. A 127.0.0.63 (nothing listens
#                     there), whose signal the operator writes too:
#                     _dns.ns2.provider.test. 1 . oots="doq:30".
#     customer.test.  NS ns1.customer.test (a vanity name at cust's address)
#                     and the customer's own alias:
#                     _dns.ns1.customer.test. SVCB 0 _dns.ns1.provider.test.
#     customer2.test. a second customer the same way: NS ns1.customer2.test
#                     and _dns.ns1.customer2.test. SVCB 0 _dns.ns1.provider.test.,
#                     the same target as customer.test's alias.
#     other.test.     NS ns1.provider.test directly, no _dns of its own.
#     two.test.       NS ns1.provider.test and ns2.provider.test, no _dns of
#                     its own: two provider servers, one RRset with a target.
#     far.test.       _dns.ns1.far.test. SVCB 0 _dns.ns.elsewhere.test., a
#                     target in no zone cust holds.
#   the resolver    127.0.0.100 IMR.
#
# Run 1: service.identities empty, the signal provisioned in provider.test.
# Run 2: ns1.provider.test in service.identities, its signal not provisioned:
#        service.transport synthesizes it. ns2's stays provisioned.
#
# Done: start cust; ask cust directly with the OOTS option for a name in
# each zone; through the resolver, a fresh one each run, the first queries
# for customer.test and customer2.test sent together, then 60 new names in
# customer.test and 30 in customer2.test; at 60 s after the start, AXFR
# every zone.
#
# Observed:
#   Z1  customer.test, customer2.test, other.test, two.test and far.test hold, at 60 s,
#       exactly what their zone files hold (DNSSEC records aside): nothing
#       was written in.
#   Z2  a customer.test response carries the alias and, in Additional, the
#       provider's signal it points to, with no identity configured.
#   Z3  an other.test response carries _dns.ns1.provider.test.
#   Z4  a far.test response carries the alias alone.
#   Z5  the resolver follows the customer's alias: ns1.customer.test holds
#       the provider's signal, honours its DoT target (S6 honours a target
#       only on a Secure path; the resolver's API shows no path state of its
#       own), answers over DoT and DoQ, and validates both hops. Redirects
#       ignored before the path is decided (a sighting in Additional ahead of
#       the verifying lookup) are S6's design, so they are noted, not failed.
#   Z6  run 2: the synthesized signal is in provider.test and nowhere else.
#   Z7  a second customer's alias to the same target: ns1.customer2.test,
#       like ns1.customer.test, holds the provider's signal, honours the DoT
#       target in run 1, and answers over DoT and DoQ. This guards the main
#       case. Z7 does NOT cover the shared-hop race fixed in S6b's review
#       (#1056 1f53f021), though the two first queries go out together: the
#       target arrives in Additional, and a hop lookup on loopback ends long
#       before the second owner gets there, so a resolver from before that
#       fix (7b1ce491) passes Z7 too. Reaching the race needs the hop lookup
#       still open when the second owner arrives, which this rig cannot hold.
#   Z8  a two.test response carries both servers' signals, as the zone data
#       holds them: ns1's whole RRset, its record with a target included, and
#       ns2's, though ns2 is not this server. Inclusion goes by zone data, not
#       by who answers. Before S2 a ServiceMode record with a target was taken
#       for an alias, checked against the answered zone's addresses, and
#       dropped: only ns2's signal came back.
#
# Negative: without the OOTS option no signal is added (Z2). A publisher
# that wrote by identity into the zone it serves would fail Z1; one that
# injected by identity would fail Z2-Z4 in run 1 (no identity).

CZ_A=127.0.0.61
CZ_T=127.0.0.62

suite_customer() {
	_cz_run 1 || return
	_cz_run 2
}

_cz_run() { # 1|2
	local _r _ids _t0 _q1 _q2
	_r="$1"
	note "run $_r: $([ "$_r" = 1 ] && echo "no identity, the signal provisioned in provider.test" || echo "identity ns1.provider.test, the signal synthesized")"
	ZDIR="$WORK/cust/zones"; mkdir -p "$ZDIR"
	_cz_zones "$_r"
	_ids=""; [ "$_r" = 2 ] && _ids="ns1.provider.test."
	{ y_service cust "$_ids" svcb "do53:0,dot:50,doq:50"
	  y_listeners "$CZ_A $CZ_T" "dot doq"
	  y_common cust "$CZ_A"
	  y_zones
	  for z in provider.test. customer.test. customer2.test. other.test. two.test. far.test.; do y_primary "$z" "online-signing, add-transport-signal"; done
	} | auth_up cust "$AUTH_PUB" "$CZ_A" provider.test. || { fail "customer: cust did not start (run $_r)"; return 1; }
	_t0=$(date +%s)

	# Z2-Z4, from cust directly, with the OOTS option.
	cz_c=$(dogq "$CZ_A" www.customer.test. A +oots +norec)
	cz_o=$(dogq "$CZ_A" www.other.test. A +oots +norec)
	cz_f=$(dogq "$CZ_A" www.far.test. A +oots +norec)
	note "customer.test Additional: $(_cz_svcb "$cz_c" | tr '\n' '|')"
	note "other.test Additional:    $(_cz_svcb "$cz_o" | tr '\n' '|')"
	note "far.test Additional:      $(_cz_svcb "$cz_f" | tr '\n' '|')"
	check Z2 "run $_r: customer.test carries its alias to _dns.ns1.provider.test." _cz_has "$cz_c" _dns.ns1.customer.test. "0 _dns.ns1.provider.test."
	check Z2 "run $_r: customer.test carries the provider's signal at the alias target" _cz_has "$cz_c" _dns.ns1.provider.test. ""
	check Z2 "run $_r: without the OOTS option, no signal is added" [ -z "$(_cz_svcb "$(dogq "$CZ_A" www.customer.test. A +norec)")" ]
	check Z3 "run $_r: other.test carries _dns.ns1.provider.test." _cz_has "$cz_o" _dns.ns1.provider.test. ""
	check Z4 "run $_r: far.test carries its alias" _cz_has "$cz_f" _dns.ns1.far.test. "0 _dns.ns.elsewhere.test."
	check Z4 "run $_r: far.test carries nothing else" [ "$(_cz_svcb "$cz_f" | awk '{ print $1 }' | sort -u)" = "_dns.ns1.far.test." ]

	# Z8: two provider servers named in one zone.
	cz_2=$(dogq "$CZ_A" www.two.test. A +oots +norec)
	note "two.test Additional:      $(_cz_svcb "$cz_2" | tr '\n' '|')"
	check Z8 "run $_r: two.test carries ns1's signal" _cz_has "$cz_2" _dns.ns1.provider.test. ""
	if [ "$_r" = 1 ]; then
		check Z8 "run 1: two.test carries ns1's record with a target" _cz_has "$cz_2" _dns.ns1.provider.test. "1 dot.provider.test."
	fi
	check Z8 "run $_r: two.test carries ns2's signal, though ns2 is not this server" _cz_has "$cz_2" _dns.ns2.provider.test. '1 . oots="doq:30"'
	check Z8 "run $_r: two.test carries nothing else" [ "$(_cz_svcb "$cz_2" | awk '{ print $1 }' | sort -u | tr '\n' ' ')" = "_dns.ns1.provider.test. _dns.ns2.provider.test. " ]

	# Z5 and Z7, through a fresh resolver: the first queries for the two
	# customers' zones go out together. Both aliases meet one target, but not
	# inside one hop lookup: Z7 is not the shared-hop race (see the header).
	imr_up || { fail "customer: the resolver did not start (run $_r)"; return 1; }
	# Wait for these two queries only: a bare wait would also wait for the
	# daemons this shell started in the background.
	dogq 127.0.0.100 first.customer.test. A >/dev/null & _q1=$!
	dogq 127.0.0.100 first.customer2.test. A >/dev/null & _q2=$!
	wait "$_q1" "$_q2"
	wait_signal ns1.customer.test. 15 || note "no signal learnt for ns1.customer.test. within 15 s"
	wait_signal ns1.customer2.test. 15 || note "no signal learnt for ns1.customer2.test. within 15 s"
	load customer.test. 60
	load customer2.test. 30
	note "ns1.customer.test. signal=$(at_get ns1.customer.test. signal) targets=$(at_get ns1.customer.test. signal_targets) redirected=$(at_get ns1.customer.test. redirected) ignored=$(at_get ns1.customer.test. ignored_redirects) counts=$(at_get ns1.customer.test. counts) failed=$(at_get ns1.customer.test. failed)"
	check Z5 "run $_r: ns1.customer.test. holds the provider's signal (doq 50, dot 50)" [ "$(at_get ns1.customer.test. signal.doq)" = 50 -a "$(at_get ns1.customer.test. signal.dot)" = 50 ]
	if [ "$_r" = 1 ]; then
		check Z5 "run 1: the DoT target dot.provider.test. is honoured, so the path is Secure" [ "$(at_get ns1.customer.test. signal_targets.dot)" = dot.provider.test. -a "$(num "$(at_get ns1.customer.test. redirected.dot)")" -gt 0 ]
	fi
	check Z5 "run $_r: answered over DoT and DoQ" [ "$(num "$(at_get ns1.customer.test. counts.dot)")" -gt 0 -a "$(num "$(at_get ns1.customer.test. counts.doq)")" -gt 0 ]
	check Z5 "run $_r: no failures" [ "$(num "$(at_get ns1.customer.test. failed_total)")" -eq 0 ]
	check Z5 "run $_r: the resolver validates the alias (AD)" _cz_ad _dns.ns1.customer.test. SVCB
	check Z5 "run $_r: the resolver validates the provider's signal (AD)" _cz_ad _dns.ns1.provider.test. SVCB

	note "Z7 does not cover the shared-hop race (#1056): the target arrives in Additional"
	note "ns1.customer2.test. signal=$(at_get ns1.customer2.test. signal) targets=$(at_get ns1.customer2.test. signal_targets) redirected=$(at_get ns1.customer2.test. redirected) ignored=$(at_get ns1.customer2.test. ignored_redirects) counts=$(at_get ns1.customer2.test. counts) failed=$(at_get ns1.customer2.test. failed)"
	check Z7 "run $_r: ns1.customer2.test. holds the provider's signal too (doq 50, dot 50)" [ "$(at_get ns1.customer2.test. signal.doq)" = 50 -a "$(at_get ns1.customer2.test. signal.dot)" = 50 ]
	if [ "$_r" = 1 ]; then
		check Z7 "run 1: ns1.customer2.test. honours the same DoT target" [ "$(at_get ns1.customer2.test. signal_targets.dot)" = dot.provider.test. -a "$(num "$(at_get ns1.customer2.test. redirected.dot)")" -gt 0 ]
	fi
	check Z7 "run $_r: ns1.customer2.test. answered over DoT and DoQ" [ "$(num "$(at_get ns1.customer2.test. counts.dot)")" -gt 0 -a "$(num "$(at_get ns1.customer2.test. counts.doq)")" -gt 0 ]
	check Z7 "run $_r: ns1.customer2.test. no failures" [ "$(num "$(at_get ns1.customer2.test. failed_total)")" -eq 0 ]

	# Z1 and Z6: the zones at 60 s after the start, against their files.
	while [ $(($(date +%s) - _t0)) -lt 60 ]; do sleep 1; done
	for z in customer.test. customer2.test. other.test. two.test. far.test.; do
		_cz_norm < "$ZDIR/${z}zone" > "$WORK/cust/$z.file"
		dogq "$CZ_A" "$z" AXFR | _cz_norm > "$WORK/cust/$z.axfr"
		[ -s "$WORK/cust/$z.axfr" ] || note "$z: the AXFR came back empty"
		cmp -s "$WORK/cust/$z.file" "$WORK/cust/$z.axfr" || diff "$WORK/cust/$z.file" "$WORK/cust/$z.axfr" | sed "s/^/      $z /"
		check Z1 "run $_r: nothing written into $z (AXFR at 60 s = its zone file)" _cz_same "$WORK/cust/$z.file" "$WORK/cust/$z.axfr"
	done
	_cz_norm < "$ZDIR/provider.test.zone" > "$WORK/cust/provider.test..file"
	dogq "$CZ_A" provider.test. AXFR | _cz_norm > "$WORK/cust/provider.test..axfr"
	if [ "$_r" = 1 ]; then
		check Z6 "run 1: provider.test. holds what its file does (the operator's signal left alone)" cmp -s "$WORK/cust/provider.test..file" "$WORK/cust/provider.test..axfr"
	else
		note "provider.test. added: $(comm -13 "$WORK/cust/provider.test..file" "$WORK/cust/provider.test..axfr" | tr '\n' '|')"
		check Z6 "run 2: the synthesized signal is in provider.test. and nothing else was added" [ "$(comm -13 "$WORK/cust/provider.test..file" "$WORK/cust/provider.test..axfr" | awk '{ print $1, $2 }' | sort -u)" = "_dns.ns1.provider.test. SVCB" ]
	fi

	stop_daemon q
	stop_daemon cust
}

# The zone files. Every name is written in full, so a zone file and an AXFR
# reduce to the same lines (_cz_norm).
_cz_zones() { # run
	_cz_zone provider.test. ns1.provider.test. <<EOF
ns1.provider.test. 60 IN A $CZ_A
dot.provider.test. 60 IN A $CZ_T
ns2.provider.test. 60 IN A 127.0.0.63
_dns.ns2.provider.test. 60 IN SVCB 1 . oots="doq:30"
www.provider.test. 60 IN A 192.0.2.1
EOF
	if [ "$1" = 1 ]; then cat >> "$ZDIR/provider.test.zone" <<EOF
_dns.ns1.provider.test. 60 IN SVCB 1 . oots="do53:0,doq:50"
_dns.ns1.provider.test. 60 IN SVCB 1 dot.provider.test. oots="dot:50"
EOF
	fi
	_cz_zone customer.test. ns1.customer.test. <<EOF
ns1.customer.test. 60 IN A $CZ_A
_dns.ns1.customer.test. 60 IN SVCB 0 _dns.ns1.provider.test.
*.customer.test. 60 IN A 192.0.2.1
EOF
	_cz_zone customer2.test. ns1.customer2.test. <<EOF
ns1.customer2.test. 60 IN A $CZ_A
_dns.ns1.customer2.test. 60 IN SVCB 0 _dns.ns1.provider.test.
*.customer2.test. 60 IN A 192.0.2.1
EOF
	_cz_zone other.test. ns1.provider.test. <<EOF
*.other.test. 60 IN A 192.0.2.1
EOF
	_cz_zone two.test. ns1.provider.test. <<EOF
two.test. 60 IN NS ns2.provider.test.
*.two.test. 60 IN A 192.0.2.1
EOF
	_cz_zone far.test. ns1.far.test. <<EOF
ns1.far.test. 60 IN A $CZ_A
_dns.ns1.far.test. 60 IN SVCB 0 _dns.ns.elsewhere.test.
*.far.test. 60 IN A 192.0.2.1
EOF
}

_cz_zone() { # zone ns : SOA and NS, then stdin
	{ echo "$1 60 IN SOA $2 hostmaster.$1 ${SERIAL:-1} 60 30 3600 30"
	  echo "$1 60 IN NS $2"
	  cat; } > "$ZDIR/${1}zone"
}

# Zone lines (a file or an AXFR) reduced to "owner TYPE" per record, with the
# RDATA too for SVCB; SOA and DNSSEC records left out, sorted, unique.
_cz_norm() {
	awk '$1 !~ /^;/ {
		for (i = 2; i <= 4 && i <= NF; i++) if ($i == "IN") {
			t = $(i + 1)
			if (t ~ /^(SOA|RRSIG|NSEC|NSEC3|NSEC3PARAM|DNSKEY|CDS|CDNSKEY|ZONEMD|TYPE65534)$/) next
			s = tolower($1) " " t
			if (t == "SVCB") for (j = i + 2; j <= NF; j++) s = s " " $j
			print s; next } }' | sort -u
}

# The SVCB lines of a response: "owner rdata...".
_cz_svcb() {
	echo "$1" | awk '$1 !~ /^;/ { for (i = 2; i <= 4 && i <= NF; i++) if ($i == "IN" && $(i + 1) == "SVCB") {
		s = $1; for (j = i + 2; j <= NF; j++) s = s " " $j; print s; next } }'
}

_cz_has() { # response owner rdata-prefix : an SVCB at owner, its RDATA starting so
	_cz_svcb "$1" | awk -v o="$2" -v p="$3" '$1 == o { r = $0; sub(/^[^ ]+ /, "", r); if (index(r, p) == 1) f = 1 } END { exit !f }'
}

_cz_same() { [ -s "$2" ] && cmp -s "$1" "$2"; } # file axfr : the AXFR is not empty and equal

_cz_ad() { # name type : NOERROR with AD from the resolver
	dogq 127.0.0.100 "$1" "$2" +dnssec | awk '
		/status:/ { if ($0 ~ /status: NOERROR/) ok = 1 }
		/^;; flags:/ { if ($0 ~ /[ :]ad[ ;]/) ad = 1 }
		END { exit !(ok && ad) }'
}
