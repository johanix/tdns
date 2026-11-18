# Suite bridge: tdns-cli's bridge from a synthesized signal to a provisioned
# one (tdns-cli auth config transport-signal, and --release). Scenario B.
#
# Party
#   br1, br2  127.0.0.81  AUTH_PUB, one at a time, each with a database of its
#                         own: br.test. (signed, add-transport-signal), the
#                         identity ns1.br.test., signal "doq:20,dot:10" with
#                         dot on port 1234.
#
# Done, br1 (with the release):
#   start with the identity, so the signal is synthesized at _dns.ns1.br.test;
#   print it with transport-signal, paste it into br.test's zone file, reload
#   the zone, --release ns1.br.test.; restart without the identity; restart
#   again with another signal ("doq:50,dot:10").
# Done, br2 (the same without the release): start, print, paste, reload;
#   restart without the identity.
#
# Observed:
#   B1  the printed records are the ones the server serves at the name.
#   B2  br1: the release says the name is released; after the restart without
#       the identity the records are still served, as pasted.
#   B3  br1: a changed service.transport does not reach them.
#   B4  br2: without the release, the records are withdrawn once the name
#       leaves service.identities.
#
# Negative: B4 is the bridge's own red. A release that did nothing would fail
# B2. SKIP when the CLI has no transport-signal command.

BR_A=127.0.0.81

suite_bridge() {
	if ! "$CLI_PUB" auth config --help 2>/dev/null | grep -q 'transport-signal'; then
		skip "B bridge: $CLI_PUB has no auth config transport-signal"
		return
	fi
	_br_run br1 release
	_br_run br2 norelease
}

_br_conf() { # party identities signal
	ZDIR="$WORK/$1/zones"
	{ y_service "$1" "$2" svcb "$3" "dot:1234"
	  y_listeners "$BR_A" "dot doq" "dot:1234"
	  y_common "$1" "$BR_A"
	  y_zones
	  y_primary br.test. "online-signing, add-transport-signal"
	} | auth_up "$1" "$AUTH_PUB" "$BR_A" br.test.
}

_br_has() { [ -n "$(rdata "$BR_A" _dns.ns1.br.test. SVCB)" ]; }

_br_cli() { # party args... : the CLI of that party's build, with its config
	local _p
	_p="$1"; shift
	"$CLI_PUB" --config "$WORK/$_p/tdns-cli.yaml" "$@"
}

_br_run() { # party release|norelease
	local _p _printed _served _after _rel
	_p="$1"
	note "$_p: $([ "$2" = release ] && echo "print, paste, reload, release, drop the identity" || echo "print, paste, reload, drop the identity, no release")"
	ZDIR="$WORK/$_p/zones"; mkdir -p "$ZDIR"
	zonefile br.test. "ns1.br.test.=$BR_A" </dev/null > "$ZDIR/br.test.zone"
	_br_conf "$_p" ns1.br.test. "doq:20,dot:10" || { fail "bridge: $_p did not start"; return; }
	wait_for 20 _br_has || note "$_p: no synthesized signal at _dns.ns1.br.test. within 20 s"
	_served=$(rdata "$BR_A" _dns.ns1.br.test. SVCB)

	_br_cli "$_p" auth config transport-signal > "$WORK/$_p/printed" 2>&1
	note "$_p printed: $(tr '\n' '|' < "$WORK/$_p/printed")"
	_printed=$(awk '$1 !~ /^;/ && $0 ~ /IN[ \t]+SVCB/ { s = ""; for (i = 1; i <= NF; i++) if ($i == "SVCB") { for (j = i + 1; j <= NF; j++) s = s (s == "" ? "" : " ") $j; print s; break } }' "$WORK/$_p/printed" | sort)
	check B1 "$_p: the printed records are the ones served" [ -n "$_printed" -a "$_printed" = "$_served" ]

	awk '$1 !~ /^;/ && $0 ~ /IN[ \t]+SVCB/' "$WORK/$_p/printed" >> "$ZDIR/br.test.zone"
	note "$_p reload: $(_br_cli "$_p" auth zone reload --zone br.test. 2>&1 | tail -1)"
	sleep 2

	if [ "$2" = release ]; then
		_rel=$(_br_cli "$_p" auth config transport-signal --release ns1.br.test. 2>&1)
		note "$_p release: $(echo "$_rel" | tr '\n' '|')"
		check B2 "$_p: the release says ns1.br.test. is released" sh -c 'echo "$1" | grep -qi released' _ "$_rel"
	fi

	stop_daemon "$_p"
	_br_conf "$_p" "" "doq:20,dot:10" || { fail "bridge: $_p did not restart"; return; }
	sleep 5
	_after=$(rdata "$BR_A" _dns.ns1.br.test. SVCB)
	note "$_p after the restart without the identity: $(echo "$_after" | tr '\n' '|')"
	if [ "$2" = release ]; then
		check B2 "$_p: released, the records stay once the name leaves service.identities" [ -n "$_after" -a "$_after" = "$_printed" ]
		stop_daemon "$_p"
		_br_conf "$_p" "" "doq:50,dot:10" || { fail "bridge: $_p did not restart"; return; }
		sleep 5
		_after=$(rdata "$BR_A" _dns.ns1.br.test. SVCB)
		note "$_p after a changed service.transport: $(echo "$_after" | tr '\n' '|')"
		check B3 "$_p: a changed service.transport does not reach provisioned records" [ -n "$_after" -a "$_after" = "$_printed" ]
	else
		check B4 "$_p: without the release the records are withdrawn" [ -n "$_served" -a -z "$_after" ]
	fi
	stop_daemon "$_p"
}
