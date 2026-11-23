# suites/pins.sh: #1168, tdns-ncli verifies the daemon (pins) and presents a
# client certificate; a local tdns-ncli manages the access file. Sourced by
# run.sh. Needs the roles suite's helpers (access_variants) and #1167's
# daemon, so it runs only on a build that has both.
. "$SRC/suites/roles.sh"

pinof() { awk -v n="$1" '$1==n{print $2}' "$CERTS/pins.txt"; }

suite_pins() {
	daemon_stop auth; daemon_stop imr
	access_variants
	printf 'keyauth: true\nclients: []\n' > "$ACC"; chmod 0600 "$ACC"
	# root's entries, with tdns-auth's config-file: the access-file variant, as
	# the client commands find the access file through it.
	sed "s|/var/tmp/cli-access/auth/tdns-auth.yaml|$RIG/auth/v-access.yaml|" "$RIG/ncli/root.yaml" > "$RIG/ncli/rootacc.yaml"
	chmod 0600 "$RIG/ncli/rootacc.yaml"
	daemon_start auth "$RIG/auth/v-access.yaml" || { fail P0 "tdns-auth starts with an empty access file" "$LOG/tdns-auth.stdout"; return; }
	daemon_start imr || { fail P0 "tdns-imr starts" "$LOG/tdns-imr.stdout"; return; }
	pass P0 "tdns-auth (empty access file) and tdns-imr (plain http) start"
	remote_or_skip P "every pin and client-certificate case runs from the CLI host" || return

	# ---- the CLI verifies the daemon ---------------------------------------------------
	o=$(out P1-pin); ncli_remote pins auth ping > "$o" 2>&1
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o"
	judge P1a "the daemon's right SPKI pin: accepted" $? "$o"
	o=$(out P1-badpin); m=$(log_mark auth); ncli_remote pins authbadpin ping > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && ! grep -q 'pongs:' "$o" && grep -qi 'pin' "$o"
	judge P1b "a wrong pin: refused, saying so" $? "$o"
	o2=$(out P1-badpin-log); log_since auth "$m" > "$o2"
	! grep -q 'api request.*apikey' "$o2"
	judge P1c "...and the key was not sent to the daemon that failed the pin" $? "$o2"
	o=$(out P1-pkix); ncli_remote pins authpkix ping > "$o" 2>&1
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o"
	judge P1d "tlsauth: pkix with the rig's CA: accepted" $? "$o"
	o=$(out P1-noverify); ncli_remote pins authnoverify ping > "$o" 2>&1
	if newcli; then
		[ "$(rc_of "$o")" = 1 ] && grep -q '^Error: not connecting to authnoverify:' "$o" && grep -q 'Fix: tdns-ncli config add' "$o" && ! grep -q 'pongs:' "$o"
	else
		[ "$(rc_of "$o")" != 0 ] && grep -q 'does not verify the daemon' "$o" && ! grep -q 'pongs:' "$o"
	fi
	judge P1e "an https entry that verifies nothing: tdns-ncli refuses it (an error, with config add as the fix)" $? "$o"

	# ---- the operator's client certificate ----------------------------------------------
	o=$(out P2-init)
	ncli_remote cert client init --cert $RIG/home/operator.crt --key $RIG/home/operator.key --name operator > "$o" 2>&1
	opin=$(sed -n 's/^Pin: *//p' "$o" | head -1)
	[ "$(rc_of "$o")" = 0 ] && [ -n "$opin" ]
	judge P2a "client init on the CLI host: a key pair and its pin" $? "$o"
	o=$(out P2-add); ncli_root rootacc auth client add operator --pin "$opin" --role read-write > "$o"
	[ "$(rc_of "$o")" = 0 ] && grep -q 'reloaded' "$o" && grep -q 'operator' "$ACC" && [ -f "$ACC.prev" ]
	judge P2b "client add as root on the daemon host: written (with .prev) and reloaded over the socket" $? "$o"
	o=$(out P2-cert); ncli_remote cert auth ping > "$o" 2>&1
	if newcli; then grep -q 'pong (TLS, read-write, certificate operator) from' "$o"; else grep -q 'authenticated as operator (read-write) by certificate' "$o"; fi
	judge P2c "authmethod: certificate: read-write as operator (ping: \"TLS, read-write, certificate operator\")" $? "$o"
	o=$(out P2-certkey); ncli_remote cert authkey ping > "$o" 2>&1
	if newcli; then grep -q 'pong (TLS, read-write) from' "$o"; else grep -q 'authenticated as apikey (read-write) by api key' "$o"; fi
	judge P2d "an entry without authmethod: certificate does not present it (the key, read-write)" $? "$o"
	o=$(out P2-unknown); ncli_remote unknown auth ping > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -qi '403\|forbidden' "$o" && ! grep -q 'pongs:' "$o"
	judge P2e "an unknown client certificate: refused" $? "$o"
	o=$(out P2-unknownkey); raw_remote -c unknown -k -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o"
	[ "$(status_of "$o")" = 403 ]
	judge P2f "an unknown client certificate with a valid key: refused (403)" $? "$o"

	# ---- the local tdns-ncli manages the access file -------------------------------------
	o=$(out P3-list); ncli_root rootacc auth client list > "$o"
	[ "$(rc_of "$o")" = 0 ] && grep -q 'operator' "$o" && ! grep -qi 'pending' "$o"
	judge P3a "client list: operator, and the daemon runs the file (nothing pending)" $? "$o"
	o=$(out P3-ro); ncli_root rootacc auth client set-role operator read-only > "$o"
	o2=$(out P3-ro-bump); ncli_remote cert auth zone bump -z $ZONE > "$o2" 2>&1
	[ "$(rc_of "$o")" = 0 ] && grep -q 'needs read-write' "$o2"
	judge P3b "client set-role read-only: the operator's bump is then refused" $? "$o" "$o2"
	o=$(out P3-dis); ncli_root rootacc auth client disable operator > "$o"
	o2=$(out P3-dis-ping); ncli_remote cert auth ping > "$o2" 2>&1
	[ "$(rc_of "$o")" = 0 ] && [ "$(rc_of "$o2")" != 0 ] && grep -qi '403\|forbidden' "$o2"
	judge P3c "client disable: the operator is refused" $? "$o" "$o2"
	o=$(out P3-en); ncli_root rootacc auth client enable operator > "$o"
	o2=$(out P3-en-ping); ncli_remote cert auth ping > "$o2" 2>&1
	if newcli; then grep -q 'pong (TLS, read-only, certificate operator) from' "$o2"; else grep -q 'authenticated as operator (read-only) by certificate' "$o2"; fi
	judge P3d "client enable: the operator is back (read-only)" $? "$o" "$o2"
	o=$(out P3-koff); ncli_root rootacc auth client keyauth off > "$o"
	o2=$(out P3-koff-key); ncli_remote pins auth ping > "$o2" 2>&1
	o3=$(out P3-koff-cert); ncli_remote cert auth ping > "$o3" 2>&1
	[ "$(rc_of "$o2")" != 0 ] && grep -qi '403\|forbidden' "$o2" && grep -q 'pongs:' "$o3"
	judge P3e "client keyauth off: the key is refused, the certificate works" $? "$o" "$o2" "$o3"
	o=$(out P3-kon); ncli_root rootacc auth client keyauth on > "$o"
	o2=$(out P3-kon-key); ncli_remote pins auth ping > "$o2" 2>&1
	grep -q 'pongs:' "$o2"
	judge P3f "client keyauth on: the key works again" $? "$o" "$o2"
	cp "$ACC" "$RUNDIR/access-before-admin.yaml"
	o=$(out P3-admin); ncli_root rootacc auth client add boss --pin "$(pinof rw)" --role admin > "$o"
	[ "$(rc_of "$o")" != 0 ] && grep -qi 'only on the local socket' "$o" && cmp -s "$ACC" "$RUNDIR/access-before-admin.yaml"
	judge P3g "client add --role admin: refused, the file unchanged" $? "$o"
	o=$(out P3-remote); ncli_remote pins auth client add intruder --pin "$(pinof rw)" --role read-write > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && ! grep -q 'intruder' "$ACC"
	judge P3h "client add from the CLI host (a remote daemon): refused, nothing changed" $? "$o"

	# ---- config add pins the daemon --------------------------------------------------------
	f=$RIG/ncli/add-pin.yaml; addfile "$f"
	o=$(out P4-add); ncli_root add-pin config add --tcp "$RIG/auth/v-access.yaml" > "$o"; cat "$f" >> "$o" 2>/dev/null
	grep -q 'tlsauth: *pin' "$f" && grep -q "$(pinof daemon)" "$f"
	judge P4 "config add --tcp writes the daemon's pin" $? "$o"

	# ---- http:// to a non-loopback host warns once; loopback is quiet -------------------------
	o=$(out P5-http); ncli_remote pins imr ping > "$o" 2>&1
	[ "$(rc_of "$o")" = 0 ] && [ "$(grep -c 'plain http' "$o")" = 1 ]
	judge P5a "http:// to the daemon host from the CLI host: works, warns exactly once" $? "$o"
	o=$(out P5-loop); ncli_user local imr ping > "$o"
	[ "$(rc_of "$o")" = 0 ] && ! grep -qi 'warning' "$o"
	judge P5b "http:// over loopback: no warning" $? "$o"

	# ---- duplicate pins ------------------------------------------------------------------------
	o=$(out P6-dup); ncli_remote dup config list > "$o" 2>&1
	grep -q 'pin the same key' "$o"
	judge P6 "config list warns when two daemons' entries pin the same key" $? "$o"
	o=$(out P6-same); ncli_remote cert config list > "$o" 2>&1
	grep -q 'pin the same key' "$o" && echo "INFO config list also warns for two entries of ONE daemon (key + certificate), see $o" | tee -a "$RES"

	# ---- tdns-cli is unchanged -------------------------------------------------------------------
	o=$(out P7-cli); ncli_remote cli cli auth ping > "$o" 2>&1
	o2=$(out P7-cli-http); ncli_remote cli cli imr ping > "$o2" 2>&1
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o" && ! grep -qi 'warning' "$o" \
		&& [ "$(rc_of "$o2")" = 0 ] && ! grep -qi 'warning' "$o2"
	judge P7 "tdns-cli: an unverified https entry and an http:// entry work as before, no warnings" $? "$o" "$o2"

	newcli && routing
	defcert && default_cert
	daemon_stop auth; daemon_stop imr
}

# default_cert: #1182, the default API certificate. A config with neither
# apiserver.certfile nor keyfile uses {confdir}/certs/{config name}-api.{crt,key}.
# config add makes a missing pair itself (Johan, 2026-11-23: the same paths,
# code and modes as the daemon's first start) and pins it; the daemon then
# uses it, never overwrites it, and refuses half a pair. A certfile: the
# config names that is missing is refused by config add. (The daemon's own
# first-start write is S13c.)
default_cert() {
	daemon_stop auth
	V=$RIG/auth/v-defcert.yaml
	sed '/^   certfile: /d; /^   keyfile: /d' "$RIG/auth/tdns-auth.yaml" > "$V"; chmod 0644 "$V"
	crt=$RIG/auth/certs/v-defcert-api.crt key=$RIG/auth/certs/v-defcert-api.key
	rm -f "$crt" "$key"
	o=$(out P11a-check); ncli_root root auth config check --offline --serverconfig "$V" > "$o" 2>&1
	grep -q "writes a self-signed pair at $crt" "$o" && ! grep -q 'FAIL' "$o"
	judge P11a "no certfile/keyfile, no pair yet: config check says the daemon will write $crt, no FAIL" $? "$o"
	f=$RIG/ncli/add-defcert.yaml; addfile "$f"
	o=$(out P11b-add); ncli_root add-defcert config add "$V" > "$o" 2>&1
	cat "$f" >> "$o" 2>/dev/null; ls -l "$crt" "$key" >> "$o" 2>&1
	dpin=$(pin_of_cert "$crt")
	[ "$(rc_of "$o")" = 0 ] && [ -n "$dpin" ] && grep -q "$dpin" "$f" \
		&& [ "$(ls -l "$key" 2>/dev/null | awk '{print substr($1,1,10), $3}')" = "-rw------- root" ]
	judge P11b "...config add before the first start: makes the pair (key 0600 root's) and pins it" $? "$o"
	sum1=$(cksum < "$crt" 2>/dev/null)
	o=$(out P11c-start)
	if daemon_start auth "$V"; then
		ls -l "$crt" "$key" > "$o" 2>&1; grep 'self-signed' "$LOG/tdns-auth.log" >> "$o"
		[ -n "$sum1" ] && [ "$(cksum < "$crt")" = "$sum1" ] && ! grep -q 'wrote a self-signed API certificate' "$LOG/tdns-auth.log"; r=$?
	else
		sed -n '/=== .* start .*v-defcert/,$p' "$LOG/tdns-auth.stdout" > "$o"; r=1
	fi
	judge P11c "...the first start uses that pair and writes none" $r "$o"
	o2=$(out P11d-ping); ncli_root add-defcert --tcp auth ping > "$o2"
	if certadd; then want='pong (TLS, read-write, certificate '; else want='pong (TLS, admin) from'; fi
	[ "$(rc_of "$o2")" = 0 ] && grep -q "$want" "$o2"
	judge P11d "...and the pinned entry reaches the daemon over TLS" $? "$o2"
	daemon_stop auth
	o=$(out P11e-restart)
	daemon_start auth "$V" > "$o" 2>&1; ls -l "$crt" >> "$o" 2>&1
	[ -n "$sum1" ] && [ "$(cksum < "$crt")" = "$sum1" ] && [ -n "$(pids_of auth)" ]
	judge P11e "...a restart keeps the pair as it was" $? "$o"
	daemon_stop auth
	rm -f "$key"
	o=$(out P11f-half)
	if daemon_start auth "$V"; then
		echo "tdns-auth started with half a default pair" > "$o"; ls -l "$key" >> "$o" 2>&1; daemon_stop auth; r=1
	else
		sed -n '/=== .* start .*v-defcert/,$p' "$LOG/tdns-auth.stdout" | tail -20 > "$o"
		[ ! -e "$key" ] && grep -qi 'keyfile' "$o"; r=$?
	fi
	judge P11f "...with the key removed: the daemon refuses the config and writes no new key" $r "$o"
	daemon_stop auth
	V2=$RIG/auth/v-certgone.yaml
	sed "s|^   certfile: .*|   certfile:   $RIG/certs/not-there.crt|" "$RIG/auth/tdns-auth.yaml" > "$V2"; chmod 0644 "$V2"
	f2=$RIG/ncli/add-certgone.yaml; addfile "$f2"
	o=$(out P11g-gone); ncli_root add-certgone config add "$V2" > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -q '^Error: not adding' "$o" && ! grep -q 'apiservers' "$f2" 2>/dev/null \
		&& [ ! -e "$RIG/certs/not-there.crt" ] && [ ! -e "$RIG/auth/v-certgone-access.yaml" ]
	judge P11g "a certfile: the config names that is missing: config add refuses, writes nothing, makes no pair" $? "$o"
	rm -f "$crt" "$key" "$f" "$f2" "$V" "$V2" "$RIG/auth/v-defcert-access.yaml" "$RIG/auth/v-defcert-access.yaml.prev" "$RIG/auth/v-defcert.yaml.prev"
}

# A TCP entry for tdns-auth with config-file: CFG: entry FILE URL CFG
tcp_entry() {
	printf 'apiservers:\n   - name:        tdns-auth\n     baseurl:     %s/api/v1\n     apikey:      cli-access-rig-test-key\n     authmethod:  X-API-Key\n     tlsauth:     pin\n     pins:        [ "%s" ]\n     config-file: %s\n' \
		"$2" "$(pinof daemon)" "$3" > "$1"
	chmod 0600 "$1"
}
# A ping over tdns-auth's socket whose request names config file CFG.
sockping() {
	printf 'POST /api/v1/ping HTTP/1.1\r\nHost: localhost\r\nX-Tdns-Config-File: %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}' "$1" \
		| nc -U "$AUTH_SOCK" 2>&1 | tr -d '\r'
}

# routing: #1168's revised routing (2026-11-23), on a build with tdns-ncli
# --tcp. Root's TCP entry with config-file: reaches the daemon over its admin
# socket, only when the entry's address is that daemon's and the daemon on the
# socket runs that config; --tcp keeps TCP; config add pins a known entry;
# every daemon serves a socket by default, named after its config path, and
# "socket: none" turns it off. Runs with tdns-auth on the access-file variant
# (the key is read-write over TCP), then on variants without an access file.
routing() {
	f=$RIG/ncli/add-route.yaml; addfile "$f"
	o=$(out P8-add); ncli_root add-route config add "$RIG/auth/v-access.yaml" > "$o"; cat "$f" >> "$o" 2>/dev/null
	o2=$(out P8a-ping); ncli_root add-route auth ping > "$o2"
	o3=$(out P8a-tsig); ncli_root add-route auth config reload-tsig > "$o3"
	[ "$(rc_of "$o2")" = 0 ] && grep -q "pong ($AUTH_SOCK) from" "$o2" && [ "$(rc_of "$o3")" = 0 ] && ! grep -q 'needs admin' "$o3"
	judge P8a "root, the TCP entry config add wrote: over the socket (ping says so), admin (reload-tsig works)" $? "$o" "$o2" "$o3"
	o2=$(out P8b-ping); ncli_root add-route --tcp auth ping > "$o2"
	o3=$(out P8b-tsig); ncli_root add-route --tcp auth config reload-tsig > "$o3"
	if certadd; then want='pong (TLS, read-write, certificate '; else want='pong (TLS, read-write) from'; fi
	[ "$(rc_of "$o2")" = 0 ] && grep -q "$want" "$o2" && [ "$(rc_of "$o3")" != 0 ] && grep -q 'needs admin' "$o3"
	judge P8b "...with --tcp: over TCP with the key, read-write (reload-tsig 403, needs admin)" $? "$o2" "$o3"
	o=$(out P8b-unix); ncli_root rootacc --tcp auth ping > "$o"
	[ "$(rc_of "$o")" != 0 ] && grep -q 'no TCP address for --tcp' "$o"
	judge P8c "--tcp on a unix:// entry: refused, it has no TCP address" $? "$o"

	f=$RIG/home/route-other.yaml
	tcp_entry "$f" https://localhost:$AUTH_API "$RIG/auth/v-access.yaml"
	o=$(out P8d-addr); ncli_root home/route-other auth ping > "$o"
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pong (TLS, read-write) from' "$o"
	judge P8d "root, an entry whose address the daemon config does not list (localhost:$AUTH_API): stays on TCP" $? "$o"
	cp "$RIG/auth/v-access.yaml" "$RIG/auth/v-other.yaml"; chmod 0644 "$RIG/auth/v-other.yaml"
	tcp_entry "$f" https://127.0.0.1:$AUTH_API "$RIG/auth/v-other.yaml"
	o=$(out P8e-cfg); ncli_root home/route-other auth ping > "$o"
	[ "$(rc_of "$o")" = 0 ] && grep -q "runs $RIG/auth/v-access.yaml, not $RIG/auth/v-other.yaml; not using its socket" "$o" \
		&& grep -q 'pong (TLS, read-write) from' "$o"
	judge P8e "root, an entry naming another config with the same socket: the socket is not used (said), TCP is" $? "$o"
	rm -f "$f" "$RIG/auth/v-other.yaml"
	o=$(out P8f-412); sockping /etc/tdns/tdns-auth.yaml > "$o"
	o2=$(out P8f-200); sockping "$RIG/auth/v-access.yaml" > "$o2"
	head -1 "$o" | grep -q ' 412 ' && grep -q "this daemon runs $RIG/auth/v-access.yaml" "$o" && head -1 "$o2" | grep -q ' 200 '
	judge P8f "the daemon refuses a socket request naming another config (412), and serves one naming its own" $? "$o" "$o2"

	# config add pins an entry it already knows (one written before pinning), as the user.
	f=$RIG/home/repin.yaml
	printf 'apiservers:\n   - name:        tdns-auth\n     baseurl:     https://127.0.0.1:%s/api/v1\n     apikey:      cli-access-rig-test-key\n     authmethod:  X-API-Key\n     rootca:      %s\n     config-file: %s\n   - name:        tdns-imr\n     baseurl:     http://127.0.0.1:%s/api/v1\n     apikey:      cli-access-rig-test-key\n     authmethod:  X-API-Key\n' \
		$AUTH_API "$CERTS/ca.crt" "$RIG/auth/v-access.yaml" $IMR_API > "$f"
	if certadd; then { printf 'client:\n   cert:          %s\n   key:           %s\n' "$RIG/home/user-client.crt" "$RIG/home/user-client.key"; cat "$f"; } > "$f.cb"; mv "$f.cb" "$f"; fi
	chown "$RIGUSER" "$f"; chmod 0600 "$f"; cp "$f" "$RUNDIR/repin-before.yaml"
	o=$(out P9a-repin); ncli_user home/repin config add "$RIG/auth/v-access.yaml" > "$o" 2>&1
	diff "$RUNDIR/repin-before.yaml" "$f" >> "$o"
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pinned the daemon' "$o" && grep -q 'tlsauth: *pin' "$f" && grep -q "$(pinof daemon)" "$f" \
		&& ! grep -q 'rootca:' "$f" && [ "$(diff "$RUNDIR/repin-before.yaml" "$f" | grep -c '^[<>]')" = 3 ]
	judge P9a "config add on a known entry with no pin (rootca:): pins it, drops rootca:, changes nothing else" $? "$o"
	o=$(out P9b-again); ncli_user home/repin config add "$RIG/auth/v-access.yaml" > "$o" 2>&1
	o2=$(out P9b-ping); ncli_user home/repin auth ping > "$o2"
	if certadd; then want='keeps the API key'; else want='nothing changed'; fi
	[ "$(rc_of "$o")" = 0 ] && flat "$o" | grep -q "$want" && grep -q 'pong (TLS, read-write) from' "$o2"
	judge P9b "...run again: nothing changed (#1184: the entry keeps the key, the user cannot enrol); and the re-pinned entry works" $? "$o" "$o2"
	rm -f "$f"

	# A socket by default, named after the config path; socket: none.
	daemon_stop auth
	sed '/^   socket:/d' "$RIG/auth/tdns-auth.yaml" > "$RIG/auth/v-default.yaml"
	sed 's|^   socket: .*|   socket:     none|' "$RIG/auth/tdns-auth.yaml" > "$RIG/auth/v-none.yaml"
	chmod 0644 "$RIG/auth/v-default.yaml" "$RIG/auth/v-none.yaml"
	ds=$(default_sock "$RIG/auth/v-default.yaml")
	o=$(out P10a-default); o2=$(out P10a-ping)
	if daemon_start auth "$RIG/auth/v-default.yaml"; then
		ls -l /var/run/tdns/ > "$o" 2>&1
		f=$RIG/ncli/add-default.yaml; addfile "$f"
		ncli_root add-default config add "$RIG/auth/v-default.yaml" >> "$o"
		ncli_root add-default auth ping > "$o2"
		[ "$(ls -l "$ds" 2>/dev/null | awk '{print substr($1,1,10), $3}')" = "srw------- root" ] \
			&& grep -q "pong ($ds) from" "$o2"; r=$?
		rm -f "$f"
	else
		sed -n '/=== .* start .*v-default/,$p' "$LOG/tdns-auth.stdout" > "$o"; r=1
	fi
	judge P10a "no socket line: the daemon serves $ds (0600), and root's config add entry finds it" $r "$o" "$o2"
	daemon_stop auth
	o=$(out P10b-gone); ls -l /var/run/tdns/ > "$o" 2>&1
	[ ! -e "$ds" ]
	judge P10b "...and the default socket is gone after the daemon stops" $? "$o"
	o=$(out P10c-none); o2=$(out P10c-ping)
	if daemon_start auth "$RIG/auth/v-none.yaml"; then
		ls -l /var/run/tdns/ > "$o" 2>&1
		f=$RIG/ncli/add-none.yaml; addfile "$f"
		ncli_root add-none config add "$RIG/auth/v-none.yaml" >> "$o" 2>&1
		ncli_root add-none auth ping > "$o2"
		if certadd; then
			# #1184: no socket, so no access file, so no certificate entry.
			[ -z "$(ls /var/run/tdns/ | grep -v '^tdns-imr.sock$')" ] && grep -q 'serves no local admin socket' "$o" \
				&& [ "$(rc_of "$o")" != 0 ] && ! grep -q 'apiservers' "$f"; r=$?
		else
			[ -z "$(ls /var/run/tdns/ | grep -v '^tdns-imr.sock$')" ] && ! grep -q 'local admin socket' "$o" && grep -q 'pong (TLS, admin) from' "$o2"; r=$?
		fi
		rm -f "$f"
	else
		sed -n '/=== .* start .*v-none/,$p' "$LOG/tdns-auth.stdout" > "$o"; r=1
	fi
	judge P10c "socket: none: no socket is served; root's entry goes over TCP (admin: no access file); #1184: a new entry is refused" $r "$o" "$o2"
	daemon_stop auth
	rm -f "$RIG/auth/v-default.yaml" "$RIG/auth/v-none.yaml" "$RIG/auth/v-default-access.yaml" "$RIG/auth/v-default-access.yaml.prev" "$RIG/auth/v-default.yaml.prev"
}
