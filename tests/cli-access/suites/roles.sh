# suites/roles.sh: #1167, the access file and the three roles. Sourced by run.sh.
#
# tdns-ncli presents client certificates only from #1168 on, so here the
# certificate clients are raw.sh (openssl s_client) and the access file is
# written by hand, as the design allows for recovery. tdns-ncli's own client
# commands are checked in the pins suite.

ACC=$RIG/auth/access.yaml

access_variants() {
	sed 's|^#  access-file:|   access-file:|' "$RIG/auth/tdns-auth.yaml" > "$RIG/auth/v-access.yaml"
	sed -e 's|^#  access-file:|   access-file:|' -e '/^   socket:/d' "$RIG/auth/tdns-auth.yaml" > "$RIG/auth/v-nosock.yaml"
	chmod 0644 "$RIG/auth/v-access.yaml" "$RIG/auth/v-nosock.yaml"
}
access_seed() { cp "$RIG/auth/access.seed" "$ACC"; chmod 0600 "$ACC"; }
# A file the daemon must refuse: a network client asking for admin.
access_broken() {
	printf 'keyauth: true\nclients:\n   - name: wants-admin\n     pin: "%s"\n     role: admin\n' \
		"$(awk '$1=="ro"{print $2}' "$CERTS/pins.txt")" > "$ACC"
}
reload_sock() { ncli_root root auth config reload > "$1"; }

suite_roles() {
	daemon_stop auth; daemon_stop imr
	access_variants; access_seed
	daemon_start auth "$RIG/auth/v-access.yaml" || { fail R0 "tdns-auth starts with an access file" "$LOG/tdns-auth.stdout"; return; }
	o=$(out R0); ncli_root root auth config status -v > "$o"
	grep -q "Access file: $ACC; the API key is accepted (read-write); 3 client(s)" "$o"
	judge R0 "tdns-auth runs the access file: key read-write, 3 clients (config status -v)" $? "$o"

	# ---- read-only ------------------------------------------------------------------
	if remote_or_skip R1 "read-only client: reads, refused writes"; then
		o=$(out R1-list); raw_remote -c ro -b cmd:list-zones "$DAEMON_ADDR:$AUTH_API" /api/v1/zone > "$o"
		o2=$(out R1-status); raw_remote -c ro -b cmd:status "$DAEMON_ADDR:$AUTH_API" /api/v1/config > "$o2"
		[ "$(status_of "$o")" = 200 ] && [ "$(status_of "$o2")" = 200 ]
		judge R1a "read-only client (certificate, from the CLI host): zone list-zones and config status 200" $? "$o" "$o2"
		o=$(out R1-bump); raw_remote -c ro -b cmd:bump:$ZONE "$DAEMON_ADDR:$AUTH_API" /api/v1/zone > "$o"
		[ "$(status_of "$o")" = 403 ] && grep -q 'needs read-write' "$o"
		judge R1b "read-only client: zone bump 403 (\"needs read-write\")" $? "$o"
		o=$(out R1-stop); raw_remote -c ro -b cmd:stop:. "$DAEMON_ADDR:$AUTH_API" /api/v1/command > "$o"
		[ "$(status_of "$o")" = 403 ] && [ -n "$(pids_of auth)" ]
		judge R1c "read-only client: stop 403, daemon still running" $? "$o"
	fi

	# ---- read-write: the key, and a read-write certificate ----------------------------
	if remote_or_skip R2 "the key is read-write"; then
		o=$(out R2-ping); ncli_remote remote auth ping > "$o" 2>&1
		if newcli; then grep -q 'pong (TLS, read-write) from' "$o"; else grep -q 'authenticated as apikey (read-write) by api key' "$o"; fi
		judge R2a "the API key, from the CLI host: read-write (ping: \"TLS, read-write\", or \"authenticated as apikey (read-write)\")" $? "$o"
		o=$(out R2-bump); ncli_remote remote auth zone bump -z $ZONE > "$o" 2>&1
		[ "$(rc_of "$o")" = 0 ] && ! grep -qi 'forbidden\|403\|needs' "$o"
		judge R2b "the key: zone bump works" $? "$o"
		o=$(out R2-stop); ncli_remote remote auth stop > "$o" 2>&1
		sleep 2
		[ "$(rc_of "$o")" != 0 ] && grep -q 'needs admin' "$o" && grep -qi 'socket' "$o" && [ -n "$(pids_of auth)" ]
		judge R2c "the key: stop refused (403, \"needs admin\", names the socket), daemon still running" $? "$o"
		[ -n "$(pids_of auth)" ] || daemon_start auth "$RIG/auth/v-access.yaml"
		o=$(out R2-tsig); ncli_remote remote auth config reload-tsig > "$o" 2>&1
		[ "$(rc_of "$o")" != 0 ] && grep -q 'needs admin' "$o"
		judge R2d "the key: config reload-tsig refused (admin)" $? "$o"
		o=$(out R2-rwcert); raw_remote -c rw -b cmd:bump:$ZONE "$DAEMON_ADDR:$AUTH_API" /api/v1/zone > "$o"
		o2=$(out R2-rwcert-stop); raw_remote -c rw -b cmd:stop:. "$DAEMON_ADDR:$AUTH_API" /api/v1/command > "$o2"
		[ "$(status_of "$o")" = 200 ] && [ "$(status_of "$o2")" = 403 ] && grep -q 'needs admin' "$o2" && [ -n "$(pids_of auth)" ]
		judge R2e "read-write client (certificate): bump 200, stop 403 (admin)" $? "$o" "$o2"
	fi

	# ---- admin is the socket's alone ---------------------------------------------------
	o=$(out R3-sock-ping); ncli_root root auth ping > "$o"
	if newcli; then grep -q "pong ($AUTH_SOCK) from" "$o"; else grep -q 'on the local socket (admin)' "$o"; fi
	judge R3a "root on the socket: admin (ping: \"pong (<socket path>)\", or \"on the local socket (admin)\")" $? "$o"
	o=$(out R3-sock-tsig); ncli_root root auth config reload-tsig > "$o"
	[ "$(rc_of "$o")" = 0 ] && ! grep -q 'needs admin' "$o"
	judge R3b "root on the socket: config reload-tsig works" $? "$o"
	o=$(out R3-loop-stop); ncli_user local auth stop > "$o"
	o2=$(out R3-loop-tsig); ncli_user local auth config reload-tsig > "$o2"
	sleep 2
	grep -q 'needs admin' "$o" && grep -q 'needs admin' "$o2" && [ -n "$(pids_of auth)" ]
	judge R3c "the key over loopback TCP (a local non-root user): stop and reload-tsig refused" $? "$o" "$o2"
	[ -n "$(pids_of auth)" ] || daemon_start auth "$RIG/auth/v-access.yaml"

	# ---- a certificate is the identity --------------------------------------------------
	if remote_or_skip R4 "unknown or disabled certificate with a valid key: 403"; then
		o=$(out R4-unknown); raw_remote -c unknown -k -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o"
		o2=$(out R4-off); raw_remote -c off -k -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o2"
		[ "$(status_of "$o")" = 403 ] && [ "$(status_of "$o2")" = 403 ]
		judge R4a "an unknown certificate, and a disabled one, are refused even with a valid key" $? "$o" "$o2"
		o=$(out R4-rokey); raw_remote -c ro -k -b cmd:bump:$ZONE "$DAEMON_ADDR:$AUTH_API" /api/v1/zone > "$o"
		[ "$(status_of "$o")" = 403 ]
		judge R4b "a read-only certificate with the (read-write) key is still read-only" $? "$o"
	fi

	# ---- the size limit -------------------------------------------------------------------
	o=$(out R5-big); raw_local -k -B 67108865 127.0.0.1:$AUTH_API /api/v1/zone > "$o" 2>&1
	o2=$(out R5-small); raw_local -k -B 1024 127.0.0.1:$AUTH_API /api/v1/zone > "$o2" 2>&1
	[ "$(status_of "$o")" = 413 ] && [ "$(status_of "$o2")" != 413 ] && [ "$(status_of "$o2")" != none ]
	judge R5 "the key (read-write): a body of 64 MiB + 1 gets 413; 1 KiB does not" $? "$o" "$o2"

	# ---- keyauth off ----------------------------------------------------------------------
	sed 's/^keyauth: true/keyauth: false/' "$RIG/auth/access.seed" > "$ACC"
	o=$(out R6-reload); reload_sock "$o"
	grep -q 'Access file reloaded: 3 client(s), keyauth off' "$o"
	judge R6a "keyauth: false, reloaded over the socket" $? "$o"
	if remote_or_skip R6b "keyauth off: key 403, certificate works"; then
		o=$(out R6-key); raw_remote -k -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o"
		o2=$(out R6-cert); raw_remote -c rw -b cmd:bump:$ZONE "$DAEMON_ADDR:$AUTH_API" /api/v1/zone > "$o2"
		[ "$(status_of "$o")" = 403 ] && [ "$(status_of "$o2")" = 200 ]
		judge R6b "keyauth off: the key gets 403, the read-write certificate still works" $? "$o" "$o2"
	fi
	access_seed; reload_sock "$(out R6-restore)"

	# ---- a broken file at a reload changes nothing ----------------------------------------
	access_broken
	o=$(out R7-reload); reload_sock "$o"
	grep -q 'Access file NOT reloaded' "$o" && grep -qi 'admin' "$o"
	judge R7a "a broken access file (role admin) at a reload: refused, with the reason" $? "$o"
	if remote_or_skip R7b "the running policy is unchanged after the refused reload"; then
		o=$(out R7-ro); raw_remote -c ro -b cmd:list-zones "$DAEMON_ADDR:$AUTH_API" /api/v1/zone > "$o"
		[ "$(status_of "$o")" = 200 ]
		judge R7b "...the previous policy is still in force (read-only client still reads)" $? "$o"
	fi
	access_seed; reload_sock "$(out R7-restore)"

	# ---- a broken file at start: DNS and the socket run, TCP answers 503 -----------------
	daemon_stop auth
	access_broken
	o=$(out R8-start)
	daemon_start auth "$RIG/auth/v-access.yaml" > "$o" 2>&1
	[ -n "$(pids_of auth)" ] && dns_answers auth
	judge R8a "a broken access file at start: the daemon runs and answers DNS" $? "$o" "$LOG/tdns-auth.stdout"
	o=$(out R8-sock); ncli_root root auth ping > "$o"
	o2=$(out R8-status); ncli_root root auth config status -v > "$o2"
	grep -q 'pongs:' "$o" && grep -q 'CANNOT BE USED' "$o2"
	judge R8b "...the socket works, and config status says the access file cannot be used" $? "$o" "$o2"
	o=$(out R8-local); raw_local -k -b empty 127.0.0.1:$AUTH_API /api/v1/ping > "$o" 2>&1
	[ "$(status_of "$o")" = 503 ]
	judge R8c "...TCP with the key: 503 (loopback)" $? "$o"
	if remote_or_skip R8d "TCP from the CLI host: 503"; then
		o=$(out R8-remote); raw_remote -k -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o"
		o2=$(out R8-remote-cert); raw_remote -c rw -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o2"
		[ "$(status_of "$o")" = 503 ] && [ "$(status_of "$o2")" = 503 ]
		judge R8d "...TCP from the CLI host, key or certificate: 503 (never a fall-back to key-only)" $? "$o" "$o2"
	fi
	access_seed
	o=$(out R8-fix); reload_sock "$o"
	o2=$(out R8-after); raw_local -k -b empty 127.0.0.1:$AUTH_API /api/v1/ping > "$o2" 2>&1
	grep -q 'Access file reloaded' "$o" && [ "$(status_of "$o2")" = 200 ]
	judge R8e "...fixed and reloaded over the socket: TCP answers again" $? "$o" "$o2"

	# ---- access-file without socket is refused ---------------------------------------------
	daemon_stop auth
	if newcli; then
		# #1168: no socket line is the default socket, so the access file has its
		# socket; only "socket: none" leaves it without one.
		ds=$(default_sock "$RIG/auth/v-nosock.yaml")
		o=$(out R9-default)
		if daemon_start auth "$RIG/auth/v-nosock.yaml"; then
			ls -l "$ds" > "$o" 2>&1
			[ "$(ls -l "$ds" 2>/dev/null | awk '{print substr($1,1,10), $3}')" = "srw------- root" ]; r=$?
			daemon_stop auth
		else
			sed -n '/=== .* start .*v-nosock/,$p' "$LOG/tdns-auth.stdout" > "$o"; r=1
		fi
		judge R9 "access-file and no socket line: the daemon starts and serves the default socket $ds" $r "$o"
		sed 's|^   socket: .*|   socket:     none|' "$RIG/auth/v-access.yaml" > "$RIG/auth/v-socknone.yaml"
		chmod 0644 "$RIG/auth/v-socknone.yaml"
		o=$(out R9b-none)
		if daemon_start auth "$RIG/auth/v-socknone.yaml"; then
			echo "tdns-auth is running with access-file and socket: none" > "$o"; daemon_stop auth; r=1
		else
			sed -n '/=== .* start .*v-socknone/,$p' "$LOG/tdns-auth.stdout" > "$o"
			grep -q 'requires the local admin socket' "$o" "$LOG/tdns-auth.log"; r=$?
		fi
		judge R9b "access-file with socket: none: the daemon refuses to start, saying why" $r "$o"
		daemon_stop auth
		return
	fi
	o=$(out R9-nosock)
	if daemon_start auth "$RIG/auth/v-nosock.yaml"; then
		echo "tdns-auth is running with access-file and no socket" > "$o"
		daemon_stop auth
		fail R9 "access-file without socket: the daemon refuses to start" "$o"
	else
		sed -n '/=== .* start .*v-nosock/,$p' "$LOG/tdns-auth.stdout" > "$o"
		grep -q 'requires apiserver.socket' "$o" "$LOG/tdns-auth.log"
		judge R9 "access-file without socket: the daemon refuses to start, saying why" $? "$o"
	fi

	daemon_stop auth
}
