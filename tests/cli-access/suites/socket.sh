# suites/socket.sh: #1165, the local admin socket. Sourced by run.sh.
#
# Needs nothing newer than #1165: no access file, no pins. Every daemon here
# has the API key as admin over TCP, as before the stack.

# variant NAME SED-EXPR: a copy of the seeded tdns-auth config with one change.
variant() {
	sed "$2" "$RIG/auth/tdns-auth.yaml" > "$RIG/auth/v-$1.yaml"
	cmp -s "$RIG/auth/tdns-auth.yaml" "$RIG/auth/v-$1.yaml" && die "variant $1 changed nothing"
	chmod 0644 "$RIG/auth/v-$1.yaml"
}
sockline() { echo "s|^   socket: .*|   socket:     $1|"; }

# A server error about the socket, as config status -v shows it (over TCP,
# as the ordinary user: the socket is what is broken). Without -v, config
# status prints only the count of active errors.
socket_error_shown() {   # socket_error_shown OUTFILE
	ncli_user local auth config status -v > "$1" 2>&1
	grep -qi 'ApiSocket\|admin socket.*not served' "$1"
}

# The daemon kept running and kept serving: process, DNS, TCP API with the key.
still_serving() {   # still_serving OUTFILE
	[ -n "$(pids_of auth)" ] || { echo "tdns-auth is not running" > "$1"; return 1; }
	dns_answers auth || { echo "tdns-auth does not answer DNS" > "$1"; return 1; }
	ncli_user local auth ping > "$1" 2>&1
	[ "$(rc_of "$1")" = 0 ] && grep -q 'pongs:' "$1"
}

suite_socket() {
	daemon_stop auth; daemon_stop imr
	rm -f "$AUTH_SOCK" "$IMR_SOCK"; rm -rf "$VDIR"
	daemon_start auth || { fail S0 "tdns-auth starts with the seeded config" "$LOG/tdns-auth.stdout"; return; }
	daemon_start imr  || { fail S0 "tdns-imr starts with the seeded config" "$LOG/tdns-imr.stdout"; return; }
	pass S0 "tdns-auth and tdns-imr start, as root, with a socket and TCP"

	# ---- root over the socket ------------------------------------------------
	o=$(out S1-auth); ncli_root root auth ping > "$o"
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o"
	judge S1a "root: tdns-auth ping over the socket, no key in the CLI config" $? "$o"
	o=$(out S1-imr); ncli_root root imr ping > "$o"
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o"
	judge S1b "root: tdns-imr ping over the socket (SetupSimpleAPIRouter)" $? "$o"
	o=$(out S1-admin); ncli_root root auth config reload-tsig > "$o"
	[ "$(rc_of "$o")" = 0 ] && ! grep -qi 'forbidden\|403' "$o"
	judge S1c "root: an admin command (config reload-tsig) over the socket, no key" $? "$o"

	o=$(out S2-perms)
	{ ls -ld /var/run/tdns; ls -l "$AUTH_SOCK" "$IMR_SOCK"; } > "$o" 2>&1
	d=$(ls -ld /var/run/tdns | awk '{print $1, $3}')
	a=$(ls -l "$AUTH_SOCK" | awk '{print substr($1,1,10), $3}')
	i=$(ls -l "$IMR_SOCK" | awk '{print substr($1,1,10), $3}')
	[ "$d" = "drwx------ root" ] && [ "$a" = "srw------- root" ] && [ "$i" = "srw------- root" ]
	judge S2 "the socket is 0600 root's, in a 0700 directory of root's" $? "$o"

	# ---- an ordinary user cannot open it, and is not moved to TCP --------------
	o=$(out S3-user); m=$(log_mark auth)
	ncli_user usersock auth ping > "$o"
	r=$(rc_of "$o")
	[ "$r" != 0 ] && grep -qi "admin socket\|$AUTH_SOCK" "$o" && grep -qi 'permission denied\|not yours' "$o" \
		&& ! grep -q 'pongs:' "$o" && ! grep -qi 'https://\|Tried addresses' "$o"
	judge S3a "a non-root user cannot open the socket: an error naming it, no fall-back to TCP" $? "$o"
	o2=$(out S3-log); log_since auth "$m" > "$o2"
	! grep -q 'api request\|/api/v1/ping' "$o2"
	judge S3b "...and the daemon saw no request from that attempt" $? "$o2"

	# ---- TCP without the key ---------------------------------------------------
	o=$(out S4-local); raw_local -b empty 127.0.0.1:$AUTH_API /api/v1/ping > "$o" 2>&1
	[ "$(status_of "$o")" = 403 ]
	judge S4a "TCP over loopback with no key: 403" $? "$o"
	if remote_or_skip S4b "TCP from the CLI host with no key: 403"; then
		o=$(out S4-remote); raw_remote -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o" 2>&1
		[ "$(status_of "$o")" = 403 ]
		judge S4b "TCP from the CLI host with no key: 403" $? "$o"
		o=$(out S4-ncli-nokey); ncli_remote remote authnokey ping > "$o" 2>&1
		[ "$(rc_of "$o")" != 0 ] && grep -qi '403\|forbidden' "$o" && ! grep -q 'pongs:' "$o"
		judge S4c "tdns-ncli from the CLI host, entry with no key: refused (403)" $? "$o"
		o=$(out S4-ncli-badkey); ncli_remote remote authbadkey ping > "$o" 2>&1
		[ "$(rc_of "$o")" != 0 ] && grep -qi '403\|forbidden' "$o" && ! grep -q 'pongs:' "$o"
		judge S4d "tdns-ncli from the CLI host, a wrong key: refused (403)" $? "$o"
		o=$(out S4-imr-nokey); ncli_remote remote imrnokey ping > "$o" 2>&1
		[ "$(rc_of "$o")" != 0 ] && grep -qi '403\|forbidden' "$o" && ! grep -q 'pongs:' "$o"
		judge S4e "tdns-imr from the CLI host, no key: refused (403)" $? "$o"
		o=$(out S4-ok); ncli_remote remote auth ping > "$o" 2>&1
		o2=$(out S4-ok-imr); ncli_remote remote imr ping > "$o2" 2>&1
		[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o" && [ "$(rc_of "$o2")" = 0 ] && grep -q 'pongs:' "$o2"
		judge S4f "control: with the key, both daemons answer the CLI host over TCP" $? "$o" "$o2"
	fi

	# ---- nothing sent over TCP passes as the socket ---------------------------------
	# Each must be 403: a request is from the socket because of the connection
	# it came in on, never because of anything in it.
	for h in Host=localhost Host=unix X-Forwarded-For=127.0.0.1 X-Real-Ip=127.0.0.1 \
	         Forwarded=for=unix X-Local-Socket=true X-Api-Socket=1 X-Api-Key=; do
		o=$(out "S5-local-$(echo "$h" | tr '=/' '__')")
		raw_local -H "$h" -b empty 127.0.0.1:$AUTH_API /api/v1/ping > "$o" 2>&1
		[ "$(status_of "$o")" = 403 ] || { fail S5a "loopback TCP with header $h passes as a socket request" "$o"; continue; }
	done
	o=$(out S5-abs); raw_local -b empty 127.0.0.1:$AUTH_API http://localhost/api/v1/ping > "$o" 2>&1
	[ "$(status_of "$o")" = 403 ] || [ "$(status_of "$o")" = 400 ]
	judge S5b "loopback TCP, absolute-form URL to localhost: refused" $? "$o"
	if remote_or_skip S5c "spoofed requests from the CLI host: all 403"; then
		bad=0
		for h in Host=localhost Host=unix X-Forwarded-For=127.0.0.1 X-Local-Socket=true; do
			o=$(out "S5-remote-$(echo "$h" | tr '=/' '__')")
			raw_remote -H "$h" -b empty "$DAEMON_ADDR:$AUTH_API" /api/v1/ping > "$o" 2>&1
			[ "$(status_of "$o")" = 403 ] || { fail S5c "TCP from the CLI host with header $h passes" "$o"; bad=1; }
		done
		[ $bad = 0 ] && pass S5c "spoofed requests from the CLI host: all 403"
	fi
	[ "$(grep -c '^FAIL S5a' "$RES")" = 0 ] && pass S5a "loopback TCP with 8 spoofing headers: every one 403"

	# ---- config status shows the socket -------------------------------------------
	# The ApiServer lines are part of config status -v.
	o=$(out S6-status-auth); ncli_root root auth config status -v > "$o"
	grep -q "local admin socket $AUTH_SOCK" "$o"
	judge S6a "config status (tdns-auth) shows the socket" $? "$o"
	o=$(out S6-status-imr); ncli_root root imr config status -v > "$o"
	grep -q "local admin socket $IMR_SOCK" "$o"
	judge S6b "config status (tdns-imr) shows the socket" $? "$o"

	# ---- config add ----------------------------------------------------------------
	if certadd; then config_add_cert; else
		f=$RIG/ncli/add-root.yaml; rm -f "$f"
		o=$(out S7-add-root); ncli_root add-root config add "$RIG/auth/tdns-auth.yaml" > "$o"
		ncli_root add-root config add "$RIG/imr/tdns-imr.yaml" >> "$o"
		cat "$f" >> "$o" 2>/dev/null
		if newcli; then
			# #1168: the TCP entry with config-file:, whoever runs it; root reaches
			# the daemon over its socket, found through config-file:.
			grep -q "baseurl: *https://127.0.0.1:$AUTH_API" "$f" && grep -q "baseurl: *http://127.0.0.1:$IMR_API" "$f" \
				&& ! grep -q 'unix://' "$f" && [ "$(grep -c 'config-file:' "$f")" = 2 ] && grep -q 'tlsauth: *pin' "$f" \
				&& grep -q "over its local admin socket $AUTH_SOCK" "$o"
			judge S7a "config add as root writes TCP entries with config-file: (key, pin), no unix://, and says root gets the socket" $? "$o"
		else
			grep -q "baseurl: *unix://$AUTH_SOCK" "$f" && grep -q "baseurl: *unix://$IMR_SOCK" "$f" \
				&& ! grep -qi 'apikey' "$f" && [ "$(grep -c 'authmethod: *none' "$f")" = 2 ]
			judge S7a "config add as root writes socket entries: unix://, authmethod none, no key" $? "$o"
		fi
		o2=$(out S7-add-root-use); ncli_root add-root auth ping > "$o2"
		if newcli; then grep -q "pong ($AUTH_SOCK) from" "$o2"; else grep -q 'pongs:' "$o2"; fi
		[ $? = 0 ] && [ "$(rc_of "$o2")" = 0 ]
		judge S7b "...and the entry it wrote works (#1168: as root, over the socket)" $? "$o2"
		if newcli; then
			o2=$(out S7f-add-root-tcp); ncli_root add-root --tcp auth ping > "$o2"
			[ "$(rc_of "$o2")" = 0 ] && grep -q 'pong (TLS, admin) from' "$o2"
			judge S7f "...tdns-ncli --tcp: the same entry over TCP with the key (admin: no access file)" $? "$o2"
		fi

		f=$RIG/ncli/add-tcp.yaml; rm -f "$f"
		o=$(out S7-add-tcp); ncli_root add-tcp config add --tcp "$RIG/auth/tdns-auth.yaml" > "$o"
		cat "$f" >> "$o" 2>/dev/null
		grep -q "baseurl: *https://127.0.0.1:$AUTH_API" "$f" && grep -q 'apikey' "$f" && ! grep -q 'unix://' "$f"
		judge S7c "config add --tcp as root writes the TCP entry with the key" $? "$o"

		# The user's CLI configs live in $RIG/home, which is the user's.
		f=$RIG/home/add-user.yaml; rm -f "$f"
		o=$(out S7-add-user); ncli_user home/add-user config add "$RIG/auth/tdns-auth.yaml" > "$o" 2>&1
		cat "$f" >> "$o" 2>/dev/null
		if newcli; then
			grep -q "baseurl: *https://127.0.0.1:$AUTH_API" "$f" && ! grep -q 'unix://' "$f" && grep -q 'config-file:' "$f"
			judge S7d "config add as a non-root user writes the same TCP entry, with config-file:" $? "$o"
		else
			grep -q "baseurl: *https://127.0.0.1:$AUTH_API" "$f" && ! grep -q 'unix://' "$f" && grep -qi 'root-only' "$o"
			judge S7d "config add as a non-root user writes the TCP entry and says why" $? "$o"
		fi
		o2=$(out S7-add-user-use); ncli_user home/add-user auth ping > "$o2"
		[ "$(rc_of "$o2")" = 0 ] && grep -q 'pongs:' "$o2"
		judge S7e "...and the user's entry works" $? "$o2"
	fi

	# ---- a stale socket is replaced at start ------------------------------------------
	daemon_stop auth KILL
	o=$(out S8-stale)
	{ echo "after kill -9:"; ls -l "$AUTH_SOCK"; } > "$o" 2>&1
	if [ -S "$AUTH_SOCK" ]; then
		daemon_start auth >> "$o" 2>&1
		ncli_root root auth ping >> "$o"
		grep -q 'pongs:' "$o" && grep -q 'serving the management API on the local admin socket' "$LOG/tdns-auth.log"
		judge S8 "a stale socket left by a crash is replaced at start" $? "$o" "$LOG/tdns-auth.stdout"
	else
		fail S8 "no socket file left after kill -9, so the stale case was not exercised" "$o"
		daemon_start auth
	fi

	# ---- a socket that cannot be served: the daemon runs, and says so ------------------
	# (a) a regular file where the socket goes: left alone.
	daemon_stop auth
	mkdir -p "$VDIR/ok"; chmod 0700 "$VDIR" "$VDIR/ok"
	echo "not a socket" > "$VDIR/ok/tdns-auth.sock"
	variant file "$(sockline "$VDIR/ok/tdns-auth.sock")"
	o=$(out S9-file)
	daemon_start auth "$RIG/auth/v-file.yaml"
	still_serving "$o"; r1=$?
	[ "$(cat "$VDIR/ok/tdns-auth.sock" 2>/dev/null)" = "not a socket" ]; r2=$?
	o2=$(out S9-file-status); socket_error_shown "$o2"; r3=$?
	[ $r1 = 0 ] && [ $r2 = 0 ] && [ $r3 = 0 ]
	judge S9a "a regular file at the socket path: not removed, daemon keeps serving, server error shown" $? "$o" "$o2" "$LOG/tdns-auth.log"

	# (b) a directory group and others can enter.
	daemon_stop auth
	mkdir -p "$VDIR/open"; chmod 0755 "$VDIR/open"
	variant open "$(sockline "$VDIR/open/tdns-auth.sock")"
	o=$(out S9-open)
	daemon_start auth "$RIG/auth/v-open.yaml"
	still_serving "$o"; r1=$?
	[ ! -e "$VDIR/open/tdns-auth.sock" ]; r2=$?
	o2=$(out S9-open-status); socket_error_shown "$o2"; r3=$?
	[ $r1 = 0 ] && [ $r2 = 0 ] && [ $r3 = 0 ]
	judge S9b "a socket directory open to others: refused, daemon keeps serving, server error shown" $? "$o" "$o2"

	# ---- a relative or too-long path is refused ----------------------------------------
	daemon_stop auth
	variant rel "$(sockline run/tdns-auth.sock)"
	o=$(out S10-rel)
	daemon_start auth "$RIG/auth/v-rel.yaml"
	still_serving "$o"; r1=$?
	[ ! -e "$RIG/auth/run/tdns-auth.sock" ]; r2=$?
	o2=$(out S10-rel-status); socket_error_shown "$o2"; r3=$?
	grep -q 'not an absolute path' "$o2" "$LOG/tdns-auth.log"; r4=$?
	[ $r1 = 0 ] && [ $r2 = 0 ] && [ $r3 = 0 ] && [ $r4 = 0 ]
	judge S10a "a relative socket path: refused (\"not an absolute path\"), daemon keeps serving" $? "$o" "$o2"
	f=$RIG/ncli/add-rel.yaml; addfile "$f"
	o=$(out S10-rel-add); ncli_root add-rel config add "$RIG/auth/v-rel.yaml" > "$o"; cat "$f" >> "$o" 2>/dev/null
	if certadd; then
		# #1200: config add needs the socket, which that config cannot have.
		[ "$(rc_of "$o")" != 0 ] && grep -q 'serves no local admin socket' "$o" && ! grep -q 'apiservers' "$f"
		judge S10b "config add as root on that config: refused (no local admin socket), nothing written" $? "$o"
	else
		grep -qi 'not an absolute path' "$o" && ! grep -q 'unix://' "$f"
		judge S10b "config add as root on that config: warns, writes no socket entry" $? "$o"
	fi

	daemon_stop auth
	long="$VDIR/ok/$(printf '%0100d' 0).sock"
	variant long "$(sockline "$long")"
	o=$(out S10-long)
	daemon_start auth "$RIG/auth/v-long.yaml"
	still_serving "$o"; r1=$?
	[ ! -e "$long" ]; r2=$?
	o2=$(out S10-long-status); socket_error_shown "$o2"; r3=$?
	[ $r1 = 0 ] && [ $r2 = 0 ] && [ $r3 = 0 ]
	judge S10c "a socket path over 100 bytes: refused, daemon keeps serving, server error shown" $? "$o" "$o2"

	# ---- no apiserver.addresses: the socket is still served -------------------------------
	daemon_stop auth
	variant noaddr '/^   addresses: .*8991/d'
	o=$(out S11-noaddr)
	if daemon_start auth "$RIG/auth/v-noaddr.yaml"; then
		ncli_root root auth ping > "$o"
	else
		sed -n '/=== .* start .*auth\/v-noaddr/,$p' "$LOG/tdns-auth.stdout" > "$o"
	fi
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o"
	judge S11a "no apiserver.addresses (tdns-auth): root still reaches the daemon on the socket" $? "$o"
	o=$(out S11-notcp); raw_local -k -b empty 127.0.0.1:$AUTH_API /api/v1/ping > "$o" 2>&1
	[ "$(status_of "$o")" = none ]
	judge S11b "...and nothing listens on TCP" $? "$o"
	addfile "$RIG/home/add-user2.yaml" user
	o=$(out S11-add-user); ncli_user home/add-user2 config add "$RIG/auth/v-noaddr.yaml" > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -qi 'only a local admin socket\|run it as root' "$o"
	judge S11c "...config add as non-root: refused, saying only root can use it" $? "$o"
	# The same for tdns-imr, whose config validation and router builder differ.
	daemon_stop imr
	sed '/^   addresses: .*8992/d' "$RIG/imr/tdns-imr.yaml" > "$RIG/imr/v-noaddr.yaml"
	o=$(out S11-imr-noaddr)
	if daemon_start imr "$RIG/imr/v-noaddr.yaml"; then
		ncli_root root imr ping > "$o"
	else
		sed -n '/=== .* start .*imr\/v-noaddr/,$p' "$LOG/tdns-imr.stdout" > "$o"
	fi
	[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o"
	judge S11d "no apiserver.addresses (tdns-imr): root still reaches the daemon on the socket" $? "$o"
	daemon_stop imr

	# ---- stop is admin, and the socket has it -----------------------------------------------
	daemon_stop auth
	daemon_start auth
	o=$(out S12-stop); ncli_root root auth stop > "$o"
	sleep 3
	[ -z "$(pids_of auth)" ]
	judge S12 "root: stop over the socket stops the daemon" $? "$o"
	o2=$(out S12b-gone); ls -l /var/run/tdns/ > "$o2" 2>&1
	[ ! -e "$AUTH_SOCK" ]
	judge S12b "...and the socket file is gone after it" $? "$o2"
	daemon_start auth; daemon_stop auth
	o2=$(out S12c-gone-term); ls -l /var/run/tdns/ > "$o2" 2>&1
	[ ! -e "$AUTH_SOCK" ]
	judge S12c "after SIGTERM the socket file is gone too" $? "$o2"

	# ---- socket-only configs need the key but no certificate -------------------------
	daemon_stop auth; daemon_stop imr
	variant nocert-noaddr '/^   addresses: .*8991/d; /^   certfile: /d; /^   keyfile: /d'
	variant nocert-empty 's|^   addresses: .*8991.*|   addresses:  []|; /^   certfile: /d; /^   keyfile: /d'
	for v in noaddr:S13a empty:S13b; do
		c=$RIG/auth/v-nocert-${v%%:*}.yaml
		o=$(out "${v#*:}-nocert-${v%%:*}")
		if daemon_start auth "$c"; then
			{ grep -n 'addresses\|certfile\|keyfile' "$c"; ncli_root root auth ping; } > "$o" 2>&1
		else
			sed -n "\\|=== .* start $c|,\$p" "$LOG/tdns-auth.stdout" > "$o"
		fi
		[ "$(rc_of "$o")" = 0 ] && grep -q 'pongs:' "$o"
		judge "${v#*:}" "socket-only ($([ "${v%%:*}" = empty ] && echo 'addresses: []' || echo 'no addresses line')), no certfile/keyfile: tdns-auth starts and serves the socket" $? "$o"
		daemon_stop auth
	done
	variant nocert '/^   certfile: /d; /^   keyfile: /d'
	o=$(out S13c-nocert)
	if defcert; then
		# #1182: the daemon writes its default pair instead.
		dc=$RIG/auth/certs/v-nocert-api; rm -f "$dc.crt" "$dc.key"
		if daemon_start auth "$RIG/auth/v-nocert.yaml"; then ls -l "$RIG/auth/certs/" > "$o" 2>&1; [ -s "$dc.crt" ] && [ -s "$dc.key" ]; r=$?; daemon_stop auth
		else sed -n "\\|=== .* start $RIG/auth/v-nocert.yaml|,\$p" "$LOG/tdns-auth.stdout" > "$o"; r=1; fi
		rm -f "$dc.crt" "$dc.key"
		judge S13c "addresses but no certfile/keyfile (#1182): tdns-auth starts and writes its default pair" $r "$o"
	else
		if daemon_start auth "$RIG/auth/v-nocert.yaml"; then r=1; echo "tdns-auth started" > "$o"; daemon_stop auth
		else sed -n "\\|=== .* start $RIG/auth/v-nocert.yaml|,\$p" "$LOG/tdns-auth.stdout" > "$o"; grep -q 'CertFile' "$o"; r=$?; fi
		judge S13c "addresses but no certfile/keyfile: tdns-auth refuses the config" $r "$o"
	fi
	variant nokey-sockonly '/^   addresses: .*8991/d; /^   certfile: /d; /^   keyfile: /d; /^   apikey: /d'
	o=$(out S13d-nokey-sockonly)
	if daemon_start auth "$RIG/auth/v-nokey-sockonly.yaml"; then r=1; echo "tdns-auth started" > "$o"; daemon_stop auth
	else sed -n "\\|=== .* start $RIG/auth/v-nokey-sockonly.yaml|,\$p" "$LOG/tdns-auth.stdout" > "$o"; grep -q 'ApiKey' "$o"; r=$?; fi
	judge S13d "socket-only with no apikey: tdns-auth refuses the config" $r "$o"

	# ---- a socket entry sends no key, whatever its authmethod says --------------------
	daemon_start auth
	f=$RIG/ncli/sockkey.yaml
	printf 'apiservers:\n   - name:        tdns-auth\n     baseurl:     unix://%s\n     authmethod:  X-API-Key\n     config-file: %s\n' \
		"$AUTH_SOCK" "$RIG/auth/tdns-auth.yaml" > "$f"; chmod 0600 "$f"
	o=$(out S14-sockkey)
	{ cat "$f"; ncli_root sockkey auth ping; ncli_root sockkey auth config reload-tsig; } > "$o" 2>&1
	[ "$(grep -c '^RC=0$' "$o")" = 2 ] && grep -q 'pongs:' "$o"
	judge S14 "root: a socket entry with authmethod X-API-Key and no apikey works (ping, reload-tsig)" $? "$o"
	daemon_stop auth

	# ---- config add refuses a TCP entry with no key to send ---------------------------
	variant nokey '/^   apikey: /d'
	if certadd; then
		# #1200: the daemon is stopped, so config add writes the entry with
		# config-file: only, and no key plays a part; non-root is refused.
		f=$RIG/ncli/add-nokey.yaml; addfile "$f"
		o=$(out S15-nokey-root); ncli_root add-nokey config add "$RIG/auth/v-nokey.yaml" > "$o" 2>&1; cat "$f" >> "$o" 2>/dev/null
		[ "$(rc_of "$o")" = 0 ] && grep -q "config-file: *$RIG/auth/v-nokey.yaml" "$f" && ! grep -q 'baseurl' "$f" \
			&& ! grep -qi 'apikey' "$f" && grep -q 'config update tdns-auth --cert' "$o"
		judge S15a "config add as root, daemon stopped, config with no apikey (#1200): the config-file: entry only" $? "$o"
		f=$RIG/ncli/add-nokey-tcp.yaml; addfile "$f"
		o=$(out S15-nokey-tcp); ncli_root add-nokey-tcp config add --tcp "$RIG/auth/v-nokey.yaml" > "$o" 2>&1; cat "$f" >> "$o" 2>/dev/null
		[ "$(rc_of "$o")" = 0 ] && grep -q "config-file: *$RIG/auth/v-nokey.yaml" "$f" && ! grep -q 'baseurl' "$f"
		judge S15b "...with --tcp: the same entry" $? "$o"
		f=$RIG/home/add-nokey.yaml; addfile "$f" user
		o=$(out S15-nokey-user); ncli_user home/add-nokey config add "$RIG/auth/v-nokey.yaml" > "$o" 2>&1
		[ "$(rc_of "$o")" != 0 ] && grep -q 'run it as root' "$o" && ! grep -q 'apiservers' "$f"
		judge S15c "...as a non-root user: refused (run it as root), nothing written" $? "$o"
		rm -f "$RIG/auth/v-nokey-access.yaml" "$RIG/auth/v-nokey-access.yaml.prev" "$RIG/auth/v-nokey.yaml.prev"
	else
		f=$RIG/ncli/add-nokey.yaml; rm -f "$f"
		o=$(out S15-nokey-root); ncli_root add-nokey config add "$RIG/auth/v-nokey.yaml" > "$o" 2>&1
		cat "$f" >> "$o" 2>/dev/null
		if newcli; then
			# #1168: root gets the TCP entry too, so no key is refused for root as well.
			[ "$(rc_of "$o")" != 0 ] && grep -qi 'apikey is not set' "$o" && [ ! -e "$f" ]
			judge S15a "config add as root, daemon config with no apikey: refused, naming apiserver.apikey, nothing written" $? "$o"
		else
			[ "$(rc_of "$o")" = 0 ] && grep -q "baseurl: *unix://$AUTH_SOCK" "$f" && ! grep -qi 'apikey' "$f"
			judge S15a "config add as root, daemon config with no apikey: the socket entry, no key" $? "$o"
		fi
		f=$RIG/ncli/add-nokey-tcp.yaml; rm -f "$f"
		o=$(out S15-nokey-tcp); ncli_root add-nokey-tcp config add --tcp "$RIG/auth/v-nokey.yaml" > "$o" 2>&1
		[ "$(rc_of "$o")" != 0 ] && grep -qi 'apikey is not set' "$o" && [ ! -e "$f" ]
		judge S15b "...with --tcp: refused, naming apiserver.apikey, nothing written" $? "$o"
		f=$RIG/home/add-nokey.yaml; rm -f "$f"
		o=$(out S15-nokey-user); ncli_user home/add-nokey config add "$RIG/auth/v-nokey.yaml" > "$o" 2>&1
		[ "$(rc_of "$o")" != 0 ] && grep -qi 'apikey is not set' "$o" && [ ! -e "$f" ]
		judge S15c "...as a non-root user: refused, naming apiserver.apikey, nothing written" $? "$o"
	fi

	# ---- config check on the socket path and the key ----------------------------------
	long=/var/run/tdns/$(printf '%0100d' 0).sock
	variant chk-sorel "/^   addresses: .*8991/d; $(sockline tdns-auth.sock)"
	variant chk-solong "/^   addresses: .*8991/d; $(sockline "$long")"
	variant chk-addrrel "$(sockline tdns-auth.sock)"
	sed '/^   apikey: /d; /^   addresses: .*8992/d' "$RIG/imr/tdns-imr.yaml" > "$RIG/imr/v-chk-nokey.yaml"
	o=$(out S16a-sorel); ncli_root root auth config check --offline --serverconfig "$RIG/auth/v-chk-sorel.yaml" > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -q 'FAIL *addresses.*not an absolute path' "$o"
	judge S16a "config check: socket-only with a relative socket path FAILs" $? "$o"
	o=$(out S16b-solong); ncli_root root auth config check --offline --serverconfig "$RIG/auth/v-chk-solong.yaml" > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -q 'FAIL *addresses.*bytes' "$o"
	judge S16b "config check: socket-only with a socket path over 100 bytes FAILs" $? "$o"
	o=$(out S16c-addrrel); ncli_root root auth config check --offline --serverconfig "$RIG/auth/v-chk-addrrel.yaml" > "$o" 2>&1
	grep -q 'WARN *socket.*not an absolute path' "$o" && ! grep -q 'FAIL *addresses' "$o"
	judge S16c "config check: with addresses, a relative socket path WARNs" $? "$o"
	o=$(out S16d-nocert); ncli_root root auth config check --offline --serverconfig "$RIG/auth/v-nocert-noaddr.yaml" > "$o" 2>&1
	grep -q 'INFO *cert' "$o" && ! grep -q 'FAIL *cert' "$o"
	judge S16d "config check: socket-only with no certfile/keyfile is not a failure" $? "$o"
	o=$(out S16e-imr-nokey); ncli_root root imr config check --offline --serverconfig "$RIG/imr/v-chk-nokey.yaml" > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -q 'FAIL *apikey' "$o"
	judge S16e "config check (tdns-imr): no apikey FAILs, also with no addresses" $? "$o"

	daemon_stop auth; daemon_stop imr
	rm -rf "$VDIR"
}

# config_add_cert: S7 on a certadd build (#1200, the cert setup design,
# section 4). The seeded daemon config names no access file, so config add is
# first refused with the line to add; the rig then turns the access file on
# as an operator would (the line, an empty file, a reload), and config add
# sets up root's client certificate. The seeded config is put back after.
config_add_cert() {
	cp "$RIG/auth/tdns-auth.yaml" "$RUNDIR/tdns-auth.yaml.seeded"
	A=$RIG/auth/tdns-auth-access.yaml; rm -f "$A" "$A.prev"
	f=$RIG/ncli/add-root.yaml; addfile "$f"; cp "$f" "$RUNDIR/add-root.before"
	o=$(out S7-add-noacc); ncli_root add-root config add "$RIG/auth/tdns-auth.yaml" > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -q "access-file: $A" "$o" && grep -q 'config reload' "$o" \
		&& cmp -s "$f" "$RUNDIR/add-root.before" && cmp -s "$RIG/auth/tdns-auth.yaml" "$RUNDIR/tdns-auth.yaml.seeded"
	judge S7h "config add as root, no access file named: refused with the access-file: line and the reload to run, nothing written" $? "$o"
	sed "s|^#  access-file: .*|   access-file: $A|" "$RUNDIR/tdns-auth.yaml.seeded" > "$RIG/auth/tdns-auth.yaml"
	printf 'keyauth: true\nclients: []\n' > "$A"; chmod 0600 "$A"
	o=$(out S7-reload); ncli_bare "$o" auth config reload --daemon-config "$RIG/auth/tdns-auth.yaml"
	[ "$(rc_of "$o")" = 0 ] || fail S7z "the reload that turns the access file on" "$o"
	o=$(out S7-add-root); ncli_root add-root config add "$RIG/auth/tdns-auth.yaml" > "$o" 2>&1
	o3=$(out S7g-add-root-imr); ncli_root add-root config add "$RIG/imr/tdns-imr.yaml" > "$o3" 2>&1
	cat "$f" >> "$o" 2>/dev/null
	cpin=$(pin_of_cert "$RIG/ncli/root-client.crt")
	[ "$(rc_of "$o")" = 0 ] && grep -q "baseurl: *https://127.0.0.1:$AUTH_API" "$f" && grep -q 'authmethod: *certificate' "$f" \
		&& ! grep -qi 'apikey' "$f" && grep -q 'tlsauth: *pin' "$f" && grep -q "$(pinof daemon)" "$f" \
		&& grep -q "config-file: *$RIG/auth/tdns-auth.yaml" "$f" && [ -n "$cpin" ] && grep -q "$cpin" "$A"
	judge S7a "config add as root (#1200): one certificate entry (pins, config-file:, no key), its pin enrolled by the daemon" $? "$o"
	[ "$(rc_of "$o3")" != 0 ] && ! grep -q ":$IMR_API" "$f"
	judge S7g "...tdns-imr (usetls: false, no access file): refused, no entry" $? "$o3"
	o2=$(out S7-add-root-use); ncli_root add-root auth ping > "$o2"
	[ "$(rc_of "$o2")" = 0 ] && grep -q "pong ($AUTH_SOCK) from" "$o2"
	judge S7b "...and the entry it wrote works (as root, over the socket)" $? "$o2"
	o2=$(out S7f-add-root-tcp); ncli_root add-root --tcp auth ping > "$o2"
	[ "$(rc_of "$o2")" = 0 ] && grep -q 'pong (TLS, read-write, certificate ' "$o2"
	judge S7f "...tdns-ncli --tcp: over TCP with the client certificate, read-write" $? "$o2"
	cp "$f" "$RUNDIR/add-root.after"
	o=$(out S7-add-again); ncli_root add-root config add "$RIG/auth/tdns-auth.yaml" > "$o" 2>&1
	cmp -s "$f" "$RUNDIR/add-root.after" && grep -q 'config update tdns-auth --repin' "$o" && [ "$(grep -c "$cpin" "$A")" = 1 ]
	judge S7c "config add again: the certificate entry is left alone, config update --repin named, the pin not enrolled twice" $? "$o"
	f2=$RIG/ncli/add-tcp.yaml; addfile "$f2"
	o=$(out S7-add-tcp); ncli_root add-tcp config add "$RIG/auth/tdns-auth.yaml" > "$o" 2>&1; cat "$f2" >> "$o" 2>/dev/null
	[ "$(rc_of "$o")" = 0 ] && grep -q 'authmethod: *certificate' "$f2" && [ "$(grep -c "$cpin" "$A")" = 1 ]
	judge S7i "a second CLI config with the same client pair: its own entry, the pin reused (listed once)" $? "$o"
	f3=$RIG/home/add-user.yaml; addfile "$f3" user
	o=$(out S7-add-user); ncli_user home/add-user config add "$RIG/auth/tdns-auth.yaml" > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -q 'run it as root' "$o" && ! grep -q 'apiservers' "$f3"
	judge S7d "config add as a non-root user: refused (run it as root on the daemon's host), nothing written" $? "$o"
	# A stopped daemon: the entry with config-file: only; it reaches the socket
	# once the daemon runs.
	daemon_stop auth
	f4=$RIG/ncli/add-stopped.yaml; addfile "$f4"
	o=$(out S7-add-stopped); ncli_root add-stopped config add "$RIG/auth/tdns-auth.yaml" > "$o" 2>&1; cat "$f4" >> "$o" 2>/dev/null
	[ "$(rc_of "$o")" = 0 ] && grep -q "config-file: *$RIG/auth/tdns-auth.yaml" "$f4" && ! grep -q 'baseurl' "$f4" \
		&& ! grep -qi 'apikey' "$f4" && grep -q 'config update tdns-auth --cert' "$o"
	judge S7s "config add as root, daemon stopped: the config-file: entry only (no address, no key), config update --cert named" $? "$o"
	daemon_start auth || fail S7z "tdns-auth starts on the access-file config" "$LOG/tdns-auth.stdout"
	o2=$(out S7-add-stopped-use); ncli_root add-stopped auth ping > "$o2"
	[ "$(rc_of "$o2")" = 0 ] && grep -q "pong ($AUTH_SOCK) from" "$o2"
	judge S7t "...once the daemon runs, that entry reaches it (as root, over the socket)" $? "$o2"
	certupdate && config_update_cases
	daemon_stop auth
	cp "$RUNDIR/tdns-auth.yaml.seeded" "$RIG/auth/tdns-auth.yaml"; rm -f "$A" "$A.prev" "$RIG/auth/tdns-auth.yaml.prev"
	daemon_start auth || fail S7z "tdns-auth starts again on the seeded config" "$LOG/tdns-auth.stdout"
}

# config_update_cases: U1-U7 on a build with #1202's config update (the cert
# setup design, section 5), from config_add_cert while tdns-auth runs the
# access-file config ($A) and root's client pin is enrolled. $f is root's
# certificate entry from S7a, $f4 the stopped daemon's config-file: entry.
config_update_cases() {
	fk=$RIG/ncli/upd-key.yaml
	{ printf 'client:\n   cert:          %s\n   key:           %s\n' "$RIG/ncli/root-client.crt" "$RIG/ncli/root-client.key"
	  printf '# a comment config update keeps\napiservers:\n   - name:        tdns-auth\n     baseurl:     https://127.0.0.1:%s/api/v1\n     apikey:      cli-access-rig-test-key\n     authmethod:  X-API-Key\n     rootca:      %s\n     config-file: %s\n' \
		$AUTH_API "$CERTS/ca.crt" "$RIG/auth/tdns-auth.yaml"; } > "$fk"
	chmod 0600 "$fk"; cp "$fk" "$RUNDIR/upd-key.before"
	o=$(out U1-cert); ncli_root upd-key config update tdns-auth --cert > "$o" 2>&1; diff "$RUNDIR/upd-key.before" "$fk" >> "$o"
	o2=$(out U1-ping); ncli_root upd-key --tcp auth ping > "$o2"
	[ "$(rc_of "$o")" = 0 ] && grep -q 'authmethod: *certificate' "$fk" && grep -q 'tlsauth: *pin' "$fk" && grep -q "$(pinof daemon)" "$fk" \
		&& ! grep -qi 'apikey' "$fk" && ! grep -q 'rootca' "$fk" && grep -q '^# a comment config update keeps$' "$fk" \
		&& grep -q "config-file: *$RIG/auth/tdns-auth.yaml" "$fk" && grep -q 'pong (TLS, read-write, certificate ' "$o2"
	judge U1 "config update --cert on a key entry (rootca:): a certificate entry in place (pins, no key, no rootca:), the comment kept; it works over TCP" $? "$o" "$o2"
	o=$(out U2-cert); ncli_root add-stopped config update tdns-auth --cert > "$o" 2>&1; cat "$f4" >> "$o" 2>/dev/null
	o2=$(out U2-ping); ncli_root add-stopped --tcp auth ping > "$o2"
	[ "$(rc_of "$o")" = 0 ] && grep -q "baseurl: *https://127.0.0.1:$AUTH_API" "$f4" && grep -q 'authmethod: *certificate' "$f4" \
		&& grep -q "$(pinof daemon)" "$f4" && grep -q 'pong (TLS, read-write, certificate ' "$o2"
	judge U2 "config update --cert on the stopped daemon's config-file: entry, once it runs: address, pins and certificate filled in; works over TCP" $? "$o" "$o2"
	cp "$f" "$RUNDIR/add-root.u3"
	o=$(out U3-again); ncli_root add-root config update tdns-auth --cert > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && cmp -s "$f" "$RUNDIR/add-root.u3"
	judge U3 "config update --cert on an entry already on a certificate: refused, the entry unchanged" $? "$o"
	fd=$RIG/ncli/upd-dry.yaml; cp "$RUNDIR/upd-key.before" "$fd"; chmod 0600 "$fd"
	o=$(out U4-dry); ncli_root upd-dry config update tdns-auth --cert --dry-run > "$o" 2>&1
	[ "$(rc_of "$o")" = 0 ] && cmp -s "$fd" "$RUNDIR/upd-key.before"
	judge U4 "config update --cert --dry-run: nothing written" $? "$o"
	fn=$RIG/ncli/upd-nocf.yaml; grep -v 'config-file:' "$RUNDIR/upd-key.before" > "$fn"; chmod 0600 "$fn"; cp "$fn" "$RUNDIR/upd-nocf.before"
	o=$(out U5-nocf); ncli_root upd-nocf config update tdns-auth --cert > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && cmp -s "$fn" "$RUNDIR/upd-nocf.before"; r1=$?
	o2=$(out U5-dc); ncli_root upd-nocf config update tdns-auth --cert --daemon-config "$RIG/auth/tdns-auth.yaml" > "$o2" 2>&1; cat "$fn" >> "$o2"
	[ "$(rc_of "$o2")" = 0 ] && grep -q "config-file: *$RIG/auth/tdns-auth.yaml" "$fn" && grep -q 'authmethod: *certificate' "$fn"; r2=$?
	[ $r1 = 0 ] && [ $r2 = 0 ]
	judge U5 "config update on an entry with no config-file:: refused; with --daemon-config: done, and the config-file: line written" $? "$o" "$o2"
	fu=$RIG/home/upd-user.yaml; cp "$RUNDIR/upd-key.before" "$fu"; chown "$RIGUSER" "$fu"; chmod 0600 "$fu"
	o=$(out U6-user); ncli_user home/upd-user config update tdns-auth --cert > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && cmp -s "$fu" "$RUNDIR/upd-key.before"
	judge U6 "config update as a non-root user: refused, the entry unchanged" $? "$o"
	# The daemon's pair rotates (the rig's "other" server certificate).
	daemon_stop auth
	sed -e "s|^   certfile: .*|   certfile:   $CERTS/other.crt|" -e "s|^   keyfile: .*|   keyfile:    $CERTS/other.key|" "$RIG/auth/tdns-auth.yaml" > "$RUNDIR/rot.yaml"
	cat "$RUNDIR/rot.yaml" > "$RIG/auth/tdns-auth.yaml"
	daemon_start auth || fail U7z "tdns-auth starts on the other server certificate" "$LOG/tdns-auth.stdout"
	o=$(out U7-stale); ncli_root add-root --tcp auth ping > "$o" 2>&1
	[ "$(rc_of "$o")" != 0 ] && grep -q 'which is not one of the 1 pinned for this entry' "$o" && ! grep -q 'pongs:' "$o"
	judge U7a "the daemon's pair rotated: a TCP request with the old pin is refused (not one of the entry's pins)" $? "$o"
	o=$(out U7-repin); ncli_root add-root config update tdns-auth --repin > "$o" 2>&1; cat "$f" >> "$o" 2>/dev/null
	o2=$(out U7-ping); ncli_root add-root --tcp auth ping > "$o2"
	[ "$(rc_of "$o")" = 0 ] && grep -q "$(pinof other)" "$f" && ! grep -q "$(pinof daemon)" "$f" && grep -q 'pong (TLS, read-write, certificate ' "$o2"
	judge U7b "...config update --repin replaces the pins (the old one dropped); the entry works over TCP" $? "$o" "$o2"
	cp "$f" "$RUNDIR/add-root.u7"
	o=$(out U7-again); ncli_root add-root config update tdns-auth --repin > "$o" 2>&1
	[ "$(rc_of "$o")" = 0 ] && grep -q 'already current' "$o" && cmp -s "$f" "$RUNDIR/add-root.u7"
	judge U7c "...--repin again: already current, nothing written" $? "$o"
}
