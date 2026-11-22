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
	[ "$(rc_of "$o")" != 0 ] && grep -q 'does not verify the daemon' "$o" && ! grep -q 'pongs:' "$o"
	judge P1e "an https entry that verifies nothing: tdns-ncli refuses it" $? "$o"

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
	grep -q 'authenticated as operator (read-write) by certificate' "$o"
	judge P2c "authmethod: certificate: \"authenticated as operator (read-write) by certificate\"" $? "$o"
	o=$(out P2-certkey); ncli_remote cert authkey ping > "$o" 2>&1
	grep -q 'authenticated as apikey (read-write) by api key' "$o"
	judge P2d "an entry without authmethod: certificate does not present it (\"by api key\")" $? "$o"
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
	grep -q 'authenticated as operator (read-only) by certificate' "$o2"
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
	f=$RIG/ncli/add-pin.yaml; rm -f "$f"
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

	daemon_stop auth; daemon_stop imr
}
