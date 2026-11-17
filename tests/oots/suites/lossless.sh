# Suite lossless: a tdns secondary re-serves an oots value byte for byte, so the
# primary's RRSIG still validates. Scenario C1.
#
# Parties
#   cs-pri        127.0.0.40  AUTH_PUB: hidden primary for cs.test., which it
#                             signs (online-signing; its DS is in the rig root).
#                             Also primary for csu.test., unsigned, on 127.0.0.42.
#   ns.cs.test    127.0.0.41  AUTH_SEC: secondary for cs.test. from cs-pri, and
#                             the only nameserver the delegation names.
#   the resolver  127.0.0.100 IMR, validating from the rig root's anchor.
#   dog           DOG, the observer. It must decode every value itself, so it
#                 has to be a lossless build (dns#6 or later).
#
# cs.test. holds five _dns SVCB RRsets, written in RFC 3597 form so the bytes
# are exact whatever the zone parser's text rules:
#   a  do53:100,dot:50                       today's tokens
#   b  do53:100,dot:50,udp:100,tcp:30,xyz:9  known and unknown tokens
#   c  tcp:30                                only unknown tokens
#   d  odd identifiers: a,b  x:y  back\slash  "sp ace"  \000\127\255  tcp
#   e  dot:150,doq:20                        a weight octet above 100
#
# Done: the secondary transfers the zone; dog asks both servers; the resolver
# resolves each RRset through the secondary.
#
# Observed: the secondary holds the primary's serial; each RRset reads the same
# from both servers in dog; the resolver answers each with AD.
#
# The byte check is the AD: the RRSIG is the primary's, and the resolver reaches
# cs.test. only through the secondary, so AD means the secondary served the
# primary's bytes. dog's text is a reading, and two different values could
# read the same, so it is a check on dog's view only. A dog that cannot read c
# (one before dns#6) makes c a SKIP; every other name is still checked, AD
# included.
#
# Negative: an unsigned name (csu.test.) must come back without AD, which shows
# AD is not simply always on. Red on base: a secondary on main drops tokens or
# fails the transfer, so AD is lost; a resolver on main cannot read c at all.

suite_lossless() {
	ZDIR="$WORK/cs-pri/zones"; mkdir -p "$ZDIR"
	{ zonefile cs.test. "ns.cs.test.=127.0.0.41" </dev/null
	  _svcb_generic _dns.a "do53=100 dot=50"
	  _svcb_generic _dns.b "do53=100 dot=50 udp=100 tcp=30 xyz=9"
	  _svcb_generic _dns.c "tcp=30"
	  _svcb_generic _dns.d 'a,b=10 x:y=20 back\\slash=30 sp\x20ace=40 \x00\x7f\xff=50 tcp=60'
	  _svcb_generic _dns.e "dot=150 doq=20"
	} > "$ZDIR/cs.test.zone"
	zonefile csu.test. "ns.csu.test.=127.0.0.42" > "$ZDIR/csu.test.zone" <<EOF
www IN TXT "unsigned"
EOF
	{ y_service cs-pri "ns.cs.test."
	  y_listeners "127.0.0.40 127.0.0.42"
	  y_common cs-pri 127.0.0.40
	  y_zones; y_primary cs.test. online-signing 127.0.0.41; y_primary csu.test.
	} | auth_up cs-pri "$AUTH_PUB" 127.0.0.40 cs.test. || { fail "lossless: the primary did not start"; return; }

	ZDIR="$WORK/cs-sec/zones"; mkdir -p "$ZDIR"
	{ y_service cs-sec "ns.cs.test."
	  y_listeners 127.0.0.41
	  y_common cs-sec 127.0.0.41
	  y_zones; y_secondary cs.test. 127.0.0.40
	} | auth_up cs-sec "$AUTH_SEC" 127.0.0.41 cs.test. || note "the secondary does not answer cs.test. SOA yet"

	serial() { dogq "$1" cs.test. SOA | awk '$4 == "SOA" { print $7; exit }'; }
	same_serial() { s1=$(serial 127.0.0.40); [ -n "$s1" ] && [ "$s1" = "$(serial 127.0.0.41)" ]; }
	wait_for 20 same_serial
	check C1 "the secondary holds the primary's serial ($(serial 127.0.0.40))" same_serial

	imr_up || { fail "lossless: the resolver did not start"; return; }
	for x in a b c d e; do
		p=$(rdata 127.0.0.40 "_dns.$x.cs.test." SVCB)
		if [ "$x" = c ] && [ -z "$p" ]; then
			skip "C1 _dns.c: dog cannot read the only-unknown value from the primary; DOG must be a lossless build"
			continue
		fi
		s=$(rdata 127.0.0.41 "_dns.$x.cs.test." SVCB)
		note "$x primary:   $p"
		[ "$s" = "$p" ] || note "$x secondary: $s"
		check C1 "_dns.$x: dog reads the same from the secondary as from the primary" [ -n "$p" -a "$s" = "$p" ]
		check C1 "_dns.$x: the resolver validates it through the secondary (AD): the primary's bytes" _ad "_dns.$x.cs.test." SVCB
	done
	if _ad www.csu.test. TXT; then
		fail "C1 an unsigned name came back with AD: the AD check proves nothing"
	else
		pass "C1 an unsigned name comes back without AD"
	fi
}

# A NOERROR answer with the AD flag, from the resolver.
_ad() { # name type
	dogq 127.0.0.100 "$1" "$2" +dnssec | awk '
		/status:/ { if ($0 ~ /status: NOERROR/) ok = 1 }
		/^;; flags:/ { if ($0 ~ /[ :]ad[ ;]/) ad = 1 }
		END { exit !(ok && ad) }'
}

# One SVCB RR, priority 1, target ".", one oots SvcParam, in RFC 3597 form.
# Entries are id=weight; an id may carry \\ and \xHH escapes (python bytes).
_svcb_generic() { # owner "id=weight ..."
	python3 -I -c '
import sys
owner, spec = sys.argv[1], sys.argv[2]
val = b""
for item in spec.split(" "):
    ident, _, w = item.rpartition("=")
    ident = ident.encode("latin-1").decode("unicode_escape").encode("latin-1")
    val += bytes([len(ident)]) + ident + bytes([int(w)])
rd = (1).to_bytes(2, "big") + b"\x00" + (12).to_bytes(2, "big") + len(val).to_bytes(2, "big") + val
print("%s IN TYPE64 \\# %d %s" % (owner, len(rd), rd.hex()))
' "$1" "$2"
}
