# XoT interoperability testing: tdns vs NSD, BIND9 and Knot DNS

**Date:** 2026-08-25
**Scope:** RFC 9103 XFR-over-TLS between tdns and the three other open-source
authoritative implementations, in both transfer roles, over three certificate
authentication mechanisms.
**Testbed:** local (macOS), all daemons on 127.0.0.1 on distinct ports.
**Companion docs:** `2026-07-21-xot-operations.md`,
`2026-07-21-DONE-peers-xfr-auth-design.md`, `2026-07-21-DONE-pkix-cert-tooling-design.md`.
**Status:** complete for PKIX and SPKI-pin in both transfer roles. DANE/TLSA is
scoped but deliberately unrun (§9); mTLS is untouched (§7).

---

## 1. Result summary

| Test | Result |
|---|---|
| tdns-auth primary → NSD / BIND9 / Knot secondary, PKIX | 3/3 pass, content identical |
| NSD / BIND9 / Knot primary → tdns-agent secondary, PKIX | 3/3 pass, content identical |
| NSD / BIND9 / Knot primary → tdns-agent secondary, SPKI pin | 3/3 pass |
| Negative tests (bad hostname / bad CA / bad pin), all four implementations | 7/7 correctly refused |
| Update propagation (serial bump → NOTIFY → re-transfer), both directions | 6/6 pass |
| **Knot as secondary of tdns, steady state** | **every second transfer fails — see §5** |
| DANE / TLSA | reserved, not yet tested — see §9 |
| mTLS (client-certificate authentication) | not yet tested — see §7 |

Two findings came out of it: a blocking one (§5) and a behavioural one (§6).

## 2. Versions

| Component | Version |
|---|---|
| tdns | v0.8-main-milestone-3-pq-registry-668-gd61cfc74 (Go 1.26.1) |
| NSD | 4.13.0 (OpenSSL 3.x) |
| BIND | 9.20.20 (OpenSSL 3.6.2) |
| Knot DNS | 3.5.2 (GnuTLS) |

tdns-agent refuses primary zones by design (`v2/parseconfig.go:1035`) and
refuses ordinary queries in agent mode (`v2/defaultqueryhandlers.go:137`), so
the primary role is played by **tdns-auth** and the secondary role by
**tdns-agent**. Both daemons share the secondary pull code.

## 3. Testbed layout

All daemons bind 127.0.0.1. Loopback aliases and port 53 need root, so the
servers are separated by port instead of by address.

| Daemon | Do53 | DoT | Role |
|---|---|---|---|
| tdns-auth | 5301 | 5401 | primary for `a.xot.test`, `neg1-3.xot.test` |
| tdns-agent | 5302 | 5402 | secondary for `b-{nsd,bind,knot}.xot.test` |
| NSD | 5303 | 5403 | secondary for `a.`, primary for `b-nsd.` |
| BIND9 | 5304 | 5404 | secondary for `a.`, primary for `b-bind.` |
| Knot | 5305 | 5405 | secondary for `a.`, primary for `b-knot.` |

PKI: one CA and one Ed25519 leaf per daemon, all issued with `tdns-cli cert`
(`cert ca`, then `cert leaf --client --emit-pin --emit-tlsa`). Each leaf
carries a DNS SAN (`ns-<impl>.xot.test`) and the IP SAN 127.0.0.1, so both
name-based and IP-literal verification are exercisable.

Ed25519 leaves were accepted by all four implementations; no key-algorithm
fallback was needed.

## 3.1 Configuration — the XoT parts

Verbatim from the running testbed, reduced to the TLS/transfer-relevant lines.
`$W` is the testbed root. Every `neg*` entry is a deliberate fault used for the
negative tests in §4.3.

### tdns-auth (primary, serves XoT)

Serving XoT needs no transfer-specific TLS config — a DoT listener plus the
ordinary `downstreams:` ACL is the whole of it. `ports.dot` moves the DoT
listener off 853; the Do53 port comes from `addresses`.

```yaml
dnsengine:
   addresses:  [ 127.0.0.1:5301 ]
   transports: [ do53, dot ]
   ports:
      dot:     [ "5401" ]
   certfile:   $W/certs/ns-tdnsauth.xot.test.crt
   keyfile:    $W/certs/ns-tdnsauth.xot.test.key

zones:
   - name:      a.xot.test.
     type:      primary
     zonefile:  $W/zones/a.xot.test.zone
     store:     map
     notify:                          # NOTIFY goes over Do53
        - addr: "127.0.0.1:5303"      # NSD
          key:  NOKEY
        - addr: "127.0.0.1:5304"      # BIND9
          key:  NOKEY
        - addr: "127.0.0.1:5305"      # Knot
          key:  NOKEY
     downstreams:                     # who may transfer FROM us
        - prefix: "127.0.0.1/32"
          key:    NOKEY
        - prefix: "::1/128"
          key:    NOKEY
```

### tdns-agent (secondary, verifies the primary's certificate)

Pin mode as run in §4.2; the `pins:` value is the output of
`tdns-cli cert pin <cert>`. Swapping `tls-auth: pin` + `pins:` for
`tls-auth: pkix` + `ca-file:` is the whole difference between the two passes —
`tls-name` is needed either way (it is the SNI, and under PKIX the name that
must match).

```yaml
zones:
   - name:      b-nsd.xot.test.
     type:      secondary
     zonefile:  $W/tdns-agent/zones/b-nsd.xot.test.zone
     store:     map
     upstreams:
        - addr:      "127.0.0.1:5403"
          key:       NOKEY
          transport: dot
          tls-auth:  pin
          tls-name:  ns-nsd.xot.test
          pins:
             - "hGKHjFqYgbDVxi+gqKtHD18RN8Gq0WN/0w6haxazcdg="
     allow-notify:
        - prefix: "127.0.0.1/32"
          key:    NOKEY
     downstreams:                     # only so the zone can be AXFR'd out for the diff
        - prefix: "127.0.0.1/32"
          key:    NOKEY

   # …identical blocks for b-bind (:5404, ns-bind.xot.test,
   #   pin /Yc1lxMUWkk/h0iEj0eRdY/ame1PWQ3VnUBQiIKSCY4=)
   #   and b-knot (:5405, ns-knot.xot.test,
   #   pin DvLO3Hsps1YtcgizgH2I+hHSPF3BsIy6trtdoLP4TNs=)

   # NEGATIVE 1 — PKIX against the right CA, wrong expected name
   - name:      neg1.xot.test.
     type:      secondary
     store:     map
     upstreams:
        - addr:      "127.0.0.1:5401"
          key:       NOKEY
          transport: dot
          tls-auth:  pkix
          tls-name:  wrong.xot.test
          ca-file:   $W/ca/xot-ca.crt

   # NEGATIVE 2 — right name, CA that signed nothing here
   - name:      neg2.xot.test.
     type:      secondary
     store:     map
     upstreams:
        - addr:      "127.0.0.1:5401"
          key:       NOKEY
          transport: dot
          tls-auth:  pkix
          tls-name:  ns-tdnsauth.xot.test
          ca-file:   $W/ca/bogus-ca.crt

   # NEGATIVE 3 — pin that matches no certificate
   - name:      neg3.xot.test.
     type:      secondary
     store:     map
     upstreams:
        - addr:      "127.0.0.1:5401"
          key:       NOKEY
          transport: dot
          tls-auth:  pin
          tls-name:  ns-tdnsauth.xot.test
          pins:
             - "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

### NSD 4.13

The CA bundle is **server-global** (`tls-cert-bundle`), not per peer; a
`tls-auth:` clause carries only the expected name. Serving DoT requires an
`ip-address:` whose port equals `tls-port`.

```
server:
	ip-address:	127.0.0.1@5303          # Do53
	ip-address:	127.0.0.1@5403          # DoT — port must match tls-port
	# --- serve XoT ---
	tls-port:	5403
	tls-service-key: "$W/certs/ns-nsd.xot.test.key"
	tls-service-pem: "$W/certs/ns-nsd.xot.test.crt"
	# --- CA used to verify peers, in BOTH roles ---
	tls-cert-bundle: "$W/ca/xot-ca.crt"

# How we authenticate tdns-auth's certificate when we pull from it
tls-auth:
	name:		"tdnsauth"
	auth-domain-name: "ns-tdnsauth.xot.test"

# NEGATIVE: wrong authentication domain name
tls-auth:
	name:		"badname"
	auth-domain-name: "wrong.xot.test"

# Direction A: NSD is SECONDARY of tdns-auth over XoT
zone:
	name:		"a.xot.test"
	zonefile:	"a.xot.test.zone"
	request-xfr:	127.0.0.1@5401 NOKEY tdnsauth   # trailing name = tls-auth clause
	allow-notify:	127.0.0.1 NOKEY
	provide-xfr:	127.0.0.1 NOKEY

# Direction B: NSD is PRIMARY, tdns-agent pulls from it
zone:
	name:		"b-nsd.xot.test"
	zonefile:	"$W/zones/b-nsd.xot.test.zone"
	provide-xfr:	127.0.0.1 NOKEY
	notify:		127.0.0.1@5302 NOKEY

# NEGATIVE
zone:
	name:		"neg1.xot.test"
	zonefile:	"neg1.xot.test.zone"
	request-xfr:	127.0.0.1@5401 NOKEY badname
```

### BIND 9.20

A `tls` statement serves both purposes: with `ca-file`/`remote-hostname` it is
outbound verification material, with `cert-file`/`key-file` it is the server
identity for `listen-on … tls`.

```
options {
	listen-on port 5304 { 127.0.0.1; };
	listen-on port 5404 tls bind-server-tls { 127.0.0.1; };
	listen-on-v6 { none; };
};

// How we verify tdns-auth's certificate (PKIX)
tls tdnsauth-tls {
	ca-file "$W/ca/xot-ca.crt";
	remote-hostname "ns-tdnsauth.xot.test";
};

// NEGATIVE: right CA, wrong expected hostname
tls badname-tls {
	ca-file "$W/ca/xot-ca.crt";
	remote-hostname "wrong.xot.test";
};

// Our own certificate, for serving XoT
tls bind-server-tls {
	cert-file "$W/certs/ns-bind.xot.test.crt";
	key-file "$W/certs/ns-bind.xot.test.key";
};

// Direction A: BIND9 is SECONDARY of tdns-auth over XoT
zone "a.xot.test" {
	type secondary;
	file "a.xot.test.db";
	primaries { 127.0.0.1 port 5401 tls tdnsauth-tls; };
	allow-transfer { 127.0.0.1; };
};

// Direction B: BIND9 is PRIMARY, tdns-agent pulls from it
zone "b-bind.xot.test" {
	type primary;
	file "$W/zones/b-bind.xot.test.zone";
	allow-transfer { 127.0.0.1; };
	also-notify { 127.0.0.1 port 5302; };
};

// NEGATIVE
zone "neg1.xot.test" {
	type secondary;
	file "neg1.xot.test.db";
	primaries { 127.0.0.1 port 5401 tls badname-tls; };
};
```

### Knot DNS 3.5.2

Per-remote verification: `cert-hostname` (PKIX, against the server-global
`ca-file`) or `cert-key` (SPKI pin) — the only non-tdns implementation here
that pins. An incoming NOTIFY needs an ACL with `action: notify`; a
`transfer`-only ACL silently drops it (`ACL, denied, action notify`).

```yaml
server:
    rundir: "/tmp/xot/run/knot"      # short path: sun_path caps near 104 bytes
    listen: 127.0.0.1@5305
    listen-tls: 127.0.0.1@5405
    cert-file: "$W/certs/ns-knot.xot.test.crt"
    key-file: "$W/certs/ns-knot.xot.test.key"
    ca-file: "$W/ca/xot-ca.crt"      # used for cert-hostname verification

remote:
  # PKIX: ca-file (above) + expected name
  - id: tdnsauth
    address: 127.0.0.1@5401
    tls: on
    cert-hostname: [ "ns-tdnsauth.xot.test" ]

  # NEGATIVE: wrong hostname
  - id: tdnsauth-badname
    address: 127.0.0.1@5401
    tls: on
    cert-hostname: [ "wrong.xot.test" ]

  # NEGATIVE: wrong SPKI pin
  - id: tdnsauth-badpin
    address: 127.0.0.1@5401
    tls: on
    cert-key: [ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ]

  # CONTROL for §5: the same Knot pulling from NSD's DoT listener
  - id: nsdprimary
    address: 127.0.0.1@5403
    tls: on
    cert-hostname: [ "ns-nsd.xot.test" ]

  - id: tdnsagent
    address: 127.0.0.1@5302

acl:
  - id: xfr-local
    address: 127.0.0.1
    action: [ transfer, notify ]     # notify is NOT implied by transfer

zone:
  # Direction A: Knot is SECONDARY of tdns-auth over XoT
  - domain: a.xot.test.
    master: tdnsauth
    storage: "$W/knot/zones"
    file: "a.xot.test.zone"
    zonefile-sync: 0
    acl: xfr-local

  # Direction B: Knot is PRIMARY, tdns-agent pulls from it
  - domain: b-knot.xot.test.
    file: "$W/zones/b-knot.xot.test.zone"
    acl: xfr-local
    notify: tdnsagent

  # NEGATIVEs
  - domain: neg1.xot.test.
    master: tdnsauth-badname
    storage: "$W/knot/zones"
    file: "neg1.xot.test.zone"

  - domain: neg2.xot.test.
    master: tdnsauth-badpin
    storage: "$W/knot/zones"
    file: "neg2.xot.test.zone"

  # CONTROL for §5: Knot as secondary of NSD over XoT
  - domain: b-nsd.xot.test.
    master: nsdprimary
    storage: "$W/knot/zones"
    file: "b-nsd-via-knot.zone"
```

## 4. What passed

### 4.1 Certificate mechanisms per implementation

Establishing the matrix first, because it decides what is testable:

| Implementation | Verifying a peer's cert | Config surface |
|---|---|---|
| tdns | PKIX, SPKI pin, DANE | `tls-auth: pkix\|pin\|dane`, `ca-file`, `pins`, `tls-name` |
| NSD | PKIX | `tls-auth:` clause (`auth-domain-name`) + global `tls-cert-bundle` |
| BIND9 | PKIX | `tls` statement (`ca-file`, `remote-hostname`) |
| Knot | PKIX, SPKI pin | `remote.cert-hostname` + `ca-file`, `remote.cert-key` |

PKIX is the only mechanism all four share; pinning is shared by tdns and Knot;
DANE is tdns-only — none of the other three consults a TLSA record to
authenticate a transfer peer, though all three parse and serve the record type
as zone data. The survey behind that claim is in §9.

`tdns-cli cert leaf --emit-pin` and Knot's own startup line
(`QUIC/TLS, certificate public key …`) computed **the same SPKI pin** for the
same certificate, so the two implementations agree on pin construction.

### 4.2 Transfers

Zone content was compared by AXFR from every server, normalised and diffed
against the source. All six combinations were byte-identical (8 RRs for
`a.xot.test`, 5 RRs for each `b-*` zone).

NSD's log states the authentication explicitly, which is useful confirmation
that TLS — not a silent Do53 fallback — carried the transfer:

```
zone a.xot.test. received update to serial 2026082505 … from 127.0.0.1@5401
TLS authenticated with domain ns-tdnsauth.xot.test cert-serial:98F850…
cert-algo:ED25519 tls-version:TLSv1.3
```

### 4.3 Negative tests

Each secondary was additionally configured to pull a zone with deliberately
wrong credentials. All refused, with accurate diagnostics:

| Side | Fault | Reported as |
|---|---|---|
| tdns-agent | wrong hostname | `certificate is valid for ns-tdnsauth.xot.test, not wrong.xot.test` |
| tdns-agent | wrong CA | `certificate signed by unknown authority` |
| tdns-agent | wrong pin | `peer SPKI digest … matches none of the 1 configured pin(s)` |
| NSD | wrong hostname | `TLS verify failed - (62) depth: 0 error: hostname mismatch` |
| BIND9 | wrong hostname | `TLS peer certificate verification failed` |
| Knot | wrong hostname | `refresh … failed (invalid certificate)` |
| Knot | wrong pin | `refresh … failed (invalid certificate)` |

The positive zones kept transferring throughout, so these are genuine
per-zone refusals rather than a broken listener.

## 5. FINDING 1 — tdns cannot reliably serve XoT to Knot DNS

**Symptom.** With Knot as a secondary of tdns-auth, *every second* transfer
attempt fails:

```
[a.xot.test.] refresh, remote 127.0.0.1@5401 TLS, remote serial 2026082505, zone is up-to-date
[a.xot.test.] refresh, remote tdnsauth, address 127.0.0.1@5401, failed (handshake failed)
[a.xot.test.] refresh, remote 127.0.0.1@5401 TLS, remote serial 2026082505, zone is up-to-date
[a.xot.test.] refresh, remote tdnsauth, address 127.0.0.1@5401, failed (handshake failed)
```

The alternation is exact and independent of timing (reproduced with refreshes
6 seconds apart), so it is neither a concurrency nor a rate effect. tdns logs
nothing at all for the failed attempts.

**Cause.** Knot uses TLS 1.3 **0-RTT early data** on resumed connections. Go's
TLS server does not accept early data outside QUIC and, rather than ignoring
the extension, aborts the handshake:

```go
// crypto/tls/handshake_server_tls13.go:165
} else if hs.clientHello.earlyData {
        c.sendAlert(alertUnsupportedExtension)
        return errors.New("tls: client sent unexpected early data")
}
```

Proven directly with GnuTLS, the same TLS stack Knot uses:

```
$ gnutls-cli --resume --earlydata=… --port=5401 127.0.0.1     # tdns-auth
*** Received alert [110]: An unsupported extension was sent   # = unsupported_extension
$ gnutls-cli --resume --earlydata=… --port=5403 127.0.0.1     # NSD
*** This is a resumed session
```

Alert 110 is exactly the alert Go emits above. The control case is equally
clear: Knot as a secondary of **NSD** succeeds 4/4 and logs the transport as
`TLS/0-RTT`, i.e. early data accepted.

The alternation follows from this: connection 1 is a full handshake and
succeeds, Go issues a session ticket, connection 2 resumes with early data and
is killed, Knot discards the ticket, connection 3 is a full handshake again.

**Whose bug.** Go issues session tickets that do **not** advertise
`max_early_data_size` (it is set only for QUIC,
`handshake_server_tls13.go:1015`). Under RFC 8446 §4.2.10 a client must not
send early data with such a ticket, so Knot is at fault. tdns is nevertheless
the party that breaks, and cannot fix it in Knot.

**Candidate mitigation, untested.** Setting `SessionTicketsDisabled: true` in
`ServerTLSConfigForDoT` (`v2/xot.go:299`, shared by the auth and agent
listeners) would stop tdns from issuing tickets at all, so
Knot would never attempt resumption and every connection would be a full
handshake — which succeeds today, as the alternating pattern shows. The cost is
a full handshake per transfer, which for zone transfer is negligible. This was
reasoned from the evidence, not measured; it needs a build and a rerun.

There is precedent for exposing it as an operator knob rather than hardcoding
it: BIND 9.20's `tls` statement carries `session-tickets <boolean>`.

**The failure is one-directional, and structurally so.** It needs a client
that offers 0-RTT talking to a Go TLS server, so it appears only with Knot
*downstream* of tdns. tdns as the client cannot produce it:

- tdns never sets `ClientSessionCache` on its XoT client config
  (`v2/xot.go:182`; the field appears nowhere in `v2/`), and Go's client only
  attempts resumption when that cache is non-nil
  (`crypto/tls/handshake_client.go:354`). Every outbound XoT connection tdns
  makes is therefore a full handshake.
- Even with a cache, Go's client marks a session as early-data-capable only
  for QUIC (`handshake_client_tls13.go:875`), so it would never offer
  `early_data` over DoT.

Confirmed empirically: four consecutive tdns-agent pulls from Knot, driven by
four serial bumps, all succeeded (`transport=dot`, "No errors", serials
2026082503 → 2026082506) with no alternation.

Operationally that means: **a tdns primary with Knot secondaries is affected; a
tdns secondary of a Knot primary is not.**

Knot's ClientHello was captured directly to confirm the first half of this
claim rather than infer it; see Appendix A.

## 6. FINDING 2 — published serial is the zone file's serial plus one

After editing a primary zone file and sending SIGHUP, tdns-auth publishes a
serial one higher than the file's:

```
the zone file has CHANGED since tdns last read or wrote it
  recorded_serial=2026082502 file_serial=2026082504
…
zone updated via refresh   serial=2026082505
```

This is intended: §8 "Serial floor" of
`2026-08-17-zonefile-journal-reconciliation.md` requires the published serial
to be strictly newer than both the highest previously served serial **and the
new file's serial**. It is recorded here only because it surprises operators
coming from BIND/NSD/Knot, where the served serial equals the file's. No
secondary had any difficulty with it — all three followed the increase.

## 7. Not covered

- **DANE / TLSA.** Not attempted here: this testbed is the wrong shape for it.
  Scoped for a later session in §9.
  The lookup goes strictly through the built-in IMR (`v2/xot.go:353`) with no
  forwarder fallback, so the IMR must iteratively resolve `_853._tcp.<name>`
  and DNSSEC-validate the answer. On a Mac on a private network that means
  synthesising a chain locally, and stub auth servers are addressed as bare IPs
  on port 53 (`AuthServer.Addrs`, port supplied by `core.DNSClient`) — port 53
  and loopback aliases both need root here. (`imrengine.stubs` itself is no
  longer the obstacle: the resolution failure written up in
  `2026-08-11-imr-stub-resolution-broken.md` was fixed by 13f29229, whose
  Status line is now stale.) The natural venue is a server with real signed
  zones on real public addresses.
  Worth noting that DANE needs no support from the peer — the TLSA record
  merely has to exist — so tdns can DANE-validate an NSD, BIND9 or Knot server
  certificate. That is a real interop case and still untested.
- **mTLS / client-certificate authentication.** The other half of the
  mechanism claim: tdns `downstream-auth:` + `peers.tls-identity`, NSD
  `tls-auth-port` with `provide-xfr <tls-auth-name>`, Knot `acl.cert-hostname`,
  BIND9 client `cert-file`/`key-file`. All certificates were issued with
  `--client` so the material is in place.
- **True IXFR over XoT.** Knot requested IXFR and logged
  `receiving AXFR-style IXFR`; tdns answered with a full transfer
  (`no contiguous IXFR history from serial … falling back to full transfer`).
  Incremental transfer over TLS is therefore untested.
- **TSIG combined with XoT**, and **DoQ/XoQ**.

## 8. Reproducing

The testbed lives in the session scratchpad:

```
/private/tmp/claude-501/-Users-johani-src-git-axfr-net/\
  ea67d3e7-dda8-4abc-bd9b-f09b39f1518c/scratchpad/xot/
    run.sh              start | stop | restart | status
    ca/  certs/         the CA and the five leaf certs
    zones/              source zone files
    tdns-auth/  tdns-agent/  nsd/  bind/  knot/    per-daemon config + state
    log/                one log per daemon
```

`run.sh status` prints the ten listeners and the serial every server holds, so
a divergence is visible in one command. The tree is self-contained apart from
the two MacPorts binaries (`/opt/local/sbin/{nsd,named}`) and the Knot build
tree (`knot-dns-v3.5.2/src/`).

Note for macOS: Knot's control socket path must stay short (`sun_path` is
capped near 104 bytes), so `server.rundir` points at a short symlink rather
than at the scratchpad path directly.

## 9. Reserved — DANE/TLSA certificate validation (NOT YET TESTED)

Deliberately left open. Nothing below has been run; it is the scope and the
setup a later session should pick up.

### Why it is a real interop case despite being tdns-only

No other implementation surveyed authenticates an XoT peer by TLSA:

| Implementation | DANE for XoT peer auth | Basis |
|---|---|---|
| NSD 4.13 | no | no `dane`/`tlsa` in `nsd.conf(5)`; the binary's only `TLSA` strings are the RR-type mnemonic |
| BIND 9.20 | no | the `tls` statement offers `ca-file`, `cert-file`, `cipher-suites`, `ciphers`, `dhparam-file`, `key-file`, `prefer-server-ciphers`, `protocols`, `remote-hostname`, `session-tickets` — and nothing else |
| Knot 3.5.2 | no | no `dane`/`tlsa` in `doc/reference.rst` or in `src/knot/conf/schema.{c,h}`; source hits are all RR-type parsing (`libzscanner`, `descriptor.c`, `rrset-dump.c`) |

All three parse and serve TLSA as zone data, as any authoritative server must;
none consults it to authenticate a transfer peer.

That does **not** make DANE untestable against them. Authentication by TLSA is
entirely the *client's* business: the record has to exist in DNS and the
verifying side has to fetch and validate it. The server whose certificate is
being checked contributes nothing and needs no support. So the case to test is:

> **tdns as secondary, `tls-auth: dane`, pulling from NSD, BIND9 and Knot** —
> tdns validates each of their server certificates against a DNSSEC-validated
> TLSA RRset.

The tdns↔tdns pairing is worth covering too, in both roles, but it exercises
less: the interesting direction is tdns validating somebody else's certificate.

### What the setup requires

The lookup runs strictly through the built-in IMR (`v2/xot.go:353`,
`lookupTLSAValidatedIMR`) with no forwarder fallback, and fails closed — no
IMR, a failed lookup, or a not-provably-secure RRset all abort the transfer.
That shapes the requirements:

1. A **signed zone** holding `_853._tcp.<name> TLSA 3 1 1 <spki-sha256>` for
   each server's certificate. `tdns-cli cert leaf --emit-tlsa <name>` prints
   the record; `tdns-cli cert pin` prints the same digest base64-encoded for
   cross-checking against a `pins:` value.
2. A **resolvable, validatable chain** from the IMR's trust anchor down to that
   zone. Real signed zones on public addresses are the path of least
   resistance; synthesising a chain locally means running the IMR against a
   local root, and stub auth servers are reached as bare IPs on port 53
   (`AuthServer.Addrs`, port supplied by `core.DNSClient`) — so port 53 and, if
   servers are to be separated by address, loopback aliases. Both need root.
   (`imrengine.stubs` itself is no longer an obstacle: the resolution failure
   in `2026-08-11-imr-stub-resolution-broken.md` was fixed by 13f29229, whose
   Status line is stale.)
3. `imrengine.trust-anchor-file` (or `trust_anchor_ds`) pointing at that
   anchor. `imrengine.require_dnssec_validation: false` exists as a lab escape
   hatch and is honoured with a warning — useful to separate "TLSA matching is
   wrong" from "the chain does not validate", but a pass under it is **not** a
   DANE pass and must not be recorded as one.

This local Mac testbed is the wrong shape for it: private network, no signed
chain, no root. A lab or hetz guest with real zones is the right venue.

### What to record when it is run

- Each of the three implementations' certs validated by tdns via DANE, with
  the transferred zone diffed against source, as in §4.2.
- The fail-closed paths, each shown to actually refuse: TLSA absent; TLSA
  present but not DNSSEC-secure; TLSA present and secure but not matching the
  presented certificate. Without these the positive result means little — the
  §4.3 negatives are what gave the PKIX and pin results their weight.
- Whether the TLSA base name is taken from `tls-name` as documented when the
  peer is an IP literal, and that an IP-literal peer without `tls-name` is
  refused at config load (`v2/peers.go:191`).
- The client-side counterpart, `tls-identity.dane` on a `peers:` entry, if
  mTLS (§7) has been covered by then: a primary validating a *downstream's*
  client certificate by TLSA. That one has no equivalent anywhere else at all.

## Appendix A — wire evidence for §5 (material for an upstream report)

§5 rests on Knot sending `early_data` against a session ticket that never
offered it. That step was confirmed on the wire rather than inferred, by
routing Knot through a transparent TCP proxy (`chinspect.py` in the testbed)
that parses each ClientHello before forwarding it to tdns-auth. No packet
capture and no root are needed: the ClientHello is plaintext.

Four consecutive `knotc zone-refresh a.xot.test.`, 4 seconds apart, through
the proxy — this is **Knot's own ClientHello**, not a test client's:

```
[conn 1] ClientHello exts: [5, 10 supported_groups, 11, 13 signature_algorithms,
         16 alpn, 22, 23, 35, 51 key_share, 43 supported_versions, 65281,
         45 psk_key_exchange_modes, 28]
[conn 2] ClientHello exts: psk [5, 10, 11, 13, 16 alpn, 22, 23, 35, 51, 43,
         65281, 42 early_data, 45, 28, 41 pre_shared_key]   <<< early_data PRESENT
[conn 2] <-- server ALERT level=2 desc=110 (unsupported_extension)
[conn 3] ClientHello exts: [ … no psk, no early_data … ]
[conn 4] ClientHello exts: psk [ … 42 early_data … 41 pre_shared_key ]
[conn 4] <-- server ALERT level=2 desc=110 (unsupported_extension)
```

Knot's own log for the same four attempts alternates accordingly: two
successful refreshes (conns 1 and 3) and two `failed (handshake failed)`
(conns 2 and 4).

The proxy was first validated against `gnutls-cli --resume --earlydata`, which
produced the identical pattern — establishing that the parser reports
extension 42 correctly.

### The two halves of the claim

1. **Knot sends early data on resumption.** Shown above, directly.
2. **tdns's ticket never permitted it.** Go sets `max_early_data_size` on a
   NewSessionTicket only for QUIC (`crypto/tls/handshake_server_tls13.go`:
   `if earlyData { m.maxEarlyData = 0xffffffff }`, with `earlyData` set true
   only on the `c.quic != nil` path). A DoT listener is not QUIC, so the field
   is absent from every ticket tdns issues. RFC 8446 §4.6.1 is explicit about
   that case: "If this field is absent, the client MUST NOT send early data."

The second half is source-level rather than on-the-wire, because a TLS 1.3
NewSessionTicket travels under handshake keys and a passive proxy cannot read
it. Demonstrating it on the wire would need the server's key log.

### Which layer is at fault — Knot or GnuTLS?

The proxy answers this incidentally. `gnutls-cli --resume --earlydata`, an
ordinary GnuTLS application asking to send early data, offered extension 42
against the *same* tdns ticket, in the same alternating pattern:

```
[conn 2] ClientHello exts: psk [ … 42 early_data … 41 pre_shared_key ]
[conn 2] <-- server ALERT level=2 desc=110 (unsupported_extension)
```

Two independent GnuTLS-based clients therefore emit `early_data` against a
ticket carrying no `max_early_data_size`. That points at GnuTLS not gating the
extension on the ticket's allowance, rather than at anything specific to
Knot's own code — Knot would just be the application that asks. A report is
probably more useful phrased that way, and may belong upstream of Knot.

The GnuTLS here is 3.7.11 (MacPorts), which is not current. Re-running the
`gnutls-cli --resume --earlydata` check against a recent GnuTLS is the cheapest
way to find out whether this is already fixed, and is worth doing before
filing anything.

### Fair to note in any report

Go's server is not blameless. RFC 8446 lets a server that will not accept
early data simply omit `early_data` from EncryptedExtensions and skip the
early-data records; Go instead aborts with `unsupported_extension`. Its own
comment says why — it cannot tell this case apart from a different server
having offered 0-RTT at the same address, and declines to guess. So the clean
outcome is both: Knot stops sending early data against a ticket that does not
allow it, and tdns stops issuing resumable tickets on the DoT listener until
that lands.

### Versions for the report

| | |
|---|---|
| Knot DNS | 3.5.2, linked against GnuTLS 3.7.11 (`libgnutls.30`) |
| Server | tdns v0.8-…-gd61cfc74, Go 1.26.1 `crypto/tls`, TLS 1.3, Ed25519 leaf |
| Trigger | any second connection to the same DoT remote after a successful one |
| Control | the same Knot against NSD 4.13 succeeds 4/4 and logs `TLS/0-RTT` |

