# XoT (XFR-over-TLS) Operations Guide

**Date:** 2026-07-21
**Standards:** RFC 9103 (DNS Zone Transfer over TLS). Implemented by the
`feature/xot` work; design in `docs/2026-07-20-xot-implementation-plan.md`.

tdns supports XoT in both roles:

- **Primary (serve):** the DoT listener serves AXFR/IXFR through the same
  handler as Do53, with full TSIG parity and the same `downstreams:` ACL.
  Optional mTLS lets the primary authenticate secondaries at the TLS layer.
- **Secondary (pull):** per-primary `transport: dot` moves the SOA probe and
  the transfer to TLS. Every DoT primary must declare how its certificate is
  authenticated (`tls-auth`): static SPKI pinning, DANE, or PKIX.

TSIG stays orthogonal throughout: RFC 9103 explicitly allows TSIG and TLS
together, and `key:` keeps working unchanged on both sides. tdns-auth and
tdns-agent share the secondary pull code, so both daemons get XoT.

---

## 1. Secondary: pulling a zone over XoT

Per-primary configuration in the zone's `primaries:` list:

```yaml
zones:
   - name: example.com.
     type: secondary
     primaries:
        # Hostname primary, DANE-authenticated. Port defaults to 853 for
        # transport: dot. The hostname doubles as SNI and the TLSA base.
        - addr: ns1.example.net
          key:  NOKEY
          transport: dot
          tls-auth: dane

        # IP-literal primary, static pin + TSIG. tls-name provides the SNI
        # (and would provide the TLSA base for dane).
        - addr: 192.0.2.53:853
          key:  xfr-key-2026
          transport: dot
          tls-auth: pin
          tls-name: ns2.example.net
          pins:
             - "spki-sha256-digest-in-base64="

        # PKIX against a private CA (omit ca-file to use the system roots).
        - addr: ns3.example.net
          key:  NOKEY
          transport: dot
          tls-auth: pkix
          ca-file: /etc/tdns/certs/xfr-ca.pem
```

Rules enforced at config load (violations quarantine the zone):

- `transport: dot` requires `tls-auth: pin | dane | pkix`.
- `tls-auth: pin` requires at least one well-formed pin (base64 SHA-256 of
  the server certificate's SubjectPublicKeyInfo).
- `tls-auth: dane` with an IP-literal `addr` requires `tls-name` (no name,
  no TLSA base). Hostname primaries use the hostname automatically — a
  multi-address hostname keeps the same name on every resolved address.
- `tls-auth: pkix`: `ca-file`, when set, must be a readable PEM bundle;
  when empty the system roots are used. An IP-literal primary without
  `tls-name` is verified against the certificate's IP SANs.
- The TLS fields on a `do53` primary, or on a `notify:` target, are
  rejected loudly rather than silently ignored.

### DANE specifics

The TLSA lookup (`_<port>._tcp.<name>`) goes through the built-in validating
IMR and **fails closed**: no IMR, a failed lookup, or a not-provably-secure
RRset all abort the transfer. The `imrengine.require_dnssec_validation:
false` lab-mode escape hatch is honored (with a loud warning), consistent
with how tdns treats TLSA elsewhere.

### Getting a pin

Ask the primary operator, or bootstrap from the live cert:

```
dog +showpin @ns1.example.net           # prints SPKI pin + TLSA 3-1-1 record
tdns-cli cert pin cert.pem              # same, from a PEM file
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

Pin rotation: list the old and the new pin simultaneously (any match
admits), roll the cert, then drop the old pin.

## 1b. Provisioning certificates: `tdns-cli cert`

You do not need an external CA. `tdns-cli cert` is a deliberately minimal
internal PKI (no CRL/OCSP/renewal, no cert database — just PEM files plus an
append-only `issued.log` audit trail next to the CA key, default home
`/etc/tdns/ca/`).

**Just testing tdns?** You don't need any of this: `config mwe` generates a
self-signed cert, and `pin`/`dane` (and dog `+showpin`) work fine against it.

**Single host, one command** — provision the local tdns-auth:

```
tdns-cli cert init [--serverconfig /etc/tdns/tdns-auth.yaml]
```

This creates the CA if absent (reuses it otherwise), derives SANs from the
config's listen addresses + this host's name, writes cert/key to the exact
`dnsengine.certfile`/`keyfile` paths the config already names, drops a CA
copy next to them, and prints ready-to-paste secondary config for all three
auth modes. Restart the daemon and you serve verified XoT. Re-running is
safe; `--force` is needed to replace existing files.

**Fleet / cross-org** — the primitives:

```
tdns-cli cert ca   --name xot-ca                                   # once
tdns-cli cert leaf --ca .../xot-ca.crt --ca-key .../xot-ca.key \
    --name ns1.example.net --dns ns1.example.net --ip 192.0.2.53 \
    --emit-pin --emit-tlsa ns1.example.net                         # per server
# remote secondary (key never leaves its host):
tdns-cli cert csr  --name ns2.example.net --dns ns2.example.net    # on ns2
tdns-cli cert sign --ca ... --ca-key ... --csr ns2.example.net.csr --client
tdns-cli cert show cert.pem   # inspect; cert pin cert.pem for the pin only
```

One issuance feeds all three modes: the CA cert is the `ca-file` (pkix), the
`--emit-pin` output is the `pins:` value, the `--emit-tlsa` output is the
DANE record. Keys are written 0600 and never overwritten without `--force`.
The CA is hard-coded pathlen-0 (it can only sign leaves, never a sub-CA)
and its key is never auto-loaded by any daemon — keep it access-controlled,
ideally on an admin host rather than the DNS servers.

### Intermediate chains (external CAs)

`dnsengine.certfile` may hold the full presented chain: **leaf first, then
intermediates**, concatenated PEM — `tls.LoadX509KeyPair` presents every
block. A CA-signed leaf without its intermediates makes secondaries fail
chain building (the server logs an informational note at startup for the
single-CA-signed-cert shape). Certs from `tdns-cli cert` need no bundling:
secondaries trust the root directly.

## 2. Primary: serving XoT

Already works with a DoT listener + transfer ACL — no new config needed:

```yaml
dnsengine:
   addresses:  [ 192.0.2.53:53 ]
   transports: [ do53, dot ]
   certfile:   /etc/tdns/certs/ns1.crt
   keyfile:    /etc/tdns/certs/ns1.key

zones:
   - name: example.com.
     type: primary
     zonefile: /var/lib/tdns/example.com
     downstreams:              # provide-xfr ACL, same as over Do53
        - prefix: 198.51.100.0/24
          key:    xfr-key-2026
```

The DoT listener runs the same handler as Do53: the `downstreams:` ACL and
TSIG verification apply unchanged to transfer requests arriving over TLS.

### Optional: authenticate secondaries with mTLS

`dnsengine.downstream-auth` gates every **auth** DoT connection (the IMR's
DoT front end never requests client certificates):

```yaml
dnsengine:
   # pin: each secondary's client-cert SPKI digest is listed explicitly
   downstream-auth: pin
   downstream-pins:
      - "sec1-spki-sha256-base64="
      - "sec2-spki-sha256-base64="

   # ...or ca: standard mTLS against a CA bundle
   #downstream-auth: ca
   #downstream-ca:   /etc/tdns/certs/downstream-ca.pem
   # optional with a SHARED ca: additionally require an allowlisted DNS SAN
   # in the client cert (empty = any cert chaining to downstream-ca)
   #downstream-names: [ sec1.example.net, sec2.example.net ]
```

Notes:

- RFC 9103 treats mTLS as one of several valid policies; TSIG + IP ACL
  remains fully supported without it.
- There is deliberately no `dane` mode here: the server cannot know which
  downstream is connecting before the handshake, so it has no name to base
  a TLSA lookup on. Pins cover that case statically.
- Misconfiguration (missing/malformed pins, unreadable CA) fails at
  startup, not at the first transfer.

### Advertising DoT

A primary that serves DoT participates in the existing transport-signaling
machinery (OOTS SVCB, `draft-johani-dnsop-transport-signaling`) when that is
configured; XoT adds no separate advertisement.

### Publishing TLSA for your own cert

`PublishTlsaRR` emits a true **3-1-1** record (DANE-EE / SPKI / SHA-256) as
of this branch — the hash is over the SubjectPublicKeyInfo, matching the
advertised selector, and `dog +showpin` prints the same record for manual
publication. (Before this branch the selector said SPKI but the hash was
over the whole cert; verifiers were consistently wrong in the same way, so
pairs of old daemons agreed. A mixed old/new pair will disagree until both
sides run the fixed code — the records are TTL 120, so re-convergence after
upgrade is quick.)

## 3. dog

```
dog AXFR example.com @ns1.example.net                      # Do53, unchanged
dog +dot AXFR example.com @ns1.example.net                 # XoT, UNVERIFIED (warns)
dog +dot +tlsa AXFR example.com @ns1.example.net           # XoT, DANE-validated
dog +dot +pin=<spki-b64> AXFR example.com @ns1.example.net # XoT, pinned
dog +dot +cafile=ca.pem AXFR example.com @ns1.example.net  # XoT, PKIX
dog +showpin @ns1.example.net                              # print server pin/TLSA
```

- `+tlsa` chase-validates the TLSA RRset from the root trust anchors
  (`--trust-anchor` / IMR config / compiled-in) through the **system
  resolver** — `@server` is the authoritative being transferred from, not a
  recursive — and fails closed unless the chain is provably secure.
- `+pin`/`+cafile` also verify plain DoT/DoQ/DoH queries, not just
  transfers.
- Without a verify flag, encrypted transports keep dog's historical
  unverified behavior but print a warning.

## 4. Limitations / notes

- tdns-agent inherits the whole secondary XoT feature unchanged — both
  daemons drive the same `FetchFromUpstream`/`DoTransfer` path (guarded by
  `TestXoT_FetchFromUpstreamPKIX`).
- dog `+cafile` against an IP-literal server verifies the cert's IP SANs
  (dog prints a note); a name-mismatch failure there usually means the cert
  lacks that IP SAN, not a bad CA.

- IXFR: the secondary always requests AXFR today, and `ZoneTransferOut`
  answers IXFR requests with a full zone (AXFR-style response, which RFC
  1995 permits). XoT changes nothing here; incremental transfer is tracked
  separately (`docs/2026-07-02-*` project C).
- DoQ/DoH zone transfer is out of scope (RFC 9103 defines XoT over TLS;
  dog refuses transfer over non-DoT encrypted transports).
- The TLS minimum version on both sides is 1.3, per the RFC 9103
  recommendation.
