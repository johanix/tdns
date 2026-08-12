# XFR-over-TLS (XoT) Implementation Plan

**Date:** 2026-07-20
**Scope:** `v2/` (module `github.com/johanix/tdns/v2`) and `cmdv2/`. The legacy
`tdns/` and `cmd/` trees are out of scope.
**Standards:** [RFC 9103](https://www.rfc-editor.org/rfc/rfc9103.html) (XoT).
Authentication targets, in priority order: **static certificate pinning** and
**DANE (TLSA)** per the DPRIVE XoT authentication work (Huque et al.); PKIX
against a shared CA is a secondary objective that falls out of the same design.

---

## 1. Executive summary

tdns is unusually close to XoT already, because of three pre-existing assets:

1. **The forked miekg/dns already implements client-side XoT transport.** The
   `replace` directive in `v2/go.mod:61` points at
   `github.com/johanix/dns v1.1.72-johanix.2`, whose `dns.Transfer` struct has a
   `TLS *tls.Config` field (`xfr.go:24`) and whose `In()` dials `tcp-tls` via
   `DialTimeoutWithTLS` when that field is set (`xfr.go:61-65`). tdns never sets
   it.
2. **The primary side already serves XoT.** The DoT listener is a real
   `dns.Server{Net:"tcp-tls"}` (`v2/dot.go:57-68`) wired with the *same*
   `authDNSHandler` (`v2/do53.go:187`) that routes AXFR/IXFR to `ZoneTransferOut`
   (`v2/queryresponder.go:962-966`), with full TSIG parity (`v2/dot.go:66-67`).
3. **DANE primitives already exist:** `VerifyCertAgainstTlsaRR` and
   `LookupTlsaRR` (`v2/ops_tlsa.go:103-139`), TLSA generation
   (`PublishTlsaRR`, `ops_tlsa.go:21`), and a DNSSEC-validating in-process
   resolver (IMR + `ValidateRRset`, `v2/dnssec_validate.go:19`).

Therefore the effort is concentrated on the **secondary/client authentication
path**: config plumbing, a verifying `tls.Config` builder, wiring the DANE/pin
check into a TLS handshake callback, and fixing three defects in the existing
TLSA primitives.

A structural convenience: **tdns-auth and tdns-agent share the secondary pull
code.** `StartAgent` (`v2/main_initfuncs.go:303-335`) runs the same
`RefreshEngine` + `DnsEngine` as auth, and both reach the wire through
`ZoneTransferIn` (`v2/dnsutils.go:53`). Implementing XoT once on that path
delivers it to both daemons.

### Effort at a glance

| Surface | State today | Work required |
| --- | --- | --- |
| Primary serve (tdns-auth) | Serves AXFR-over-DoT already | Docs + optional mTLS client-auth; ~none for the core goal |
| Secondary pull (tdns-auth + tdns-agent) | Do53 only; `Transfer.TLS` never set | Config + TLS builder + wire 2 call sites |
| dog | `InsecureSkipVerify:true`; AXFR rejected on non-Do53 | Verify flags + relax guard + set `Transfer.TLS` |
| DANE/pin primitives | Generate + verify exist, 3 defects | Fix selector, validation, generation consistency; add SPKI + pin store |

---

## 2. Current-state reference map

Concrete anchors every phase below refers back to.

### 2.1 Secondary pull chain (client)

- `v2/refreshengine.go:202` `RefreshEngine` — engine loop; dispatches refresh.
- `v2/zone_utils.go:30` `Refresh` — `case Secondary:` (`:55`) re-resolves
  primaries (`:64`), runs the SOA probe (`:70`), fetches on serial advance
  (`:81`).
- `v2/zone_utils.go:116` `DoTransfer` — SOA probe. Builds `dns.Client`
  (`:138`), `c.TsigProvider = provider` (`:145`), `c.Exchange(m, upstream)`
  (`:146`). **Do53 only; no `TLSConfig`, no `Net:"tcp-tls"`.**
- `v2/zone_utils.go:252` `FetchFromUpstream` — iterates `zd.Upstreams`,
  calls `new_zd.ZoneTransferIn(upstream, zd.IncomingSerial, "axfr", up.Key, conf)`
  (`:289`). Always requests **axfr**.
- `v2/dnsutils.go:53` `ZoneTransferIn` — `transfer := new(dns.Transfer)`
  (`:72`), `transfer.TsigProvider = provider` (`:79`),
  `transfer.In(msg, upstream)` (`:80`). **`transfer.TLS` never set.**

### 2.2 Primary serve chain (server)

- `v2/queryresponder.go:962-966` routes `TypeAXFR`/`TypeIXFR` to
  `zd.ZoneTransferOut(w, r)`.
- `v2/dnsutils.go:237` `ZoneTransferOut` — ACL + TSIG gate (`:240-249`),
  snapshot pin (`:264`), `dns.Transfer.Out(w, r, ch)` (`:318`).
- `v2/do53.go:34` `DnsEngine` — builds `authDNSHandler`, starts Do53 listeners,
  and (gated on cert/key at `:113-131`) calls `DnsDoTEngine(ctx, conf,
  addresses, &cert, authDNSHandler)` (`:187`), DoH (`:194`), DoQ (`:201`).
- `v2/dot.go:19` `DnsDoTEngine` — real `dns.Server{Net:"tcp-tls", TLSConfig,
  TsigProvider, Handler: TsigSigningHandler(loggingHandler)}` (`:57-68`).
  `tls.Config` at `:29-34` (TLS1.3, `NextProtos:["dot"]`, no `ServerName`,
  `ClientAuth` commented out at `:32`).

### 2.3 Config + resolution

- `v2/structs.go:254` `PeerConf{Addr, Key, Legacy}` — **no transport/TLS
  fields.**
- `v2/structs.go:266` `ZoneConf.Primaries []PeerConf`;
  `v2/structs.go:145-146` `ZoneData.PrimariesConf` / `.Upstreams`.
- `v2/parseconfig.go:658-731` secondary validation (requires ≥1 primary,
  rejects legacy bare-string, requires explicit key, normalizes `:53`,
  `resolvePrimaries`).
- `v2/resolve_primaries.go:28` `resolvePrimaries` →
  `expandPrimaryEntry` (`:52`) → `imrLookupAddrs` (`:73`) → `buildUpstreams`
  (`:113`). **Collapses hostname → IP and discards the name**
  (`buildUpstreams` keeps only `addr:port` + key).
- `v2/config.go:185-186` `DnsEngineConf.CertFile`/`.KeyFile` (server);
  `:206-207` IMR; `:356-361` API server. **No client-side trust config.**

### 2.4 Auth primitives

- `v2/ops_tlsa.go:21` `PublishTlsaRR` — TLSA `Usage:3, Selector:1, MatchingType:1`
  (`:33-37`) but `parseCertificate` hashes `cert.Raw` (full cert, `:77`).
  **Selector says SPKI, hash is full-cert → inconsistent.**
- `v2/ops_tlsa.go:103` `LookupTlsaRR` → `RecursiveDNSQueryWithConfig`
  (`v2/dnslookup.go:1739`) → external resolvers. **Not DNSSEC-validating.**
- `v2/ops_tlsa.go:114` `VerifyCertAgainstTlsaRR(tlsarr, rawcert)` — usage 3
  only, SHA-256/512, constant-time. **Ignores `Selector`** (always hashes the
  bytes passed in).
- `v2/dnssec_validate.go:19` `ValidateRRset` — the validating path DANE needs.
- `v2/dnslookup.go:2205` parses TLSA from SVCB answers →
  `imr.Cache.StoreTLSAForServer(...)` (validated discovery, currently unused for
  handshakes).
- `v2/core/dnsclient.go:136` `NewDNSClient` — client factory; DoT/DoH/DoQ
  default to `InsecureSkipVerify:true` (`:140-149`); TODO at `:135`
  ("Once we can do cert validation ... add a WithVerifyCertificates() option").
  `tlsConfig` is an injectable parameter — a caller *can* pass a verifying
  config.
- `v2/apiclient.go:34-68` — the only place with verify branching; the
  `rootcafile == "tlsa"` DANE branch is **commented out** (`:35-56`).
- `v2/tsig_peer.go:215` `SignForPeer`; `:91` `tsigProvider`; `:255`
  `checkInboundTSIG`.

### 2.5 dog

- `cmdv2/dog/dog.go:343-353` — `tls.Config{InsecureSkipVerify:true,
  MinVersion:TLS12}`, DoQ NextProtos `["doq"]`. No verify/pin/tlsa flag.
- `cmdv2/dog/dog.go:264-274` — AXFR/IXFR dispatch **rejects non-Do53**
  (`"Zone transfer only supported over Do53/TCP"`); guard in
  `cmdv2/dog/internal/transport/transport.go:14-20` (`PlainDo53`).
- `v2/rr_print.go:314` `ZoneTransferPrint` — `transfer := new(dns.Transfer)`
  (`:334`), TSIG wired (`:338-341`), `transfer.In(msg, upstream)` (`:342`).
  **`transfer.TLS` never set.**

---

## 3. Design decisions

### 3.1 Per-primary configuration model

Extend `PeerConf` (`v2/structs.go:254`) rather than inventing a parallel type,
so `Primaries`, `Notify`, and the resolution pipeline keep working unchanged for
Do53 peers. New fields are all optional and default to today's Do53 behavior.

```go
// v2/structs.go — PeerConf
type PeerConf struct {
    Addr      string `yaml:"addr" mapstructure:"addr"`
    Key       string `yaml:"key" mapstructure:"key"`
    Legacy    string `yaml:"-" mapstructure:"-"`

    // XoT additions (all optional; empty Transport => do53, unchanged behavior)
    Transport string   `yaml:"transport" mapstructure:"transport"` // do53 | dot
    TLSAuth   string   `yaml:"tls-auth" mapstructure:"tls-auth"`   // pin | dane | pkix
    TLSName   string   `yaml:"tls-name" mapstructure:"tls-name"`   // SNI + DANE base name; defaults to Addr hostname
    Pins      []string `yaml:"pins" mapstructure:"pins"`           // base64 SPKI SHA-256 pins (tls-auth: pin)
    CAFile    string   `yaml:"ca-file" mapstructure:"ca-file"`     // PEM bundle (tls-auth: pkix)
}
```

Example zone config:

```yaml
zones:
  example.com:
    type: secondary
    primaries:
      - addr: ns1.example.net:853
        key: NOKEY
        transport: dot
        tls-auth: dane          # TLSA at _853._tcp.ns1.example.net, DNSSEC-validated
      - addr: 192.0.2.53:853
        key: xfrkey.example.
        transport: dot
        tls-auth: pin
        tls-name: ns2.example.net
        pins:
          - "sha256-base64-of-spki=="
```

**Rationale for keeping TSIG orthogonal:** RFC 9103 explicitly allows TSIG *and*
TLS together. `tls-auth` authenticates the channel/peer certificate; `key`
still authenticates the message stream. Both are independent and both continue
to work.

### 3.2 Preserving the hostname through resolution

XoT needs the primary's DNS name for two things the current pipeline throws
away: **SNI** and the **DANE base domain** (`_853._tcp.<name>`).
`buildUpstreams` (`v2/resolve_primaries.go:113`) currently produces only
`{Addr: ip:port, Key}`. Add a resolved-name field so each resolved upstream
tuple remembers where it came from.

- Add `TLSName string` propagation: when `expandPrimaryEntry`
  (`resolve_primaries.go:52`) resolves a hostname, copy that hostname (or the
  explicit `p.TLSName` if set) into each produced `PeerConf`. For IP-literal
  primaries, `TLSName` stays whatever the user configured (required for DANE/SNI
  when connecting to a bare IP).
- Carry `Transport`, `TLSAuth`, `Pins`, `CAFile` through `expandPrimaryEntry`
  and `buildUpstreams` unchanged (copy from the source `PeerConf`).

### 3.3 The single verifying `tls.Config` builder

One helper is the core of the whole feature. New file `v2/xot.go`:

```go
// v2/xot.go
package tdns

// ClientTLSConfigForPeer builds a *tls.Config for an outbound XoT connection to
// peer, dispatching certificate verification to the configured auth mode.
// Returns (nil, nil) when peer.Transport is empty/"do53" (caller stays on TCP).
func (conf *Config) ClientTLSConfigForPeer(peer PeerConf) (*tls.Config, error)
```

Behavior:

- `Transport == "" || "do53"` → return `(nil, nil)`; caller uses plain TCP.
- Otherwise build `&tls.Config{ServerName: serverName(peer), MinVersion:
  tls.VersionTLS13, NextProtos: []string{"dot"}}` and set exactly one
  verification strategy via **`VerifyConnection`** (preferred over
  `VerifyPeerCertificate` because it gives access to the negotiated
  `tls.ConnectionState` including `PeerCertificates` and `ServerName`):
  - **`pin`**: set `InsecureSkipVerify: true` (disables PKIX chain building) and
    in `VerifyConnection` compute base64(SHA-256(SPKI)) of
    `cs.PeerCertificates[0].RawSubjectPublicKeyInfo` and constant-time compare
    against `peer.Pins`. No DNS.
  - **`dane`**: set `InsecureSkipVerify: true` and in `VerifyConnection` call a
    new `conf.verifyDANE(peer, cs.PeerCertificates[0])` that looks up the TLSA
    RRset at `_<port>._tcp.<TLSName>` **through the validating IMR** (§3.4) and
    runs `VerifyCertAgainstTlsaRR` against each RR (any match ⇒ pass).
  - **`pkix`**: leave `InsecureSkipVerify:false`, load `peer.CAFile` into
    `RootCAs` (or system roots if empty). Standard PKIX; `ServerName` drives
    hostname check. No custom callback needed.

`serverName(peer)` = `peer.TLSName` if set, else the hostname portion of
`peer.Addr`. For DANE with usage 3 (DANE-EE) the SNI/name match is not strictly
required, but we set it for interoperability with primaries that vhost on SNI.

### 3.4 DANE lookups must be DNSSEC-validated

DANE is meaningless over an unvalidated lookup. `LookupTlsaRR`
(`v2/ops_tlsa.go:103`) uses `RecursiveDNSQueryWithConfig` (external resolvers,
no chain validation). For XoT DANE, route TLSA lookups through the in-process
validating IMR instead. Two options, in preference order:

1. **Consume the already-validated cache.** `v2/dnslookup.go:2205` already
   parses TLSA from SVCB and calls `imr.Cache.StoreTLSAForServer(...)` after
   DNSSEC validation. Add a `Cache.LookupTLSAForServer(name, port)` reader and
   prefer it.
2. **Direct validated fetch.** Add `func (conf *Config) LookupTlsaRRValidated(
   name string, port uint16) (*core.RRset, error)` in `v2/xot.go` that uses the
   IMR's `DefaultRRsetFetcher` for `_<port>._tcp.<name> TLSA` and requires the
   result to be DNSSEC-validated (reuse the same validation gate as
   `ValidateRRset`, `v2/dnssec_validate.go:19`). Fail closed if unvalidated.

### 3.5 TLSA primitive fixes (must-fix before DANE is correct)

1. **`VerifyCertAgainstTlsaRR` ignores `Selector`** (`v2/ops_tlsa.go:114`). Add a
   `switch tlsarr.Selector`: selector 0 hashes `cert.Raw`; selector 1 hashes
   `cert.RawSubjectPublicKeyInfo`. Change the signature to accept the parsed
   `*x509.Certificate` (or both raw forms) instead of a single `rawcert []byte`,
   so the caller cannot pass the wrong bytes.
2. **`PublishTlsaRR` is internally inconsistent** (`v2/ops_tlsa.go:33-37,77`):
   it advertises `Selector:1` (SPKI) but `parseCertificate` hashes `cert.Raw`
   (full cert = selector 0 semantics). Align generation to true **3-1-1**
   (DANE-EE / SPKI / SHA-256) by hashing `cert.RawSubjectPublicKeyInfo`, which is
   the form the XoT/DANE profile recommends and what pinning also uses. Add a
   regression test.
3. **Static-pin helper.** Add `SPKISHA256(cert *x509.Certificate) string`
   (base64 of SHA-256 over `RawSubjectPublicKeyInfo`) in `v2/xot.go`, shared by
   the pin verifier, `PublishTlsaRR`, and a future `tdns-cli`/`dog` "show pin"
   command.

Keep the changes to `VerifyCertAgainstTlsaRR` backward-compatible for its
current single caller (the commented-out `apiclient.go` block) — since that
caller is dead code, updating its signature is free.

---

## 4. Phased implementation

Each phase is independently mergeable and testable.

### Phase 0 — TLSA primitive fixes + pin helper (foundation)

**Files:** `v2/ops_tlsa.go`, new `v2/xot.go`, new `v2/xot_test.go`.

- [ ] Add `SPKISHA256(cert *x509.Certificate) string` to `v2/xot.go`.
- [ ] Rework `VerifyCertAgainstTlsaRR` (`ops_tlsa.go:114`) to honor `Selector`
      (0 = `cert.Raw`, 1 = `cert.RawSubjectPublicKeyInfo`) and take a
      `*x509.Certificate`.
- [ ] Fix `PublishTlsaRR`/`parseCertificate` (`ops_tlsa.go:21-80`) to emit true
      3-1-1 over SPKI.
- [ ] Tests: round-trip a self-signed cert through `PublishTlsaRR` →
      `VerifyCertAgainstTlsaRR` for both selectors; a pin round-trip.

**Acceptance:** `go test ./v2/ -run TLSA` green; generated TLSA verifies against
the same cert.

### Phase 1 — Config schema + resolution plumbing

**Files:** `v2/structs.go`, `v2/parseconfig.go`, `v2/resolve_primaries.go`,
`v2/config_validate.go`, plus sample configs under
`cmdv2/auth/tdns-auth.sample.yaml` and `cmdv2/agent/`.

- [ ] Add the five fields to `PeerConf` (`structs.go:254`) per §3.1.
- [ ] Validate in the secondary path (`parseconfig.go:658-731`): `transport ∈
      {"", do53, dot}`; if `dot`, require a resolvable `tls-auth ∈ {pin, dane,
      pkix}`; `pin` requires non-empty `Pins`; `pkix` requires readable
      `CAFile`; default port to 853 when `transport: dot` and no port given
      (mirror the existing `:53` normalization at `parseconfig.go:698`).
- [ ] Thread `Transport`/`TLSAuth`/`TLSName`/`Pins`/`CAFile` through
      `expandPrimaryEntry` + `buildUpstreams` (`resolve_primaries.go:52,113`),
      setting `TLSName` to the source hostname when resolving names (§3.2).
- [ ] Extend `ValidateACL`-adjacent config validation if needed; add a
      `deprecated_config_keys`-style test asserting old Do53 configs still parse.

**Acceptance:** existing secondary configs parse unchanged; a `transport: dot`
config resolves to upstreams that carry `TLSName` + auth mode; a `dot` config
missing `tls-auth` is rejected at load with a clear error.

### Phase 2 — The verifying TLS builder (core)

**Files:** `v2/xot.go`, `v2/xot_test.go`.

- [ ] Implement `ClientTLSConfigForPeer` (§3.3) with the three
      `VerifyConnection` strategies.
- [ ] Implement `LookupTlsaRRValidated` (or `Cache.LookupTLSAForServer`) per
      §3.4, failing closed on unvalidated DANE lookups.
- [ ] Tests with a local TLS server (reuse `startTestAXFRServerCore` from
      `v2/zone_transfer_out_test.go:31` as a pattern): pin match/mismatch;
      DANE match against an injected validated TLSA; pkix against a test CA.

**Acceptance:** unit tests cover pass/fail for all three modes; a mismatched pin
or TLSA aborts the handshake.

### Phase 3 — Secondary pull over XoT (tdns-auth + tdns-agent)

**Files:** `v2/dnsutils.go`, `v2/zone_utils.go`.

- [ ] `ZoneTransferIn` (`dnsutils.go:53`): thread the upstream `PeerConf`
      (not just `upstream string` + `keyName`) so the function can call
      `conf.ClientTLSConfigForPeer(peer)` and set `transfer.TLS = cfg` before
      `transfer.In` (`:80`). Update the caller `FetchFromUpstream`
      (`zone_utils.go:289`) to pass the full `up` tuple. Default port 853 when
      `Transport == dot` and no port is present.
- [ ] `DoTransfer` SOA probe (`zone_utils.go:116-146`): when the upstream is
      `dot`, set `c.Net = "tcp-tls"` and `c.TLSConfig =
      conf.ClientTLSConfigForPeer(up)` on the `dns.Client` (`:138`). Keep Do53
      behavior for empty transport.
- [ ] Confirm TSIG still layers correctly (provider set after TLS config; the
      fork applies TSIG inside the TLS stream — same as the DoT server side).

**Acceptance:** an integration test transfers a zone from a local DoT primary to
a secondary `ZoneData` using each auth mode; a tampered cert fails the transfer.
Manual: point a `transport: dot` secondary at a real DoT-serving tdns-auth
primary and observe a successful AXFR-over-TLS in the log.

### Phase 4 — dog (client tool)

**Files:** `cmdv2/dog/dog.go`, `cmdv2/dog/internal/transport/transport.go`,
`v2/rr_print.go`.

- [ ] Add flags: `+tlsa` (DANE-verify the server), `+pin=<base64>` (repeatable),
      `+cafile=<path>` (PKIX). Build the outbound `tls.Config` at
      `dog.go:343-353` via `tdns.ClientTLSConfigForPeer` (construct a synthetic
      `PeerConf` from flags) instead of the hardcoded `InsecureSkipVerify:true`.
      Keep `InsecureSkipVerify` only when no verify flag is given, and print a
      warning (parity with browsers/dig `+tls-ca`).
- [ ] Relax the transfer guard: allow AXFR/IXFR over DoT. In
      `dog.go:264-274`, permit the transfer when transport is DoT (not only
      `PlainDo53`); pass the built `tls.Config` into `ZoneTransferPrint`.
- [ ] `ZoneTransferPrint` (`rr_print.go:314`): add a `tlsConfig *tls.Config`
      parameter and set `transfer.TLS = tlsConfig` before `transfer.In`
      (`:342`).

**Acceptance:** `dog +dot +tlsa AXFR example.com @ns1.example.net` performs a
validated XoT transfer; `+pin` with a wrong pin fails; plain `dog AXFR` over
Do53 is unchanged.

### Phase 5 — Primary serve hardening + docs (optional / low effort)

The primary already serves AXFR-over-DoT (see §1). This phase is about making it
explicit and, optionally, authenticating the *secondary* at the TLS layer.

**Files:** `v2/dot.go`, `v2/do53.go`, guide docs.

- [ ] Document that `transports: [dot]` + `dnsengine.certfile/keyfile` +
      a `downstreams` ACL already yields a working XoT primary.
- [ ] (Optional) Enable **mTLS client-auth** for downstreams: uncomment/replace
      `ClientAuth` at `dot.go:32`, add a `downstream-ca` / `downstream-pins`
      config, and verify the client cert in a `VerifyConnection` callback that
      reuses the Phase-2 pin/DANE logic. Note RFC 9103 treats mTLS as one of
      several options; TSIG+IP ACL remains valid without it.
- [ ] (Optional) Advertise XoT capability via the existing transport-signal
      SVCB machinery (`v2/ops_svcb_transport.go`,
      `OptAddTransportSignal`).

**Acceptance:** documented end-to-end XoT between two tdns instances.

---

## 5. Testing strategy

- **Unit** (`v2/xot_test.go`, `v2/ops_tlsa` tests): TLSA selector matrix, pin
  compute/compare, `ClientTLSConfigForPeer` per mode.
- **Integration** (extend `v2/zone_transfer_out_test.go` harness at `:31`):
  spin a DoT-serving test primary, transfer to a secondary over each auth mode,
  assert failure on cert/pin/TLSA mismatch and on unvalidated DANE.
- **Regression:** existing Do53 secondary configs and transfers must be
  byte-for-byte unchanged (empty `Transport` path). Add an assertion in the
  config parse tests.
- **Manual/interop:** transfer against a known XoT implementation (BIND `tls`
  primary, or Unbound/nsd) to validate on-wire compatibility, since the
  transport lives in the miekg fork.

## 6. Risks and open questions

1. **Fork dependency.** Client XoT relies on `johanix/dns`'s `Transfer.TLS`
   field. Confirm the fork's `In()` applies TSIG correctly *inside* the TLS
   stream (the server side already proves TSIG-over-tcp-tls works via
   `dns.Server`). Add an interop test early.
2. **DANE without DNSSEC is a footgun.** `LookupTlsaRR` must not be used for XoT
   DANE; enforce the validated path (§3.4) and fail closed. Consider a startup
   check that the IMR/validator is enabled when any zone requests
   `tls-auth: dane`.
3. **IP-literal primaries + DANE/SNI.** A primary configured as a bare IP has no
   name for SNI or the TLSA base domain; require explicit `tls-name` in that
   case (validate in Phase 1).
4. **Port defaults.** Do53 defaults to 53, DoT to 853. The normalization at
   `parseconfig.go:698` and the ad-hoc `:53` join in `DoTransfer`
   (`zone_utils.go:129-132`) must both become transport-aware.
5. **`SortV4First` / multi-address primaries.** A hostname primary expands to
   several IP upstreams that must all share the same `TLSName` for
   SNI/DANE — handled by copying the name in Phase 1, but worth a test.
6. **IXFR-over-TLS.** `FetchFromUpstream` always requests AXFR
   (`zone_utils.go:289`) and `ZoneTransferOut` never generates incremental
   IXFR. Orthogonal to XoT but note it if IXFR-over-TLS is advertised.

## 7. Suggested PR sequence

1. Phase 0 (TLSA fixes) — small, self-contained, valuable on its own.
2. Phase 1 (config) — no behavior change for Do53.
3. Phase 2 (TLS builder) — pure addition + tests.
4. Phase 3 (secondary pull) — the headline feature.
5. Phase 4 (dog).
6. Phase 5 (primary docs + optional mTLS).
