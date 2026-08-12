# PKIX for XoT: remaining loose ends + a minimal in-tool CA

**Date:** 2026-07-21
**Scope:** `v2/` (module `github.com/johanix/tdns/v2`) and `cmdv2/`.
**Baseline:** builds on the XoT work in branch `feature/xot` (RFC 9103 XoT with
pin / DANE / PKIX auth). File/line anchors below refer to that branch, not to
`main`, which does not yet carry the XoT code.
**Companion docs:** `docs/2026-07-20-xot-implementation-plan.md` (the XoT plan)
and `docs/2026-07-21-xot-operations.md` (operations guide).

This document has two parts:

1. **PKIX loose ends** — what is still missing to call PKIX/CA-based XoT
   "complete" across tdns-auth, tdns-agent, and dog. PKIX *verification* already
   works on `feature/xot`; the gaps are provisioning, chain handling, a few
   config/validation niceties, and tests.
2. **A minimal in-tool CA** — the design for `tdns-cli cert …`, so PKIX (and pin,
   and DANE) can be used without depending on an external CA and without growing
   the fragile `utils/gen-cert.sh` openssl wrapper into a CA.

---

## Part 1 — PKIX loose ends in XoT (tdns-auth / tdns-agent / dog)

### 1.1 What already works (baseline on `feature/xot`)

PKIX is already implemented in both directions; this section exists so the "loose
ends" are understood as a delta, not a rebuild.

- **Secondary → primary (Strict TLS).** `ClientTLSConfigForPeer`
  (`v2/xot.go`, `case TLSAuthPKIX`) loads `ca-file` into `RootCAs` (or falls back
  to system roots), sets `ServerName` from `tls-name`/addr, and relies on
  crypto/tls's standard chain + hostname/IP-SAN verification. This is the
  equivalent of BIND 9's Strict TLS with `ca-file` + `remote-hostname`
  (tdns's `tls-name` == BIND's `remote-hostname`). Covered by
  `TestXoT_PKIXModeEndToEnd` (`v2/xot_test.go`).
- **Primary (Mutual TLS).** `ServerTLSConfigForDoT` (`v2/xot.go`,
  `case "ca"`) builds a `ClientCAs` pool and sets
  `tls.RequireAndVerifyClientCert`, gated by the opt-in
  `dnsengine.downstream-auth: ca` + `downstream-ca` config
  (`v2/config.go`, `DnsEngineConf.DownstreamAuth/DownstreamCA`). Applied only to
  the auth DoT listener, never the IMR front end (`v2/do53.go` passes
  `applyDownstreamAuth=true`; `v2/imrengine.go` passes `false`). Covered by
  `TestXoT_ServerMTLSCA`.
- **dog (client).** `+cafile=<pem>` builds a PKIX-verifying config through
  `tdns.ClientTLSConfigForPeer` for both queries and transfers
  (`cmdv2/dog/dog.go`, `buildDogTLSConfig`).
- **Config validation.** `ca-file` is checked for readability and at least one
  CERTIFICATE PEM block at load (`v2/xot.go`, `checkPEMCertFile`, called from
  `validatePeerXoT`).

### 1.2 Loose ends

Ordered by value. None of these block the common case; together they close the
gap to "BIND-equivalent, production-comfortable" PKIX.

#### LE-1. Certificate provisioning without an external CA — **the real blocker**

PKIX verification is meaningless until someone can *produce* a CA and CA-signed
server/client certs. Today tdns can only emit a single self-signed cert
(`utils/gen-cert.sh`). This is Part 2 of this document and is the one piece that
actually gates real-world use.

#### LE-2. Server intermediate-chain presentation (doc + guard)

A CA-signed auth-server cert usually needs to present leaf **+ intermediate(s)**
so the secondary can build the chain. `tls.LoadX509KeyPair(certFile, keyFile)`
(`v2/do53.go`) already reads *all* CERTIFICATE blocks in `certFile` as the chain,
so this works if the operator concatenates leaf + intermediates into
`dnsengine.certfile`. Work:

- Document the "bundle intermediates into certfile, leaf first" requirement in
  the operations guide.
- Optional startup guard: if the loaded cert is not self-signed and only one
  certificate is present, log a warning ("CA-signed leaf with no intermediates
  in certfile — secondaries may fail chain building"). Purely diagnostic.

Effort: doc + ~15 lines. No API change.

#### LE-3. `tdns-agent` parity check

The agent shares the secondary pull path (`ZoneTransferIn` / `DoTransfer`), so it
inherits PKIX automatically — there is no agent-specific PKIX code to write. The
loose end is only **verification**: add a test (or a note in the ops guide) that a
zone configured with `transport: dot, tls-auth: pkix` transfers under
`tdns-agent` as well as `tdns-auth`, since the two daemons wire the refresh
engine slightly differently (`v2/main_initfuncs.go`, `StartAgent` vs the auth
start path). No new code expected; this is a guardrail against future drift.

#### LE-4. Optional client-identity binding on the primary

Today `downstream-auth: ca` accepts *any* client cert that chains to
`downstream-ca`. That is the BIND model and is fine when the CA is dedicated to
this purpose. For a shared CA, an operator may want "this secondary must present
a cert whose SAN/CN is X." Work (optional):

- Add `downstream-names: [ns2.example.net, …]` and, in the `ca` branch of
  `ServerTLSConfigForDoT`, extend the `VerifyConnection` callback to also require
  the verified client leaf's DNS SAN to be in the allowlist.
- Keep it opt-in; empty list = current behavior (chain-only).

Effort: ~30 lines + test. Low priority — IP ACL + TSIG already provide a coarse
identity gate.

#### LE-5. TLS tuning knobs (low value)

BIND's `tls` object exposes `protocols`, `ciphers`, `cipher-suites`,
`dhparam-file`, `prefer-server-ciphers`, `session-tickets`. tdns pins
`MinVersion: tls.VersionTLS13` everywhere, which makes almost all of these moot
(TLS 1.3 has a fixed, safe cipher set and no DH param file). Recommendation:
**do not implement** unless a concrete interop need appears; if it does, the only
plausible knob is an optional `min-tls-version: "1.2"` per listener/peer. Note as
a non-goal so it does not accrete.

#### LE-6. dog PKIX ergonomics

`+cafile=` covers PKIX in dog. Two small polish items:

- `+cafile` with a server given as an IP literal: verification then requires an
  IP SAN in the server cert (crypto/tls sets `ServerName` to the IP). Emit a
  hint when verification fails against an IP that this may be a missing-SAN or
  wrong-`tls-name` situation.
- Document that `+cafile` and `+tlsa`/`+pin` are mutually exclusive (already
  enforced in `buildDogTLSConfig`), and that `+showpin` is the bootstrap helper
  for all three modes.

Effort: doc + a couple of log lines.

#### LE-7. Test coverage

- **PKIX with an intermediate CA** (root → intermediate → leaf): assert the
  secondary builds the chain when the primary presents leaf+intermediate, and
  fails when the intermediate is omitted. This exercises LE-2.
- **PKIX hostname/SAN mismatch**: server cert valid chain but wrong name ⇒
  transfer must fail (distinct from the existing untrusted-CA test).
- **tdns-agent PKIX transfer** (LE-3).

### 1.3 Summary of Part 1

| Item | Type | Effort | Priority |
|---|---|---|---|
| LE-1 provisioning (in-tool CA) | feature | Part 2 | **required** |
| LE-2 intermediate chain | doc + guard | ~15 lines | medium |
| LE-3 agent parity test | test | small | medium |
| LE-4 client-identity allowlist | feature (opt-in) | ~30 lines | low |
| LE-5 TLS tuning knobs | — | — | non-goal |
| LE-6 dog ergonomics | doc + logs | small | low |
| LE-7 PKIX/SAN/agent tests | test | small | medium |

The verification machinery needs essentially nothing. Everything of substance
funnels into LE-1 → the in-tool CA below.

---

## Part 2 — A minimal certificate authority in `tdns-cli`

### 2.1 Rationale (why in-tool, not the shell script)

The goal is **PKIX without depending on an external CA**, as a closed loop: one
tool mints a root, signs the auth-server (and optionally client) certificates,
and hands back the `ca-file` operators drop onto secondaries.

Two ways to get there were considered:

- **Grow `utils/gen-cert.sh` into a CA (openssl).** Fastest to a first version,
  no new Go, standard artifacts — but openssl CA state in shell is fragile
  (`index.txt`/serial, `openssl ca` vs `x509 -req`, SAN/EKU extensions dropped on
  signing unless `copy_extensions`/`-extfile` are exactly right), and it is a
  portability landmine across LibreSSL (macOS), OpenSSL 1.1/3.0, and the *BSD
  targets tdns already cares about. It is also interactive, so it does not
  compose with Docker/CI (the Dockerfile already pipes `echo | sh` into it).
- **Build a minimal PKI into `tdns-cli` (crypto/x509).** More code (~a few
  hundred lines), stdlib-only, identical on every platform, testable,
  non-interactive, and it closes the XoT loop natively: the same command can
  print the SPKI pin (`SPKISHA256`) and emit the matching TLSA 3-1-1
  (`NewTlsaRR`), so it serves **pin and DANE** as well as PKIX.

**Decision: build it into `tdns-cli`, scoped as a deliberately minimal internal
PKI.** Keep `utils/gen-cert.sh` for the trivial self-signed case; do **not** grow
it into a CA. The one real cost — owning a mini-CA — is bounded by keeping the
scope tight (no CRL/OCSP, no policy engine, safe hard-coded constraints).

There is already a natural home and precedent: `tdns-cli` has a `generate`
command group that imports `crypto/x509` and does `generate tlsa <domain>
<cert.pem>` (`v2/cli/generate_cmds.go`), and the CLI already manages SIG(0)/TSIG
key material and a KeyDB.

### 2.2 Command surface

New command group `tdns-cli cert` (sibling to `generate`), file
`v2/cli/cert_cmds.go`:

```
tdns-cli cert ca    --name <cn> [--out-dir DIR] [--validity DAYS] [--algorithm ed25519|ecdsa-p256|rsa2048]
tdns-cli cert leaf  --ca CA.crt --ca-key CA.key --name <cn>
                    [--dns a,b] [--ip 1.2.3.4] [--server] [--client]
                    [--validity DAYS] [--algorithm …] [--out-dir DIR]
                    [--emit-tlsa <owner>] [--emit-pin]
tdns-cli cert csr   --name <cn> [--dns …] [--ip …] [--algorithm …] [--out-dir DIR]
tdns-cli cert sign  --ca CA.crt --ca-key CA.key --csr REQ.pem [--server] [--client]
                    [--validity DAYS] [--out-dir DIR] [--emit-tlsa <owner>] [--emit-pin]
tdns-cli cert pin   <cert.pem>            # print base64 SPKI SHA-256 (reuse SPKISHA256)
tdns-cli cert show  <cert.pem>            # human-readable summary (subject, SANs, EKU, validity, pin)
```

Design points:

- **`ca`** — self-signed root: `BasicConstraintsValid=true, IsCA=true,
  MaxPathLenZero=true` (pathlen 0: signs leaves only, no sub-CAs),
  `KeyUsage = CertSign | CRLSign`, long validity (default 3650d). Emits
  `<name>.crt` + `<name>.key`.
- **`leaf`** — key + CA-signed end-entity cert. `IsCA=false`; SANs from
  `--dns`/`--ip`; `ExtKeyUsage` = `serverAuth` (`--server`, default on) and/or
  `clientAuth` (`--client`); for **mutual XoT** a downstream cert wants both.
  `KeyUsage = DigitalSignature | KeyEncipherment`. Default validity shorter
  (e.g. 397d, the CA/Browser cap, a sane habit even for a private CA).
- **`csr` + `sign`** — the split-provisioning path for cross-org mutual TLS: the
  secondary generates a key + CSR locally (private key never leaves the host),
  the CA operator runs `cert sign`. `sign` copies SANs from the CSR and applies
  the requested EKU/validity.
- **`--emit-tlsa <owner>`** — after producing a leaf, print the TLSA 3-1-1 RR
  (via `NewTlsaRR`) for the given owner/port so DANE users get the record in the
  same step. **`--emit-pin`** — print the SPKI pin so pin users get their
  `pins:`/`+pin=` value. This is what makes the tool serve all three auth modes.
- **`pin`/`show`** — read-only helpers; `pin` reuses `tdns.SPKISHA256`.

### 2.3 Implementation notes

All stdlib, no new dependencies:

- Key generation: `ed25519.GenerateKey` (default; smallest, fastest, and fine for
  TLS 1.3), `ecdsa.GenerateKey(elliptic.P256())`, or `rsa.GenerateKey(…, 2048)`.
- Cert creation: `x509.CreateCertificate(rand, template, parent, pub, caPriv)`
  — self-signed when `parent == template`, CA-signed otherwise.
- CSR: `x509.CreateCertificateRequest` / `x509.ParseCertificateRequest` +
  `req.CheckSignature()`.
- Serial numbers: random 128-bit (`rand.Int(rand.Reader, 2^128)`) — no serial-file
  state to manage, which is a core reason to avoid the openssl-CA-in-shell path.
- Output: PEM for cert (`CERTIFICATE`) and key (`PRIVATE KEY`, PKCS#8 via
  `x509.MarshalPKCS8PrivateKey`). **Key files written `0600`; refuse to overwrite
  an existing key without `--force`.**
- Reuse: `SPKISHA256` (`v2/xot.go`) and `NewTlsaRR` (`v2/ops_tlsa.go`) already
  exist and produce exactly the values pin/DANE modes consume — the CLI must not
  reimplement hashing.

### 2.4 Closing the XoT loop (end-to-end operator flow)

```
# 1. Make a private CA (once)
tdns-cli cert ca --name "tdns-xot-ca" --out-dir /etc/tdns/pki

# 2. Server cert for the primary's DoT listener (serverAuth)
tdns-cli cert leaf --ca /etc/tdns/pki/tdns-xot-ca.crt --ca-key /etc/tdns/pki/tdns-xot-ca.key \
    --name ns1.example.net --dns ns1.example.net --ip 192.0.2.53 --server \
    --emit-pin --emit-tlsa ns1.example.net
#   -> ns1.example.net.crt/.key  (set dnsengine.certfile/keyfile)
#   -> prints SPKI pin + TLSA 3-1-1

# 3a. PKIX: secondaries trust the CA
#     primaries: { addr: ns1.example.net:853, transport: dot, tls-auth: pkix, ca-file: /etc/tdns/pki/tdns-xot-ca.crt }
# 3b. pin:  secondaries pin the SPKI from step 2 (tls-auth: pin, pins: [<printed>])
# 3c. dane: publish the printed TLSA at _853._tcp.ns1.example.net (tls-auth: dane)

# 4. (optional) mutual TLS: client cert for a secondary
tdns-cli cert leaf --ca …ca.crt --ca-key …ca.key --name ns2.example.net \
    --dns ns2.example.net --client
#   primary: dnsengine.downstream-auth: ca, downstream-ca: /etc/tdns/pki/tdns-xot-ca.crt
```

The same CA output feeds PKIX (`ca-file`), the printed pin feeds pin mode, and
the printed TLSA feeds DANE — one provisioning step, three auth modes.

### 2.5 Security considerations

- **CA private-key custody.** `cert ca` writes a long-lived signing key. Write
  `0600`, print the path and a reminder that it should live offline / access-
  controlled. Do not auto-load it anywhere; it is only read by `cert leaf`/`sign`.
- **Fixed safe constraints.** Hard-code `pathlen:0` on the CA and `IsCA=false`
  on leaves so a leaf can never sign further certs. Do not expose knobs that let
  a user accidentally mint a sub-CA.
- **Scope.** No CRL, no OCSP, no renewal automation, no cert database. It is a
  provisioning convenience for a *private* trust domain, not a general CA. State
  this in `--help` so users do not mistake it for public-PKI tooling.
- **Algorithm default ed25519** — modern, and every TLS 1.3 stack tdns talks to
  supports it; offer ECDSA/RSA for interop with older verifiers.

### 2.6 Testing plan

- Unit: `cert ca` produces a valid self-signed CA (parses, `IsCA`, pathlen 0);
  `cert leaf` produces a leaf that **verifies against the CA** with
  `x509.Certificate.Verify` for the requested SANs and EKUs; `csr`→`sign`
  round-trips and the signed cert matches the CSR's SANs.
- Integration with XoT: generate CA + server leaf, stand up the DoT test primary
  with them, and run a `tls-auth: pkix` transfer (reuse the `feature/xot`
  `startTestAXFRServerTLS` harness) — proving the tool's output actually
  satisfies the verifier. Repeat asserting `--emit-pin` output works under
  `tls-auth: pin` and `--emit-tlsa` output works under `tls-auth: dane`.
- File-permission test: key files are `0600`; overwrite refused without
  `--force`.

### 2.7 Non-goals

- Public-CA features (CRL/OCSP/transparency/renewal).
- A persistent CA database or serial file.
- TLS cipher/protocol tuning knobs (see LE-5).
- Replacing `utils/gen-cert.sh` for the trivial self-signed case.

---

## Suggested PR sequence

1. **In-tool CA** (`tdns-cli cert …`, Part 2) — unblocks LE-1 and is independently
   useful for pin and DANE, so it lands first.
2. **PKIX polish** (LE-2 intermediate handling + LE-7 tests + LE-6 dog docs).
3. **Optional** (LE-3 agent parity test, LE-4 client-identity allowlist) as
   appetite allows.
