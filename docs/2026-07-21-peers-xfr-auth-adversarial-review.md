# Adversarial review: `feature/peers-xfr-auth` (XoT + cert tooling + peers/downstream-auth)

**Date:** 2026-07-21
**Worktree:** `tdns-peers` @ `feature/peers-xfr-auth` (stack tip: #314 → #316 → #318)
**Diff basis:** `origin/main...HEAD` (~50 files / ~5800 insertions)
**Specs read first:** `docs/2026-07-20-xot-implementation-plan.md`,
`docs/2026-07-21-pkix-cert-tooling-design.md`,
`docs/2026-07-21-peers-xfr-auth-design.md` (on `origin/main`),
`docs/2026-07-21-server-error-registry-design.md` (low priority here)
**Method:** design → code → concrete fail scenarios; findings confirmed by
path tracing and failing proof tests in `v2/adversarial_review_proof_test.go`
(`go test . -run TestReview_`).

**Verdict:** Do **not** merge as-is. The transfer-time auth ladder and outbound
XoT verifier look solid in isolation, but config/dynamic wiring has multiple
**fail-open** holes that can defeat a strict `downstream-auth` or silently
downgrade intended XoT to plaintext Do53.

---

## Confirmed findings (most severe first)

### 1. Template transfer-list alias conflict does not quarantine dependent zones — **auth fail-open**

- **Where:** `v2/peers.go:318-320` (conflict recorded under template `name`);
  `v2/parseconfig.go:654-658` (quarantine checks **only** `zconf.Name`)
- **Defect:** Design §4 requires “two spellings of the same field in one
  zone/**template** = config error (quarantine), never silent preference.”
  `NormalizeXfrAliases` records template conflicts, but `ParseZones` never
  looks up the zone’s template name in that map. On conflict the rewrite is
  skipped, **both** keys remain, and mapstructure keeps the canonical key —
  often the broader ACL — while the restrictive alias is ignored.
- **Scenario:**
  ```yaml
  templates:
    - name: served
      downstreams: [{ prefix: 0.0.0.0/0, key: NOKEY }]   # broad
      provide-xfr: [{ prefix: 192.0.2.0/24, key: xfr-key }]  # intended
  zones:
    - name: example.
      template: served
  ```
  Conflict is stored as `served`, zone `example.` is **not** quarantined, and
  unsigned AXFR from any IPv4 source is allowed.
- **Proof:** `TestReview_TemplateAliasConflictQuarantinesDependentZones` (FAIL)
- **Severity:** auth fail-open / ACL open

### 2. Dynamic-zone load path drops `downstream-auth` — **auth fail-open**

- **Where:** `v2/dynamic_zones.go:291-305` (`ZoneRefresher` built without
  `DownstreamAuth`); `v2/dynamic_zones.go:394-408` (`zoneDataToZoneConf`
  never serializes it). Contrast static path `v2/parseconfig.go:1195`.
- **Defect:** Persisted/edited dynamic `ZoneConf` can carry
  `downstream-auth:` (field exists on `ZoneConf`), but load installs only the
  `downstreams` ACL. `authorizeTransfer` then hits the empty-ladder branch
  (`downstream_auth.go:77-80`) and authorizes any ACL match — pre-ladder
  behavior, defeating a persisted `[tls-pkix]` (etc.) policy. Re-persist also
  strips the field.
- **Scenario:** Dynamic primary YAML has
  `downstreams: [{prefix: 192.0.2.0/24, key: NOKEY}]` and
  `downstream-auth: [tls-pkix]`. After `LoadDynamicZoneFiles`, unsigned Do53
  AXFR from that prefix succeeds.
- **Proof:** `TestReview_DynamicZoneRefresherDropsDownstreamAuth` (FAIL)
- **Severity:** auth fail-open (dynamic zones / API-managed primaries)

### 3. `peers:` reference silently discards inline TLS fields — **silent XoT downgrade**

- **Where:** `v2/peers.go:219-238` (`expandPeerList` rejects only `addr`/`key`
  coexistence; copies TLS solely from the peer definition)
- **Defect:** An entry may be reference **or** inline, but TLS knobs on the
  reference entry (`transport`, `tls-auth`, `pins`, `ca-file`, `tls-name`) are
  accepted by decode then thrown away. If the named peer is plain Do53, the
  secondary pulls over plaintext while the operator believes they configured
  pin/DoT on the zone entry.
- **Scenario:**
  ```yaml
  peers:
    primary: { addr: 192.0.2.1:53, keys: [NOKEY] }
  zones:
    - name: example.
      type: secondary
      upstreams:
        - peers: [primary]
          transport: dot
          tls-auth: pin
          pins: ["…"]
  ```
  Expansion yields `{Addr:192.0.2.1:53, Key:NOKEY}` with empty Transport →
  Do53 AXFR, no pin check.
- **Proof:** `TestReview_PeerRefRejectsInlineTLSFields` (FAIL)
- **Severity:** fail-open / confidentiality+integrity downgrade (operator intent)

### 4. Unnormalized `transport: "DoT"` on API/dynamic `PeerConf` → plaintext — **silent XoT downgrade**

- **Where:** `v2/xot.go:50-54,154-157` (`peerUsesDoT` requires exact `"dot"`);
  `v2/dynamic_zones.go:738-756` / API zone add (validates addr+key only — never
  `validatePeerXoT`, which is what lowercases transport on the static path)
- **Defect:** Static config always runs `validatePeerXoT` (normalizes case).
  Programmatic/API/dynamic peers can carry `Transport: "DoT"` / `"DOT"`.
  `ClientTLSConfigForPeer` returns `(nil, nil)`; `ZoneTransferIn` sets
  `transfer.TLS = nil` and dials plain TCP. Configured pins/`tls-auth` are never
  consulted.
- **Scenario:** API `zone add` primary
  `{addr, key, transport:"DoT", tls-auth:"pin", pins:[…]}` → unsigned plaintext
  pull; MITM can impersonate the primary.
- **Proof:** `TestReview_PeerUsesDoTRequiresNormalizedCase` (FAIL)
- **Severity:** fail-open / XoT downgrade (API & dynamic paths)

### 5. dog: verify flags (`+pin`/`+cafile`/`+tlsa`) ignored on Do53; default transport case bug — **client downgrade**

- **Where:** `cmdv2/dog/dog.go:250-267` (AXFR: PlainDo53 → nil TLS, never
  builds verify config); `cmdv2/dog/dog.go:339-370`
  (`transport != "do53"` while default is `"Do53"`)
- **Defect:**
  1. `dog @ns AXFR example. +pin=…` without `+TLS` uses Do53 and **silently
     ignores** the pin (no error, no verify).
  2. Default transport `"Do53"` is **not** equal to `"do53"`, so ordinary Do53
     queries enter the TLS-config branch, emit the “certificate NOT verified”
     warning, and attach an unused `InsecureSkipVerify` config. When verify
     flags **are** present on Do53, a verifying `tls.Config` is built and then
     unused by the Do53 client.
- **Note:** On real DoT (`+TLS` / `tls://`), `+pin`/`+cafile` correctly go
  through `ClientTLSConfigForPeer`; `+tlsa` correctly uses
  `InsecureSkipVerify` **only** with a mandatory `VerifyConnection` DANE gate.
  The bug is the missing “verify flags require encrypted transport” gate, plus
  the case mismatch.
- **Severity:** fail-open for the operator tool (lower than daemon, still real)

### 6. `PublishTlsaRR` subdomain check uses `strings.HasSuffix` — **zone integrity**

- **Where:** `v2/ops_tlsa.go:24-26`
- **Defect:** `notexample.com.` has suffix `example.com.`, so an
  out-of-zone owner is accepted; the TLSA owner
  `_853._tcp.notexample.com.` can be injected into zone `example.com.` via the
  internal update path and later AXFR’d.
- **Scenario:** Control-plane caller
  `PublishTlsaRR("notexample.com.", 853, certPEM)` against zone `example.com.`
  — should reject “not a subdomain”; currently passes the gate (fails only later
  on bad PEM in the proof test).
- **Proof:** `TestReview_PublishTlsaRRRejectsLabelBoundaryCollision` (FAIL)
- **Severity:** correctness / zone pollution (not a remote auth bypass)

### 7. `config check` alias/peer parity gaps — **diagnostic false assurance**

- **Where:** `v2/cli/config_check_cmds.go:320-324` (viper `AllSettings`
  lower-cases keys); daemon `processConfigFile` preserves YAML key case;
  `config_check_cmds.go` never runs `ValidatePeers` / `expandPeerRefs`
- **Defect:**
  1. `Provide-Xfr:` may be normalized and accepted by `config check` while the
     daemon leaves it as an unknown key (dropped). Combined with a broad
     canonical `downstreams:`, this also skips conflict quarantine on the
     daemon.
  2. Unknown/broken peer refs can look “configured” in check while the daemon
     quarantines the zone at expand time.
- **Severity:** correctness / ops false confidence (not runtime bypass by itself)

---

## Areas checked and believed sound

| Area | Why sound |
|---|---|
| **Transfer ladder** (`authorizeTransfer`) | ACL match first; empty list = pre-ladder; `[any]` override; `tls-*` only after match + credentials; `[tls-pkix]` alone refuses Do53/TSIG-only (base mech not in set; no client cert). Covered by `downstream_auth_test.go` matrix + MUSTs. |
| **BLOCKED supersedes** | Scanned before allow matching; blocked entries excluded from `matchedDownstreams`. |
| **`connectionState` + TSIG wrapper** | `tsigSignResponseWriter.Unwrap()` exists; walker reaches fork `ConnectionStater`; DoT harness tests exercise the production wrapper shape. |
| **Listener mTLS policy** | Auth DoT uses `RequestClientCert` only (`do53.go` → `true`); IMR DoT passes `false`. Cert-less ADoT queries still work (`TestDownstreamAuth_MUSTs`). |
| **Outbound pin/DANE gates** | `InsecureSkipVerify` only with non-nil `VerifyConnection`; mismatch/no-cert abort handshake (`xot_test.go`). PKIX uses stdlib verify. Constant-time pin compare. |
| **DANE fail-closed** | No IMR / lookup fail / non-secure (when required) → error. Lab `require_dnssec_validation=false` honored with warning (by design). |
| **Hostname→IP resolution** | `buildUpstreams` preserves/fills `TLSName` for DoT so SNI/DANE base survives. |
| **Fork `Transfer.TLS` + TSIG** | `replace` → `johanix/dns`; TSIG MAC on same TLS `Conn`; `TestXoT_TransferTSIGInsideTLS`. |
| **PKI constraints** | CA `pathlen 0` + `CertSign`; leaves `IsCA=false`, no CertSign; `SignCSR` `CheckSignature` + SAN copy; leaf-as-parent fails verify (`pki_test.go`). API cannot mint a sub-CA. |
| **`VerifyCertAgainstTlsaRR`** | Honors Selector 0/1; MatchingType 1/2; Usage 3 only; fail-closed otherwise. `NewTlsaRR` is true 3-1-1 over SPKI. |
| **Static peer expansion** | After templates; prefix×key cross-product; `TLSIdentity` on downstreams only; unknown/broken peer quarantines zone. |
| **NOKEY-shadow under `[tsig]`** | Hard refusal (`TestDownstreamAuth_NokeyShadowRefusal`). |
| **servererror registry** | Out of adversarial focus; not re-reviewed in depth. |

---

## Unconfirmed suspicions (not elevated to findings)

- **`tls-identity` with IP-only peer and no `name`:** chain-only PKIX (“any cert from this CA”). Documented in design §3; coarse but intentional for a dedicated transfer CA.
- **Leaf `NotAfter` not clamped to CA expiry:** availability/mis-issuance, not auth bypass.
- **Dynamic zones + unexpanded `peers:` refs:** ACL validation may fail closed on bare refs; mixed shapes not fully traced end-to-end.
- **`PublishTlsaRR` blocking send on `UpdateQ`:** hang risk if queue stalled; not security.
- **No combined unit test** of `tsigSignResponseWriter` + `tls-pin` authorize path (integration tests cover DoT+RequestClientCert; unwrap is correct by inspection).

---

## Suggested fix order (for the implementer)

1. Quarantine zones whose **template** appears in `XfrAliasConflicts` (and/or reject conflicting templates at template-load).
2. Thread `DownstreamAuth` through dynamic load + `zoneDataToZoneConf`; call `validateDownstreamAuth` on that path.
3. Reject TLS fields on `peers:` reference entries (same “not both” rule as addr/key); call `validatePeerXoT` on API/dynamic primaries (or casefold in `peerUsesDoT`).
4. dog: require encrypted transport when verify flags are set; compare transports case-insensitively / via `PlainDo53`.
5. Replace `HasSuffix` with DNS label-boundary subdomain check in `PublishTlsaRR`.
6. Align `config check` key casing and peer-ref expansion with the daemon.

Proof tests in `v2/adversarial_review_proof_test.go` should be flipped to positive regressions (or deleted) once the above lands.

---

## How to re-run the proof suite

```bash
export GOROOT=/opt/local/lib/go
export GOMODCACHE=/Users/johani/go/pkg/mod   # or your normal module cache
cd v2 && go test . -count=1 -run 'TestReview_' -v
# Expect FAIL on each TestReview_* until fixed.

# Existing positive coverage (should stay green):
go test . -count=1 -run 'TestPeers_|TestDownstreamAuth_|TestPKI_|TestXoT_|TestTLSA_|TestClientTLS'
```
