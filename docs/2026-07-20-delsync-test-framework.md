# Test framework for delegation-mgmt-via-ddns + keystate (tdns-debug `delsync`)

**Status:** design approved, ready for implementation. Self-contained.
**Targets:** draft-ietf-dnsop-delegation-mgmt-via-ddns-02, draft-berra-dnsop-keystate-03.
**Companion:** `docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md` (the implementation plan this tests).

## 1. Why

The delegation-sync stack is implemented across a branch stack but has had **zero live
validation** — everything so far is unit-tested and `-race` green, which is a weaker claim.
The plan's own test plan calls for an end-to-end parentsync exercise that has never run.

Equally important: this framework exists so **an agent can run the matrix exhaustively**.
Manual human testing does not scale to ~35 stateful cases with reset between each.

## 2. Key architectural finding

**A large fraction of the matrix cannot be tested against a well-behaved parent.**
Testing retry/backoff needs a receiver that goes silent; testing the re-bootstrap bound needs
one that returns BADKEY forever; testing mutual auth (D-7) needs one that returns *forged* and
*unsigned* KeyState responses. A correct `tdns-auth` will never do any of those.

Hence two tiers, and the adversarial tier carries most of the value:

- **Tier 1 — deterministic, no lab.** Real receiver + a scriptable **hostile receiver double**.
  Repeatable, exhaustive, CI-able. ~20 of ~35 cases.
- **Tier 2 — live two-server lab.** Real DNS publication, real DNSSEC chains, the three
  bootstrap methods, real transport, full lifecycle. ~13 cases.

## 3. Testbed abstraction (the seam)

All scenarios are written against `Testbed`, with two providers, so Tier 1 can be built and run
before any lab exists.

```go
// v2/debug/delsync_testbed.go
type Endpoint struct {
    Zone string          // authoritative zone
    DNS  string          // host:port
    Api  *tdns.ApiClient // mgmt API (no curl needed)
    SSH  string          // optional: daemon lifecycle only
}
type Testbed struct {
    Provider      string // "local" | "lab"
    Parent, Child Endpoint
    Imr           string
    Caps          *CapabilityMatrix
}
func LoadTestbed(path string) (*Testbed, error)  // lab provider (YAML)
func StartLocalTestbed(ctx) (*Testbed, error)    // local provider (ephemeral)
func (t *Testbed) Probe(ctx) *CapabilityMatrix   // reuses ProbeApi/ProbeDns
func (t *Testbed) ResetChildKeys(ctx) error      // per-case reset, via mgmt API
func (t *Testbed) Close() error
```

`testbed.yaml` — the only lab-dependent artifact:

```yaml
parent: {zone: parent.example., dns: 119.0.0.21:53, mgmt: https://119.0.0.21:8080, ssh: root@p}
child:  {zone: child.parent.example., dns: 119.0.0.22:53, mgmt: https://119.0.0.22:8080, ssh: root@c}
imr: 119.0.0.20:53
capabilities: [signed-parent, signed-child, pq-algs]
```

Scenarios declare `Requires` capability names and are `Report.Skip`-ed when a provider cannot
offer them (e.g. `dnssec-chain`, `pq-algs`) — reusing the existing `CapabilityMatrix`.

## 4. Test matrix

IDs are stable and used by `--case`.

| ID | Case | Tier |
|----|------|------|
| **A. KeyState protocol** (K-1/2/3/4/5) | | |
| A1 | Inquiry carries QTYPE=KEY; response carries KeyState option | 2 |
| A2 | KEY-STATE in {0,1,3,11,99} → response 0 (KEY_REQUEST_MALFORMED), KEY-ID echoed, KEY-DATA=0 | 1 |
| A3 | Response is SIG(0)-signed by the receiver | 2 |
| A4 | Receiver cannot sign → response carries **no** KeyState option (fail closed) | 1 |
| A5 | State map: trusted→4, absent→5, broken KEY→6, validated&!trusted→10, manual→10, auto→9, store-error→1 | 1 |
| **B. UPDATE auth / rcode+EDE** (D-8) | | |
| B1 | Unknown key → BADKEY(17) + EDE 513 | 1 |
| B2 | Known-but-untrusted key → REFUSED(5) + EDE 514 | 1 |
| B3 | Trusted keytag + corrupted signature → BADSIG(16), **not** treated as trusted | 1 |
| B4 | Signature outside validity window → BADTIME | 1 |
| B5 | Unsigned UPDATE → BADKEY (deliberate conflation with unknown key) | 1 |
| B6 | Valid trusted UPDATE → NOERROR + applied | 1/2 |
| **C. Transport** (D-2a) | | |
| C1 | Small delegation UPDATE is sent over **TCP** | 1 |
| C2 | Large PQ (ML-DSA) SIG(0) UPDATE succeeds | 2 |
| **D. Retry / RCODE handling** (D-2b) | | |
| D1 | Silent parent → ≥5s, exponential backoff, ≤5 attempts, then give up | 1 |
| D2 | BADKEY → one re-bootstrap → retry → success | 1 |
| D3 | BADKEY forever → **exactly one** re-bootstrap, then hard error (no loop) | 1 |
| D4 | Single REFUSED → retry (not a stop signal); repeated REFUSED → bounded give-up | 1 |
| **E. Bootstrap ceremony + deferred DEL** (D-4) | | |
| E1 | Bootstrap UPDATE carries `DEL <child> ANY KEY` + `ADD <child> KEY` on the wire | 1 |
| E2 | New key stored untrusted; existing trusted key **not** removed (DEL deferred) | 1 |
| E3 | New key validates → trusted → old key(s) removed (deferred DEL completes) | 2 |
| E4 | New key never validates → old trusted key retained; deferred DEL never fires | 1 |
| E5 | **Bogus** self-signed DEL+ADD → trusted key retained (non-eviction) | 1 |
| E6 | Bare untrusted `DEL ANY KEY` (no ADD) → refused | 1 |
| E7 | Re-bootstrap after key loss, end-to-end | 2 |
| **F. Bootstrap methods** | | |
| F1 | `at-apex` — KEY at child apex in signed zone → validated → trusted | 2 |
| F2 | `at-ns` — KEY at `_sig0key.{child}._signal.{ns}` in signed zone → validated → trusted | 2 |
| F3 | `unsigned` — unsigned child zone → policy-permitted acceptance | 2 |
| F4 | `manual` — manual policy → key stays untrusted; KeyState reports 10 | 2 |
| **G. Mutual authentication** (D-7) | | |
| G1 | Receiver publishes its KEY at the DSYNC target; child acquires + DNSSEC-validates it | 2 |
| G2 | Child verifies SIG(0) on a KeyState response → accepts | 2 |
| G3 | **Forged** (wrong-key) KeyState response → child rejects | 1 |
| G4 | **Unsigned** response while receiver KEY is obtainable → child rejects | 1 |
| G5 | Receiver KEY not obtainable → accept-with-logged-operator-ack (draft carve-out, default) | 1 |
| G6 | Strict policy knob → the G5 case is rejected instead | 1 |
| **H. End-to-end** | | |
| H1 | Full lifecycle: keygen → publish → bootstrap → trust → inquire → delegation UPDATE → parent applies | 2 |
| H2 | DS / NS / glue delegation change round-trip | 2 |
| H3 | Policy hook invoked from **both** the scanner and the UPDATE path (reduced D-3b) | 1 |

## 5. Primitives (new files in `v2/debug/`)

### `delsync_keystate.go`

Arbitrary-KEY-STATE inquiry with response introspection **including signature verification**
(this is what makes A3/G2/G3/G4 assertable).

```go
type InquiryOpts struct {
    Server, Child string
    KeyID uint16
    KeyState, KeyData uint8   // arbitrary: 99, 0, 1, 3, 11, ...
    Qtype uint16              // default dns.TypeKEY
    Signer *Sig0Signer        // nil => send unsigned
    ReceiverKey *dns.KEY      // to verify the response SIG(0)
    Transport string
}
type InquiryResult struct {
    Rcode string
    OptionPresent bool
    KeyState, KeyData uint8
    KeyID uint16
    ExtraText string
    Signed, SigVerified bool
    Signer string
    EDE *uint16
    Transport string
}
func SendKeyStateInquiry(ctx context.Context, o InquiryOpts) (*InquiryResult, error)
```

### `delsync_update.go`

Crafted UPDATEs; extends the existing `Sig0Signer.Send`.

```go
type UpdateOpts struct {
    Server, Parent, Child string
    Adds, Removes []dns.RR
    DelRRsets []struct{ Name string; Type uint16 } // class ANY (RRset delete)
    Ceremony bool                                   // DEL ANY KEY + ADD KEY
    SignMode string                                 // trusted|unknown|untrusted|none|corrupt
    Inception, Expiration uint32                    // for BADTIME
    Transport string                                // tcp|udp|auto
}
type UpdateResult struct {
    Rcode string
    EDECode *uint16
    EDEText string
    Transport string
    UpdateSection []string   // rendered RRs — asserts DEL+ADD on the wire (E1)
    Elapsed time.Duration
}
func SendCraftedUpdate(ctx context.Context, o UpdateOpts) (*UpdateResult, error)
```

### `delsync_truststore.go`

Deterministic receiver-state control through the mgmt API (`tdns.ApiClient`), no curl:

```go
type ChildKeyState struct {
    Child, KeyRR string
    KeyID uint16
    Validated, DnssecValidated, Trusted bool
}
func ListChildKeys(ctx, api) ([]ChildKeyState, error)
func SetChildKey(ctx, api, ChildKeyState) error
func DeleteChildKey(ctx, api, child string, keyid uint16) error
func ResetChildKeys(ctx, api, child string) error
```

## 6. `delsync_double.go` — the adversarial receiver

The highest-value new piece. A scriptable fake UPDATE Receiver / KeyState responder. Without
it D1–D4 and G3–G4 are untestable.

```yaml
# double-script.yaml — rules matched per request, in order
rules:
  - match: {opcode: UPDATE}
    respond: {rcode: BADKEY}
    times: 1
  - match: {opcode: UPDATE}
    respond: {rcode: NOERROR}
  - match: {opcode: QUERY, keystate: true}
    respond: {keystate: 4, sign: wrong-key}   # forgery -> G3
```

- `respond.drop: true` — silence, for the retry/backoff cases (D1).
- `respond.sign` — `correct | none | wrong-key`.
- `respond.delay_ms` — latency injection.
- `times` — 0 means unlimited.

Every request is journaled; **the journal is what assertions read**:

```go
type DoubleJournalEntry struct {
    At time.Time
    Transport, Opcode, Qname, Signer string
    KeyID uint16
    UpdateSection []string
    RespondedRcode string
    Dropped bool
}
type Double struct{ /* ... */ }
func StartDouble(ctx context.Context, listen string, script DoubleScript, signer *Sig0Signer) (*Double, error)
func (d *Double) Journal() []DoubleJournalEntry
func (d *Double) Close() error
```

Assertions derived from the journal: retry intervals and attempt count (D1), **exactly one
re-bootstrap** (D3 — count UPDATEs whose Update section is a DEL+ADD ceremony), transport (C1).

## 7. Scenario registry + runner

```go
type Scenario struct {
    ID, Title string      // matrix IDs: "A2", "D3", ...
    Tier int
    Requires []string     // capability names
    Run func(ctx context.Context, tb *Testbed, rep *Report) error
}
var DelsyncScenarios = []Scenario{ /* the matrix */ }
func RunScenarios(ctx context.Context, tb *Testbed, ids []string, rep *Report) error
```

Each case: **reset → act (primitive) → assert via `rep.Violate(...)` → cleanup.**
Registered into the existing `list-tests`; failures surface via the existing `Report.ExitCode()`.

## 8. CLI surface (`cmdv2/debug/cmds.go`)

```
tdns-debug test delsync run --local|--testbed f.yaml [--case A2|--tier 1|all] --json
tdns-debug delsync keystate  --server ... --child ... --state 99 --json
tdns-debug delsync update    --server ... --ceremony --sign-mode untrusted --json
tdns-debug delsync truststore list|set|reset --json
tdns-debug delsync double    --listen 127.0.0.1:5354 --script s.yaml --journal j.json
tdns-debug delsync testbed   up --local | probe --testbed f.yaml
```

## 9. Reuse map — extend, do not reinvent

| Need | Existing tdns-debug piece |
|------|---------------------------|
| Assertions / failure reporting | `Report.Violate/Skip/Stat`, `ExitCode`, `RenderJSON` (`report.go`) |
| Capability gating and principled skips | `CapabilityMatrix`, `ProbeApi`, `ProbeDns` (`capabilities.go`) |
| SIG(0)-signed UPDATE sending | `Sig0Signer` / `LoadSig0Signer` / `Send` (`dnsclient.go`) |
| Mgmt API access (no curl) | `tdns.ApiClient` |
| Per-test provisioning + cleanup | `State`, `TestRecord` (`state.go`), existing `cleanup` command |
| Test listing | existing `list-tests` command |
| Streaming invariant checks (pattern) | `Checker` (`checkers.go`) |

## 10. Implementation order (parallel-safe)

| Step | Content | Needs lab? |
|------|---------|-----------|
| 1 | Scenario registry + `Report` wiring + the three primitives + **the double** | No |
| 2 | `testbed local` (ephemeral parent+child) → run Tier 1 (~20 cases) | No |
| 3 | `testbed lab` (YAML provider) → run Tier 2 (~13 cases) | Yes |

**Risk (flagged, not hidden):** Step 2 requires spawning a real `tdns-auth` locally, which means
templating config + zones + keystore and dealing with the `make`/genalgs build flow.
`provision.go` / `provision_reload.go` give precedent. If it proves fiddly, the fallback is a
library-level in-process receiver for the receiver-side cases — same scenarios, less realism.
Discover this early rather than promising it.

## 11. Lab requirements (provided separately)

1. Two nameservers (parent + child) reachable from the agent sandbox — public address space,
   not RFC1918 (the sandbox cannot reach RFC1918).
2. ssh access allowlisted for the agent (the agent cannot see approval prompts; an unattended
   matrix run stalls silently without it). `dig`/`dog` likewise.
3. A disposable parent zone + child delegation that may be freely mutated and re-signed;
   DNSSEC-signed parent for the `at-apex`/`at-ns` methods; a reachable IMR for validation.
4. A reset primitive: wipe truststore/KeyDB and restart `tdns-auth` on both boxes between cases.

## 12. Working rules

- Build/test: `GOROOT=/opt/local/lib/go CGO_ENABLED=1`; `go vet` + `go test -race` green.
  `v2/` and `v2/debug` are separate Go modules — run commands inside each module directory.
  Building the `cmdv2/*` apps uses `make`, not bare `go build`.
- GPG-sign every commit (`-S`); no `Co-Authored-By` or AI/tool byline.
- Design-note-first for each substantial step; implement → commit → push → open PR → stop.
