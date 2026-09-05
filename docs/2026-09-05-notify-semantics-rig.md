# The notify-semantics rig — one inbound change, how many outbound changes? (relay rig)

**Status:** design agreed; R1–R4 (the `v2/debug/peer` library) implemented 2026-09-05, R5–R6 outstanding. Not on a branch yet — the working tree is on `fix/csync-publisher-484-506`, which is unrelated.
**Base:** `main` @ `d833c683` (read on `fix/csync-publisher-484-506`, which does not touch any
of this).
**Scope of the first cut:** the SUT is an **inline-signing secondary that re-serves**. The
mirroring-secondary control and the `outbound-soa-serial` sweep are deliberately out (§10).
**Related:** [2026-09-05-refresh-engine-redesign-364-502.md](2026-09-05-refresh-engine-redesign-364-502.md)
§1.4 documents the two drifted post-refresh bodies. This document is about a different
axis — how many times one inbound change is *published and announced* — which that redesign
does not address and, as written, does not fix.

---

## 0. Summary

We cannot agree on the semantics of refresh → sign → publish → serial-bump → notify because
nothing measures them. This document specifies (§3) what the correct semantics are, argues
from the code (§2) what the current semantics actually are, and designs the rig (§4–§8) that
tells the two apart.

The rig is a **sandwich**: it plays the upstream primary on one side of the SUT and the
downstream secondary on the other, so it authors every change and observes every consequence,
with no third-party daemon in the loop and nothing inferred from logs.

**The predicted result, derived in §2.3:** on today's code, one inbound change to an
inline-signing secondary produces **four outbound NOTIFYs and three SOA serial increments**.
If that is what the rig reports on first run, the rig is working and the semantics need
fixing. It is stated here as a falsifiable prediction precisely so that a first run which
reports something else is informative rather than confusing.

---

## 1. The question

A tdns-auth in the middle of a chain — secondary to someone, primary to someone else,
signing what passes through — must answer:

> For **one** change made upstream, how many times does the zone we serve change, what serial
> does each of those states carry, and how many NOTIFYs do our downstreams get?

The intended answer is **one, one, one**. Every extra published state is a state a downstream
can and will transfer, so an N-fold amplification here is an N-fold amplification of transfer
load at every level below, and each intermediate state is a serial that some downstream is
now pinned to.

Four sub-questions, matching the brief:

- **(a)** Can we author a change upstream, NOTIFY the SUT, and serve it the AXFR/IXFR it asks
  for?
- **(b)** Can we receive the SUT's outbound NOTIFYs and transfer the result back?
- **(c)** Does the change that comes out the far side equal the change that went in the near
  side, modulo the DNSSEC records that must change?
- **(d)** How many NOTIFYs, at what serials, per inbound change?

(d) is the one the design hinges on. (a)–(c) exist to make (d) trustworthy: a NOTIFY count is
only interesting if we know the content was right, and content is only checkable if we
authored it.

---

## 2. What the code does today

### 2.1 The inbound path

An inbound NOTIFY(SOA) for a zone the SUT is secondary for:

1. `do53.go:417` routes it to `DnsNotifyQ`.
2. `NotifyResponder` ([notifyresponder.go:315](../v2/notifyresponder.go)) authorizes it
   (`allow-notify` + TSIG), then sends a bare `ZoneRefresher{Name, ZoneStore, Edns0Options}`
   on `zonech` — no `Force`, no `Response`.
3. `RefreshEngine` picks it up on `zonerefch` and takes the **async operator path**
   ([refreshengine.go:841](../v2/refreshengine.go)) — `go func(...)` per request.

So a NOTIFY-driven refresh runs the `:841` body, not the ticker body at `:1180`. That matters
because the two have drifted (redesign doc §1.4) and only one of them is on this path.

### 2.2 Every publish notifies

`publishWorkingSetLocked` ([zone_mutation.go:353](../v2/zone_mutation.go)) ends, at `:601`,
with an unconditional

```go
_ = zd.NotifyDownstreams()
```

and `NotifyDownstreams` ([zone_utils.go:1370](../v2/zone_utils.go)) loops over `zd.Notify`
doing a synchronous `dns.Exchange` per target. This is the site that is easy to miss when
reasoning about "where do we notify from", because it is not in the refresh engine at all.
Three consequences:

- **every** publish announces, whatever caused it;
- the announcement happens **under `zd.mu`** — publish runs locked — so an unresponsive
  downstream holds the zone lock for `2s × targets`;
- `publishLocked` ([zone_mutation.go:346](../v2/zone_mutation.go)) calls
  `publishWorkingSetLocked(gen, **true**)` — **every** publish through that door also
  **bumps the serial**.

### 2.3 The chain, for an inline-signing secondary

`zoneMayOriginateContent` ([zone_origination.go:42](../v2/zone_origination.go)) returns true
for `ZoneType == Primary || Options[OptInlineSigning]`. So an inline-signing secondary is *not*
under MUST-NOT-MODIFY: it advances the serial in its own space. Tracing one inbound change,
with `S` the serial the SUT was serving before it:

| # | site | what it does | serial after | NOTIFY? |
|---|---|---|---|---|
| 1 | `applyRefreshReplacementLocked` `default:` branch ([zone_mutation.go:676](../v2/zone_mutation.go)) | `CurrentSerial = next + 1`, then `publishWorkingSetLocked(gen, **false**)` | `S+1` | **yes** — content as transferred, upstream's RRSIGs or none |
| 2 | `SetupZoneSigning` → `SignZone(kdb, false)` → `publishLocked` ([sign.go:969](../v2/sign.go)) | signs, publishes **with bump** | `S+2` | **yes** — first locally-signed state |
| 3 | `SetupZoneSigning` also does `resignq <- zd` ([zone_utils.go:2018](../v2/zone_utils.go)); `ResignerEngine`'s `resignNow` force-re-signs → `SignZone(kdb, **true**)` → `publishLocked` | re-signs everything, publishes **with bump** | `S+3` | **yes** — same content, fresh RRSIG inceptions |
| 4 | `refreshengine.go:912` — `conf.Internal.NotifyQ <- NotifyRequest{...}` | announces only | `S+3` | **yes** — duplicate of #3's serial |

**Four NOTIFYs, three serial increments, one inbound change.** Every one of the four goes to
the same `zd.Notify` target set.

Two of these are worth naming individually, because they are separate defects that happen to
compound:

- **#3 is a redundant re-sign.** `SetupZoneSigning` signs the zone and *then* hands it to the
  resigner, whose `resignNow` immediately force-signs it again. `force=true` bypasses the
  `NeedsResigning` short-circuit, so the second pass rewrites every RRSIG the first pass just
  wrote. The comment at [resigner.go:41](../v2/resigner.go) explains why `resignNow` must
  force — a post-rollover zone has valid signatures from the wrong key — but the refresh path
  reaches it having *already* signed, which is not that case.
- **#1 publishes unsigned content on a signed zone.** A downstream that transfers on NOTIFY #1
  gets serial `S+1` carrying whatever RRSIGs came off the wire — for a zone signed *here*,
  that means none. It is a correct-serial, valid-transfer, BOGUS-to-a-validator state, and it
  is served until #2 lands. The window is small and entirely real.

### 2.4 The NOTIFY carries no serial

`m.SetNotify(zone)` (miekg `defaults.go:44`) sets opcode, `Authoritative`, and a single
question `<zone> SOA`. It does **not** put the SOA in the answer section, which RFC 1996 §3.7
permits and which BIND does. So a downstream cannot tell two of these four apart without
probing.

This is a design constraint on the rig (§5.3 — the downstream peer must SOA-probe on every
NOTIFY receipt, and that probe races the next publish). It is also a finding in its own right:
carrying the SOA would let a downstream drop NOTIFY #4 as a duplicate of #3 without a round
trip.

### 2.5 What the redesign does and does not change

The refresh-engine redesign moves `NotifyDownstreams()` off the engine goroutine and onto
`queueNotify`, and unifies the two refresh bodies. That removes the *stall*. It does not
change the *count*: #1, #2 and #3 are in the publish and signing paths, which the redesign
does not touch, and #4 becomes `queueNotify` instead of a direct `NotifyQ` send. **The rig
should therefore report the same count before and after that work** — which makes it a useful
regression guard across it, and means fixing the count is a separate change with a separate
argument.

---

## 3. The oracle

The rig needs a definition of correct that a checker can evaluate. These are proposed, not
established — settling them is half the point of writing this down.

**N1 — one published state per inbound change.** For one upstream change, the SUT publishes
exactly one new zone state. Downstreams see the serial advance exactly once.

**N2 — one NOTIFY per published state.** Each published state produces exactly one NOTIFY per
configured downstream target. Not zero (a downstream that missed it waits a full REFRESH), not
two.

**N3 — never announce a state that is not final.** A NOTIFY implies the announced state is
servable and correct. For a signing zone that means signed: no NOTIFY may precede the signing
of the content it announces. (This is the invariant #1 in §2.3 violates.)

**N4 — content equality modulo DNSSEC.** With RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, CDS,
CDNSKEY and ZONEMD removed, and the apex SOA compared on every field except SERIAL, the zone
the SUT serves is byte-identical to the zone the upstream serves. This is (c), stated as an
equality over the whole zone rather than over the change, so that an error which compounds
across a series is caught at the end of the series.

**N5 — the delta expresses the change.** The IXFR the SUT hands a downstream, with DNSSEC
records removed, contains exactly the RRs the rig added and removed upstream — no more. This
is (c) stated over the change rather than the zone, and it is the sharper of the two: N4 passes
if the SUT reaches the right state by AXFR-ing everything, N5 does not.

**N6 — the signed state is self-consistent.** Every non-DNSSEC RRset in the served zone has an
RRSIG by a DNSKEY published in that same zone state, and the NSEC chain is closed (every owner
in the chain reachable, `next` fields forming one cycle). Cheap for the rig, because it holds
the whole zone anyway, and it is what makes N3's "servable and correct" mean something.

**Where N1 and N2 might reasonably be relaxed:** if the SUT deliberately coalesces — publish
cadence, `PublishCadence` — then several *upstream* changes may legitimately collapse into one
published state. That is a violation of neither invariant as stated (they are per-change in one
direction only: one change may not become many states). The rig's quiescent-round mode (§5.4)
keeps the two apart by making one change at a time and waiting.

---

## 4. Where the rig lives, and why

**Decision: `cmdv2/debug` (tdns-debug), as a new test family `test relay`, with a new
`v2/debug/peer` package supplying the server side.**

The reasoning, and what was rejected:

**`tests/ixfr-interop` (shell + real BIND) — rejected.** It answers a genuinely different
question well: does a *foreign* implementation accept what we emit, and does a long series
converge byte-for-byte. It cannot answer (d). Counting NOTIFYs there means either grepping
BIND's log (which tells you what BIND decided to do about them, not how many arrived) or
running a packet capture. Correlating each NOTIFY to a serial means a timed SOA probe, which
is a program, not a shell loop. And BIND-as-downstream will silently suppress a redundant
NOTIFY, which is exactly the observation we need to keep.

**A new standalone harness — rejected.** It would duplicate the report/violation/skip/JSON
plumbing, the capability gating, the SIG(0) and transfer clients, and the state-directory
provisioning that tdns-debug already has, for no gain.

**tdns-debug — chosen, but it needs a new organ.** The framework is today a pure *client*:
actors poll and probe, a ledger models correct server states, checkers consult it. The relay
family needs the rig to *be a server on both sides* — an authoritative zone with a journal
that answers AXFR and IXFR, and a NOTIFY listener. That is a new package, not a new actor. But
everything above it (report, verdict, JSON, capability gating, per-test state dir) is reused
unchanged, and the framework's own README says it is expected to grow this way.

**Plus a thin seeder in `tests/notify-semantics/`.** Provisioning the SUT — a signed secondary
whose primary is the rig and whose only notify target is the rig — is config generation, which
`tests/*/setup.sh` already does well, and CLAUDE.md's "testing on NetBSD VMs" means the rig
must also be pointable at a tdns-auth someone else started. So: `--sut` addresses always; the
seeder is a convenience for the local case, not a dependency.

---

## 5. Design

### 5.1 Topology

```
   ┌──────────────────────────── tdns-debug test relay ────────────────────────────┐
   │                                                                               │
   │   upstream peer                                          downstream peer      │
   │   (authoritative + journal)                              (NOTIFY listener)    │
   │   127.0.0.1:5361                                         127.0.0.1:5362       │
   └───────┬───────────────────────────────────────────────────────▲───────────────┘
           │ (1) author change, NOTIFY ──►                         │
           │ (2) ◄── SOA probe, IXFR/AXFR                          │ (3) NOTIFY ──►
           │                                                       │ (4) ◄── SOA, IXFR/AXFR
           ▼                                                       │
   ┌───────────────────────────────────────────────────────────────┴───────────────┐
   │  SUT: tdns-auth   127.0.0.1:5360                                              │
   │  zone relay.test.  type: secondary                                            │
   │    primaries:   [127.0.0.1:5361]   allow-notify: [127.0.0.1/32]               │
   │    notify:      [127.0.0.1:5362]   downstreams:  [127.0.0.1/32]               │
   │    options:     [inline-signing]   dnssecpolicy: relay                        │
   └───────────────────────────────────────────────────────────────────────────────┘
```

One process (the rig) holds both peers, so the correlation between "the change I made" and
"the NOTIFY I received" needs no clock synchronisation and no log parsing.

### 5.2 The upstream peer

A `dns.Server` (UDP + TCP) authoritative for the test zone, holding an ordered list of
**versions**. Each version is a full zone map plus the delta from its predecessor.

- `SOA` query → current version's SOA.
- `AXFR` → current version, streamed.
- `IXFR` with a known serial → the concatenated deltas from that serial forward, in RFC 1995
  form; with an unknown or too-old serial → AXFR fallback, **recorded** as a fallback.
- `Change(spec)` → build version *n+1* by applying an add/remove set, bump the SOA serial,
  append, then send NOTIFY(SOA) to the SUT and record the response rcode.

The version list is the rig's own ledger of ground truth for N4/N5. It is capped (default 32
versions) so a long run does not grow without bound; the cap is also what lets us exercise the
too-old-serial AXFR fallback deliberately.

The change specs are drawn from a seeded generator so a run is reproducible: `--seed` already
exists in the framework and means the same thing here. The default mix is add-a-name,
delete-a-name, replace-an-RRset, add-a-second-RR-to-an-existing-RRset — the fourth because it
is the case where an IXFR delta must carry both a removal and an addition for one owner/type.

### 5.3 The downstream peer

A `dns.Server` accepting NOTIFY for the test zone. On each NOTIFY it appends an observation:

```go
type notifyObs struct {
    Seq        int           // arrival order
    At         time.Time
    From       netip.AddrPort
    Answered   int           // rcode we returned
    ProbeAt    time.Time     // when we SOA-probed the SUT
    ProbeSerial uint32       // what the SUT was serving then
    ProbeErr   error
}
```

Because the NOTIFY carries no SOA (§2.4), `ProbeSerial` is a probe, not a read, and it races
the SUT's next publish. The rig handles that honestly rather than pretending otherwise:

- the probe is issued immediately on receipt, before writing the NOTIFY response;
- a NOTIFY whose probe lands on a serial *later* than the one a subsequent NOTIFY's probe
  reports is flagged as **race-collapsed**, not silently merged;
- the count of NOTIFYs is always exact (it is a packet count); only the serial attribution
  can be uncertain, and when it is, the rig says so.

The peer then transfers: IXFR from its last-known serial (falling back to AXFR on the SUT's
say-so), recording the request form, the response form, the deltas, and the resulting zone.

**The downstream peer answers NOTIFY promptly by default**, but takes a `--downstream-delay`
so the lock-holding hazard in §2.2 can be provoked deliberately. Not part of the first cut's
verdict; the knob is one line and the hazard is real.

### 5.4 Rounds and quiescence

The unit of measurement is a **round**:

1. Record the SUT's current serial and zone (baseline).
2. Author one change upstream; NOTIFY the SUT.
3. Collect every observation until **quiescence**: no NOTIFY received and no SUT serial change
   for `--settle` (default 10s).
4. Evaluate the invariants over that round's observations.
5. Repeat for `--rounds` (default 12).

Quiescent rounds are what make N1/N2 decidable: with changes in flight the question "how many
states did *this* change produce" has no answer. A burst mode — several changes without
waiting, to test coalescing — is a natural second family and is explicitly not in the first
cut (§10).

Rounds where the round window is entered while the SUT is still settling from the previous one
are marked **tainted** and excluded from the verdict rather than counted as violations.

### 5.5 The correlation record

The whole run reduces to one table, which is also the JSON output:

| field | source |
|---|---|
| `round` | loop counter |
| `upstream_serial` | version the rig published |
| `change` | the add/remove set, as text |
| `notifies` | count received in the round window |
| `serials` | probed serial per NOTIFY, in arrival order |
| `distinct_serials` | how many distinct states the SUT published |
| `transfers` | per transfer: requested form, answered form, delta size |
| `axfr_fallbacks` | count |
| `content_equal` | N4 verdict |
| `delta_equal` | N5 verdict |
| `dnssec_consistent` | N6 verdict |
| `unsigned_states` | states announced before signing (N3) |
| `tainted` | round overlapped the previous one |

A human reads the table; the checker reads the same fields. There is no third representation.

---

## 6. The verdict

| invariant | how it is decided |
|---|---|
| N1 | `distinct_serials == 1` |
| N2 | `notifies == distinct_serials` |
| N3 | `unsigned_states == 0` — for each distinct serial the downstream transferred, did the zone at that serial carry a complete RRSIG set? |
| N4 | canonical compare of upstream version *n* and the SUT's final state, both stripped of DNSSEC types, SOA compared without SERIAL |
| N5 | the union of the round's IXFR deltas, DNSSEC-stripped, equals the round's change spec |
| N6 | every non-DNSSEC RRset has an RRSIG by a published DNSKEY; NSEC chain closed |

**Section 0 first, as in `tests/ixfr-interop`.** Before any round runs, the rig proves its own
comparators discriminate: it compares two deliberately different zones and requires N4 to fail,
compares a delta against the wrong change spec and requires N5 to fail, and strips one RRSIG
and requires N6 to fail. A comparator that cannot report a difference makes every PASS below it
worthless, and this rig's whole value is in its PASSes and counts.

Exit codes follow the framework: `0` clean, `1` violations, `2` setup error.

---

## 7. What the rig assumes of the SUT

```yaml
dnssec:
   policies:
      relay:
         algorithm:  ED25519
         ksk:  { lifetime: forever }
         zsk:  { lifetime: forever }
         csk:  { lifetime: none }
         sigvalidity: { default: 14d, dnskey: 30d, ds: 14d }

zones:
   - name:      relay.test.
     type:      secondary
     store:     map
     options:   [ inline-signing ]
     dnssecpolicy: relay
     primaries:
        - addr: "127.0.0.1:5361"
          key:  NOKEY
     allow-notify:
        - prefix: "127.0.0.1/32"
          key:    NOKEY
     notify:
        - addr: "127.0.0.1:5362"
          key:  NOKEY
     downstreams:
        - prefix: "127.0.0.1/32"
          key:    NOKEY
```

`inline-signing` is what puts the zone on the may-originate side of
`zoneMayOriginateContent`, which is what makes §2.3's chain the one under test. `NOKEY`
throughout: TSIG is orthogonal to this question and `tests/xot-interop` already covers transfer
auth.

The rig requires **no management API**. It drives the SUT entirely through DNS — NOTIFY in,
transfer out — which is what lets the same run be pointed at a tdns-auth on a NetBSD VM with
nothing but two ports reachable. The API is used only if present, for `zone desc` readback of
`EffectiveOutboundSoaSerial` and applied policy, and is reported SKIPPED when absent, per the
framework's existing capability rule.

---

## 8. CLI surface

```
tdns-debug test relay --sut 127.0.0.1:5360 --zone relay.test. \
    [--upstream-listen 127.0.0.1:5361] [--downstream-listen 127.0.0.1:5362] \
    [--rounds 12] [--settle 10s] [--seed 1] [--json] [--downstream-delay 0s]

tdns-debug test relay --generate-config --zone relay.test.
```

`--generate-config` emits the §7 zone block, the zone file for version 0, and the operator
to-do — matching what `test churn --generate-config` already does, and for the same reason:
the rig never touches the SUT's config itself.

`tests/notify-semantics/setup.sh` + `run.sh` seed and start a local SUT for the development
case, following `tests/ixfr-interop` exactly.

---

## 9. Implementation plan

Six commits, each separately reviewable and revertable. **R1–R4 are implemented**
(2026-09-05); R5–R6 are not.

| # | commit | files | status | lines (prod / test) |
|---|---|---|---|---|
| R1 | zone versions + delta model + canonical compare | `peer/versions.go`, `peer/compare.go` | **done** | 556 / 478 |
| R2 | upstream peer: SOA/AXFR/IXFR server + NOTIFY sender | `peer/upstream.go`, `peer/ixfr.go`, `peer/listen.go` | **done** | 499 / 414 |
| R3 | downstream peer: NOTIFY listener + SOA probe + transfer client | `peer/downstream.go` | **done** | 364 / 255 |
| R4 | DNSSEC checks: strip, RRSIG coverage, NSEC chain closure | `peer/dnssec.go` | **done** | 316 / 242 |
| R5 | the `relay` family: rounds, quiescence, correlation, verdict, Section 0 | `v2/debug/relay.go` | todo | ~380 / ~260 |
| R6 | `tdns-debug test relay` command + `tests/notify-semantics/` seeder | `cmdv2/debug/cmds.go`, `tests/notify-semantics/*` | todo | ~120 / — |

**Landed so far: 1735 production lines, 1389 test lines** in `v2/debug/peer`. 41 tests,
`go vet` and `staticcheck` clean, race-clean.

The unit tests matter more than usual here: a rig whose comparators are wrong reports
confident nonsense, so every comparator in R1–R4 lands with a test that proves it **fails**
on a planted difference, not only that it passes on identical input —
`TestCompareContentDetectsPlantedDifferences`, `TestCompareDeltaDetectsPlantedDifferences`,
`TestCheckSigningDetectsPlantedDefects`, `TestParseTransferRejectsMalformedStreams`. Section
0 (§6) is the same discipline applied at runtime.

R1–R4 are pure library code with no daemon in the loop. They are nonetheless tested end to
end, because the upstream peer is a complete authoritative server and can therefore stand in
for the SUT: `startPair` in `downstream_test.go` wires the downstream peer to the upstream
peer and drives change → NOTIFY → probe → IXFR → delta-application → content comparison with
nothing else running. That is the only configuration in which the rig's two halves can be
held to a known-correct counterpart, and it is what makes an R5 failure attributable to the
SUT rather than to the instrument.

### 9.1 Deviations from the plan above

- **`peer/ixfr.go` was not in the plan.** The IXFR stream parser is the inverse of the
  upstream peer's emitter and is needed by the downstream peer, so it is its own file rather
  than being duplicated on both sides. It also carries `TransferKind`, which is what keeps an
  AXFR that was *asked for* distinct from one that arrived because the server would not answer
  incrementally — the same bytes, and very different findings.
- **`peer/listen.go` was not in the plan.** A peer must answer on UDP and TCP at ONE address.
  Binding TCP and reusing its port for UDP races with anything else claiming that ephemeral
  port, which showed up immediately as a flaky test. `bindPair` retries with a fresh port when
  the address is `:0`, and fails at once when the port was given explicitly.
- **The downstream peer rebuilds its zone from the deltas** rather than re-AXFRing after each
  NOTIFY. Deliberate: a delta that does not say what it should then shows up as content drift
  (N4) instead of being papered over by a whole-zone refetch.
- **The downstream peer transfers once per NOTIFY** rather than coalescing as a real secondary
  would. Coalescing is correct behaviour and wrong instrumentation: an intermediate published
  state that no transfer observed is a state the rig cannot report on.

### 9.2 What R4 does and does not check

Signature **presence and attribution**, never cryptography: every RRset that must be signed
carries an RRSIG naming a key (keytag + algorithm) the zone itself publishes, no RRSIG is left
behind by a withdrawn RRset, and the NSEC chain closes in one cycle from the apex covering
every authoritative name. It does not verify a signature — that needs the algorithm
implementations tdns-debug deliberately does not link. This is enough for N3, because the
failure being hunted (a state announced before it was signed) is a presence failure. NSEC3 and
black-lies zones report the chain check as SKIPPED, never as a pass.

**Verification of the whole thing, once R5 lands:** run it against `main`, expect §2.3's
four-and-three. Then plant a deliberate regression — comment out the `resignq <- zd` handoff in
`SetupZoneSigning` — and confirm the count drops to three-and-two. A rig that cannot see a
change it was built to see is not yet finished.

---

## 10. Deliberately not in the first cut

- **The mirroring-secondary control** (no `inline-signing`). Expected behaviour is simpler —
  MUST-NOT-MODIFY, serial mirrors upstream, one publish — and it would tell us whether a 1:1
  break is in the signing path or below it. Worth having; a second profile, not a second rig.
- **The `outbound-soa-serial` sweep** (`keep` | `unixtime` | `persist`). Each rewrites the
  serial at a different point, so each gives a different expected downstream serial for one
  inbound change. The rig's structure takes it as a flag when we want it.
- **Burst mode** — several upstream changes without waiting, to test deliberate coalescing.
  A different question from this one (§5.4) and it needs its own oracle.
- **The lock-holding hazard** — a slow downstream stalling `zd.mu` because
  `NotifyDownstreams` runs under it (§2.2). The `--downstream-delay` knob provokes it; turning
  that into a verdict needs a concurrent query actor and a latency threshold, which is the
  churn family's machinery, not this one's.
- **TSIG on any hop.** Orthogonal; `tests/xot-interop` covers transfer auth.
- **Fixing anything.** This document specifies the instrument. What §2.3 measures is a defect
  in at least three places, and each wants its own issue and its own argument.
