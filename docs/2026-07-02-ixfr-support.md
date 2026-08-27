# Project C — IXFR Support (RFC 1995)

**Status:** FIRMED UP 2026-07-24 (was: design sketch deferred until Project B landed).
Project B (#279) and Project A are both DONE on main; this doc now reflects the
**verified** state of main @ 7885f23 and the concrete plan being implemented on
`feature/ixfr-support`.
**Scope implemented:** outbound delta-IXFR = C1-lite (per-publish delta retention
into the byte-bounded `IxfrChain`) + C3 (outbound IXFR serving). See §6 for what
is deliberately deferred (inbound IXFR / C2, the POP-style downstream tracker,
condensation).
**Date:** 2026-07-02 (sketch), 2026-07-24 (firm-up)

---

## 1. Verified state of main (2026-07-24)

What the 2026-07-02 sketch guessed at is now checked against code:

* `Ixfr{FromSerial,ToSerial uint32; Removed,Added []core.RRset}` (structs.go)
  and `ZoneData.IxfrChain []Ixfr` exist; `zoneSnapshot.IxfrChain` is copied on
  every publish via `copyIxfrChain` (zone_mutation.go `buildSnapshotLocked`).
  **Nothing ever appends to the chain — it is always empty on main.** There is
  no delta history to serve from; retention must be built (this project).
* `publish()` does NOT compute an RR-level delta. The only diffing on main is
  `pendingChanges()` (B2 observability): owner/type-level, on-demand, not
  retained.
* **The delta IS cheaply computable at publish time.** Post-B3, the working set
  is seeded from the published snapshot **sharing `*OwnerData` pointers**
  (`ensureWorkingSet`), and every mutator goes through `cloneOwner` /
  `stageOwnerReplaceLocked`, which swap in a fresh pointer. Therefore
  changed owners == owners whose pointer differs between the old snapshot's
  `Data` and the new working set. The diff is O(#owners) pointer compares plus
  RR-level comparison only on changed owners. This is the load-bearing fact
  that makes delta retention affordable on the publish hot path.
* `ZoneTransferOut` (dnsutils.go) already: runs the complete transfer-out
  authorization gate (`authorizeTransfer`: downstreams ACL + downstream-auth
  mechanism ladder, XoT-aware), pins ONE snapshot for the whole transfer (M1),
  fail-closes on unsigned must-be-signed zones, and streams through the
  Project-A envelope batcher (`batchState`, `appendRRset`, 64000-byte safe
  cap, oversize-RRset abort). IXFR queries are dispatched to it
  (queryresponder.go) but the client serial is ignored and a full AXFR-shaped
  response is served — which is already the RFC 1995 §4 fallback, so the
  baseline on main is compliant-but-never-incremental.
* The johanix/dns fork (v1.1.72-johanix.2) `Transfer.Out` writes envelopes
  verbatim (Answer := envelope RRs) with TSIG continuation; `Transfer.In`'s
  `inIxfr` gives the exact client-side framing contract (see §4.2).
* Publishes that change content WITHOUT bumping the serial exist on main:
  catalog version-TXT injection (apihandler_catalog.go), transport-signal
  commits (tsignal.go), `RepopulateDynamicRRs` (zone_utils.go). Publishes that
  bump the serial without changing content also exist
  (outbound-soa-serial=unixtime/persist restore, refreshengine.go). Both must
  be handled by retention (§4.1).
* Wholesale zone replacement on the SAME `ZoneData` happens only in
  `applyRefreshReplacementLocked` (refresh/AXFR-in/reload). `ModifyDynamicZone`
  replaces the whole `ZoneData` object, so its chain resets for free.
  `InstallInitialSnapshot` re-baselines from `zd.Data`.

## 2. Scope decision (owner AFK — decided and documented)

**Implement real outbound delta-IXFR now**, not just the fallback baseline:

* The mission fork was "(i) real deltas if the snapshot chain gives enough
  history, (ii) otherwise fallback baseline first". Literally, main retains no
  history — but the pointer-sharing property above means correct, exact deltas
  are computable at publish time with near-zero incremental cost, and the
  snapshot/pinning discipline gives torn-free serving for free. Building only
  the fallback would leave the interesting 90% (retention) unbuilt while all
  its foundations are in place; and the fallback shape ALREADY exists on main.
* Blast-radius control (§2 of the sketch) is preserved: **IXFR is never a
  correctness dependency.** Any doubt — unknown serial, non-contiguous chain,
  same-serial content mutation, serial regression, over-budget chain, UDP —
  degrades to the existing full-transfer path or a single-SOA answer.
  The worst case of any retention bug is a wasteful transfer, never a wrong
  delta... provided retention itself is exact, which the tests must pin down.

## 3. Guiding invariants (unchanged from the sketch)

1. AXFR fallback is always available; serve a full zone whenever the chain
   cannot prove a contiguous path `clientSerial → snap.Serial`.
2. Serve ONLY from one pinned snapshot (`snap.IxfrChain`, `snap.SOA`,
   `snap.Data`) — never from live `zd` state — so a concurrent publish cannot
   tear a response.
3. One canonical chain order: newest-last. Append at publish; trim from the
   front on budget; contiguity `chain[i].ToSerial == chain[i+1].FromSerial`
   holds by construction and is re-verified at serve time (belt and braces).
4. Serial space: chain serials live in the OUTBOUND (`CurrentSerial`) space —
   the same space the SOA in every response and transfer uses. Inbound
   (`IncomingSerial`) never enters the chain.
5. Concatenate, don't condense (RFC 1995-canonical; condensation is the
   optional merge step we skip — an outbound-bug risk with no v1 payoff).

## 4. Design

### 4.1 Retention (the publish path)

Single choke point: `publishWorkingSetLocked` (all cadence/urgent/staged
publishes funnel through it), immediately before `buildSnapshotLocked`, so the
new snapshot's copied chain always ends exactly at the new snapshot's serial.

`zd.updateIxfrChainLocked(old *zoneSnapshot, newSerial, newData, newSOA)`:

* `old == nil || old.SOA == nil` → chain = nil (first publish / no baseline).
* staged epoch reset (`zd.wsIxfrEpochReset`, set by
  `applyRefreshReplacementLocked`) → chain = nil, skip diffing entirely (a
  wholesale replace has no meaningful "delta"; diffing it would be O(zone)
  work to produce a delta nobody should serve).
* `newSerial == old.Serial`: diff; empty → chain unchanged (e.g. a
  signalSynth-only publish); non-empty → **chain = nil + loud log** (a
  same-serial content change makes "serial N" ambiguous — any retained history
  through that point could ship a wrong delta; see also the §7 wart).
* `newSerial` not RFC-1982-newer than `old.Serial` → chain = nil + log
  (serial regression/wrap anomaly).
* else: compute the delta, append
  `Ixfr{FromSerial: old.Serial, ToSerial: newSerial, FromSOA, ToSOA, Removed,
  Added, EstBytes}`; an EMPTY delta still appends a link (serial-only advance,
  e.g. outbound-soa-serial=unixtime — the empty step keeps the chain
  contiguous and is legal RFC 1995 wire: `SOA(from) SOA(to)`).
* trim: while total `EstBytes` exceeds the budget (or link count > hard cap),
  drop the OLDEST link; if the newest link alone exceeds the budget →
  chain = nil (history cannot be retained at this budget).

Delta computation (`computeZoneDelta(oldData, newData)`):

* Pointer-diff owners first (the COW property); RRset-level comparison
  (`rrsetEqual`, exists on main) only for owners whose pointer changed;
  RR-level string-keyed set difference only for RRsets that differ. TTL or
  RDATA change ⇒ delete-old + add-new, per RFC 1995.
* **Apex SOA special case:** the SOA RRs themselves are EXCLUDED from
  Removed/Added — in the wire format the bracketing SOAs ARE the SOA change.
  SOA RRSIGs are ordinary diff content (they must travel in Removed/Added, and
  they churn on every re-sign). Bracket SOAs are stored as full RRs
  (`FromSOA`/`ToSOA`) because SOA RDATA (timers/MNAME) can change between
  serials — reconstructing brackets by rewriting the current SOA's serial
  would be wrong.
* Removed/Added hold REFERENCES to snapshot-owned RRs (no dns.Copy): snapshot
  data is immutable by the B invariant, and the chain budget bounds retained
  bytes. Emission only reads them.

`Ixfr` struct: gains `FromSOA, ToSOA *dns.SOA` and `EstBytes int` — additive;
the struct is declared-but-unused on main so this breaks nobody.

Epoch resets: `applyRefreshReplacementLocked` (flag as above) and
`InstallInitialSnapshot` (unconditional chain = nil: it re-baselines from
`zd.Data` outside the publish path).

Config: `ixfr-chain-max-bytes` (per-zone in ZoneConf, template-gap-filled like
every other field; parsed next to publish-cadence). 0/unset → default
1 MiB; negative → retention disabled (zone serves only fallback AXFR). Link
count is secondarily capped (512) as a defensive bound. Default-ON: retention
is cheap, additive, and AXFR remains available regardless.

### 4.2 Serving (ZoneTransferOut)

All existing gates run UNCHANGED first (authorizeTransfer, Ready, MapZone,
snapshot pinned, apex/SOA present, signed-zone fail-closed). Then, for
`Qtype == IXFR` only:

1. Parse the client's SOA from the query Authority section. No SOA → log +
   serve the full zone (always-correct; SetIxfr always includes it, so this is
   a malformed-client corner, not a protocol branch).
2. `clientSerial` same-or-newer than `snap.Serial` (RFC 1982; incomparable
   counts as not-older, conservative) → **single-SOA reply** (RFC 1995 §2), a
   normal TSIG-signed response via `signResponseLikeRequest`, not an envelope
   stream.
3. Transport is UDP → **single-SOA reply** (RFC 1995 §4 "does not fit"
   signal; the client retries over TCP). v1 never attempts delta-over-UDP —
   optional per RFC, and it sidesteps the truncation minefield. (UDP AXFR
   behavior is untouched.)
4. Chain walk on the PINNED snapshot: find `chain[i].FromSerial ==
   clientSerial`, verify contiguity through the tail AND tail `ToSerial ==
   snap.Serial`. Found → emit the delta stream. Not found / any
   inconsistency → log + fall through to the existing full-transfer code
   (RFC 1995 §4 fallback).

Delta emission reuses the Project-A machinery exactly (same tr.Out goroutine,
`batchState`, size caps, oversize abort, TSIG-per-envelope, done-channel
client-disconnect handling):

```
SOA(cur)                                        ← bare RR, serial = snap.Serial
per step: FromSOA, Removed…, ToSOA, Added…      ← bare bracket SOAs; RRSIGs inside Removed/Added
SOA(cur)                                        ← trailing, with the AXFR path's
                                                  flush-before-trailing treatment
```

No bare SOA RR may ever appear inside Removed/Added (the §4.1 exclusion): the
client-side framing (fork `inIxfr`) counts SOA records to find step boundaries
and the end of the stream; a stray SOA would break framing. The emission
contract against fork `inIxfr`, verified: first RR must be SOA (cur);
`qser >= serial` short-circuits up-to-date; stream ends at the third
occurrence of a cur-serial SOA (or the second for AXFR-shaped responses).

### 4.3 Serial arithmetic

`serialNewer(a, b uint32) bool` — RFC 1982 "a is newer than b":
`d := a - b (mod 2^32); d != 0 && d < 2^31`. Distance exactly 2^31 is
undefined by the RFC → reports not-newer both ways → we serve a single SOA
(client not provably behind) — conservative, self-healing (client's own SOA
refresh logic recovers). Table-tested including wrap.

## 5. Tests (all in v2, table/harness style; reuse the Project-A harness)

Retention: publish appends exact delta (adds/removes/brackets/serials); apex
SOA excluded, SOA RRSIG churn included; epoch reset on refresh-replacement and
InstallInitialSnapshot; same-serial content change resets; serial-only publish
appends empty link; byte budget trims oldest / nukes on oversize link;
disabled (negative) keeps chain empty.

Serving (loopback DNS server + fork Transfer.In, per Project A):
up-to-date and client-ahead → single SOA; unknown/too-old serial → full zone
(AXFR-shaped: second RR non-SOA); one-step delta → exact RFC 1995 sequence;
multi-step → concatenated sequences, envelope caps respected; UDP IXFR →
single SOA via fakeRW; TSIG round-trip on the delta path; contiguity-violation
snapshot (hand-built) → fallback.

`serialNewer` table incl. wrap and the 2^31 boundary.

Gate: full `v2` -race suite green; gofmt clean; cmdv2 binaries build via
gmake (GOROOT=/opt/local/lib/go).

## 6. Deferred (documented, not blocking)

* **C2 inbound IXFR** (`FetchFromUpstream` still hardcodes AXFR): separate
  project; needs the RFC 1995 difference-sequence parser on the client side
  and stepwise apply via publish. Nothing in this PR blocks it; retention
  gives it the serial bookkeeping it will need.
* **Downstream tracker** (POP §4): prune-by-lowest-downstream-serial is an
  optimization on top of the byte budget; the budget alone bounds memory and
  the fallback covers pruned-too-far clients. Add when a real deployment
  shows chain churn.
* **Condensation**; **XfrType field wiring** (still dead — wire or delete in a
  cleanup PR); serving IXFR-delta over UDP when it fits.

## 7. Known wart surfaced (NOT fixed here)

Same-serial content changes (catalog TXT, transport signals, dynamic RRs) are
a pre-existing zone-consistency wart: downstreams that already hold serial N
never see those changes until the next serial bump. Retention handles it
safely (reset + loud log) but does not fix it; candidate follow-up is bumping
the serial in those paths. Kept out of scope to stay additive.
