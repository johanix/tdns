# Project A — Retire SliceZone + Outbound Zone Transfer Hardening

**Status:** implementation-ready (final — SliceZone retirement + transfer fixes;
all review rounds folded in)
**Date:** 2026-07-02
**Scope:** (0) retire the SliceZone store entirely, then (1) fix `ZoneTransferOut`
+ the envelope batcher in `v2/dnsutils.go`. **Independent** of Projects B and C.
Do **first** — it fixes live bugs (PQ-apex envelope overflow + a goroutine hang on
client disconnect) and hands B a single-store (MapZone-only) codebase.
**Siblings:** `…-zone-mutation-snapshot-correctness.md` (B), `…-ixfr-support.md`
(C). **Review folded in:** `…-outbound-transfer-hardening-review.md`.
Anchors are as of 2026-07-02; verify before editing.

---

## Step 0 — Retire SliceZone (behavior-neutral simplification)

**Why:** `OwnerData` is a 24-byte handle (`Name string` + `RRtypes *RRTypeStore`;
structs.go:518) — the real RR data is behind the shared pointer. So SliceZone
(`[]OwnerData` **plus** a `map[string]int` `OwnerIndex`) buys nothing: its lookup
is a map lookup **+** an array deref (strictly slower than MapZone's single map
lookup), and its memory is marginally *higher* (a slice *and* an index map). The
map-overhead it was meant to dodge doesn't exist because the value is a thin
handle. At 1M owners the store-choice difference is ~4 MB inside a multi-hundred-
MB-to-GB zone. It's a dead hedge — remove it so A and B only ever handle one
representation.

**Full retirement checklist (verified; DNS responses identical before/after):**
- **Enum / type / fields:** delete the `SliceZone` `ZoneStore` value + names
  (structs.go:24/30/41), the `Owners` type (structs.go:516), and the `zd.Owners`
  / `zd.OwnerIndex` fields (structs.go:119-120).
- **The `"slice"` string parser → MapZone:** `parseZoneStore` (catalog.go:492-512,
  the branch at :506) and config parsing (parseconfig.go:629-630) map `"slice"`.
  Make both a **deprecated alias returning MapZone** so existing configs don't
  error. (Correction: catalog *member* zones are already created as MapZone —
  catalog.go:406 — there is no "catalog defaults to slice.")
- **Cross-module + tests (else the build breaks when the enum value is removed):**
  `tdns-mp/v2/hsync_utils.go:1187-1197` (`PrintOwnerNames` `case tdns.SliceZone` —
  delete the branch) and `zonestore_test.go` (:10/:22/:38 enumerate `SliceZone` —
  expect `"slice"`→MapZone, drop the const).
- **dnsutils.go:** delete `ComputeIndices()` (796-820) + the `Owners` sort methods
  `Len`/`Swap`/`Less` (822-830); drop the `ComputeIndices()` calls (113, 549);
  collapse the store checks/branches at 68, 340-374 (→ the MapZone loop 376-411),
  479, 677; in `SortFunc` remove the `case SliceZone: fallthrough` at 574 (keep
  the MapZone path only — inbound transfer already stores into `Data`).
- **zone_utils.go:** delete the `Owners`/`OwnerIndex` copies in the two hard flips
  (237-238, 341-342); collapse the `case SliceZone` branches in `nameExists`
  (440), `GetOwner` (464-469 → `Data.Get`), `AddOwner` (500-502, the FIXME'd
  broken path), `GetOwnerNames` (536-550 → `Data.Keys()`), and `PrintOwners` (608-628);
  update stale error strings that mention “SliceZone and MapZone” (e.g. `GetOwner`
  :489, `GetOwnerNames` :550) to MapZone-only (or MapZone + XfrZone where relevant).
- api_structs.go:315 `OwnerIndex map[string]int` is an unrelated API-response
  field — leave it.
- **NSEC scoping check — RESOLVED, safe:** `GenerateNsecChain` (sign.go:948-952)
  and `SignZone` (sign.go:804-808) collect names via `GetOwnerNames()` then
  **`sort.Strings()`** — they do **not** rely on SliceZone's pre-sorted `Owners`.
  Retiring the slice does not break NSEC(3) generation (MapZone's unordered
  `Data` + the existing sort is already the universal path).
- **Bonus:** zone_utils.go:455 `XXX: FIXME: SliceZones do not yet support adding
  new owner names` — retirement eliminates that latent limitation.

**Effect on the rest of A:** `ZoneTransferOut` now has a **single** owner loop, so
the batcher fixes below apply once, not twice.

**Risk: low** (behavior-neutral). No `ZoneTransferOut`/query integration tests exist
today, so add a smoke AXFR round-trip (via the §4 harness) to cover Step 0 rather
than leaning on existing coverage.
**~150–300 LOC** (mostly deletions).

---

## 1. The transfer defects (verified against code)

`ZoneTransferOut` at dnsutils.go:229; dispatched from queryresponder.go:813-816.
Batcher `maybeFlushBatch` (132-192), `estimateRRSize` (196-210),
`estimateEnvelopeSize` (214-227); `safeMessageSize = 59000` (duplicated 134 & 285).

1. **Mismatched flush gate** (141-164): gates on `estimated+newRRSize` but flushes
   only if the *current* batch alone `>= safe` → `current=55k, new=12k` → 67k
   envelope.
2. **Apex bypasses the batcher** (290-326): apex SOA + apex RRtypes + RRSIGs
   accumulate raw with no `maybeFlushBatch` (owner loop starts at 339). A PQ apex
   can exceed 64K alone → first envelope overflows.
3. **Final send not size-gated** (426-437): `finalSize` logged only; unconditional
   send.
4. **Producer hangs on consumer failure**: `outbound_xfr` unbuffered (252);
   `tr.Out` consumer in a goroutine (257-263) returns on write error without
   draining (miekg `for x := range ch`); producer then blocks forever on the next
   send → leaked goroutine; `wg.Wait()`/`w.Close()` (440-441) never run.
5. **Panic on missing apex/SOA** (265-266): `apex, _ := GetOwner(...)` discards the
   error; `...RRs[0]` nil-derefs / index-panics; the already-spawned goroutine
   leaks.
6. **Unsupported `ZoneStore` streams partial apex** (413-416 → 437) — but after
   step 0 the only stores are MapZone (+ the pure-`xfr` store); keep a REFUSE
   default anyway.
7. **No `Ready`/`Status` gate** — serves during refresh.
8. **`safeMessageSize` duplicated** (134, 285).
9. **Stale TODO** dnsutils.go:29 (TSIG transfers are implemented).

TSIG-out signing is **correct** (miekg `Transfer.Out` `SetTsig`s each envelope;
provider MACs via `w.WriteMsg`; wrapper idempotent). Do not touch.

---

## 2. The fixes

### (f) Guard apex/SOA before spawning the goroutine — 265-266
Fetch the apex **before** the `tr.Out` spawn (257). Handle **all three** failure
modes: `err != nil` (incl. `ErrZoneNotReady`), `err == nil && apex == nil`
(missing apex), and an **empty SOA RRset** (`RRs[0]` would panic). On any → REFUSE
(no goroutine spawned).

### (g) Serve without writing shared state — delete the transfer-time re-sign — 267-276
Interim (pre-B): capture `CurrentSerial` + the `Data` pointer at entry, deep-copy
the SOA, stamp `Serial=CurrentSerial` on the **copy**, and **delete the
transfer-time SOA re-sign block (270-276)** — no write to `apex.RRtypes`.
**Acceptance criterion: `ZoneTransferOut` performs zero writes to shared zone
state.** (Not full read-isolation — reads still traverse shared `RRtypes` until B;
torn logical views remain possible until B's snapshot. That residual is accepted
for A.) After B, (g) collapses to `snap := zd.snapshot.Load()`.

### (a) Flush gate — 141-164
Flush the current batch when `estimateEnvelopeSize(current) + newRRSize >= safe`
(measure current accurately, add the candidate's estimate), then start the next
batch with the new RRset — do **not** reuse the "measure current alone" branch at
144. Edge case: if a **single** RRset's own packed size approaches `safe`, the
append is valid but the send may exceed cap once the trailing SOA is added — (d)
+ (e) must catch it.

### (b) Apex through the batcher — 290-326
Feed apex SOA + apex RRtypes + RRSIGs through the same `maybeFlushBatch` path as
the (now single) owner loop.

### (d) Size-gate the final send — 426-437
Size-check the final batch (remaining + trailing SOA). If it exceeds cap because
it holds multiple RRsets → flush earlier batches via the same gate. If it exceeds
cap as a **single** RRset → **abort via (e) + log owner+type** (no splitting, per
§3). Do **not** "split."

### (e) Producer + consumer abort — both directions — 252-263, 154/179/437
Two abort directions must both be handled:
- **Consumer fails first** (client disconnect / write error): `tr.Out` returns an
  error → the **wrapper goroutine** around it closes `done` (`go func(){ defer
  wg.Done(); if err := tr.Out(...); err != nil { close(done) } }()` — `tr.Out`
  itself has no `done` param). Producer sends `select { case outbound_xfr <- env:
  case <-done: return }`.
- **Producer aborts first** (oversize final batch / local fatal): the producer
  must **`close(outbound_xfr)`** so `tr.Out`'s `for x := range ch` exits, then
  `wg.Wait()`. Returning on `<-done` alone would leave `tr.Out` blocked → the
  original hang.
Use one `sync.Once` for the channel close so no path double-closes.

### Unified cleanup on every exit — new
After the `tr.Out` spawn — **immediately, before any batcher work that could return
early** — arm one teardown:
`defer func(){ closeOnce.Do(func(){ close(outbound_xfr) }); wg.Wait(); w.Close() }()`.
Pre-spawn guards (f, Ready gate, unsupported store) return **before** the spawn,
so they never reach it. Every post-spawn exit runs the same teardown.

### safe 59000 → 64000, one constant — 134, 285
Single `const safeMessageSize = 64000` (remove the duplicate). Comment: ~1.5 KB
headroom reserves the per-envelope **question** (`SetReply`, ≤259 B) + **TSIG**
(miekg appends after our measurement, ≤~360 B) that `estimateEnvelopeSize` omits.

### Ready/Status gate — entry
Refuse/SERVFAIL when `zd.GetStatus() != ZoneStatusReady`. Note: `GetOwner` gates
on the weaker `zd.Ready` bool, which is set `true` mid-refresh ("this is a lie",
zone_utils.go:223-225) while `Status` stays `loading` until the flip — so
**`GetStatus()` is the correct transfer gate**, not `zd.Ready`.

### Unsupported `ZoneStore` → REFUSE — 413-416
Replace the fall-through with a REFUSE before streaming (defensive; step 0 already
removed SliceZone).

### Remove stale TODO — 29

### (optional) IXFR → REFUSE until Project C
Dispatch still sends `TypeIXFR` to `ZoneTransferOut` (queryresponder.go:813-816),
which serves full AXFR. Optionally REFUSE `TypeIXFR` (or document "IXFR yields
AXFR") until C. Not a blocker.

---

## 3. Won't do
- **(c) Intra-RRset splitting** — an RRset >64K is unanswerable to any ordinary
  query anyway (TCP is also capped at 65535; RFC 5936 keeps RRsets whole), so the
  zone is unserveable regardless. Handle via (e)'s clean abort + a **loud log
  naming the owner+type**.
- **Shelf / bin-packing** — over-engineering; `safe`→64000 captures the win.

---

## 4. Test plan
No `ZoneTransferOut` tests exist (only `transfer_fallback_test.go`, SOA probe,
TSIG server :55-105). Build the harness (**reused by Project C**):
- **TCP-AXFR-over-TSIG harness** — model on `startTestSOAServerTSIG`
  (transfer_fallback_test.go:57-105): a `dns.Server{Net:"tcp",
  TsigSecret:{key:secret}, Handler:mux}` whose mux installs
  `TsigSigningHandler(func(w,r){ zd.ZoneTransferOut(w,r) })` for the zone (it's a
  method — needs the closure; `TsigSigningHandler` @ tsig_peer.go:126, installed on
  Do53 @ do53.go:51); client `tr :=
  &dns.Transfer{TsigSecret:{key:secret}}` with `msg.SetAxfr(zone)` +
  `msg.SetTsig(...)` then `tr.In(msg, addr)`. Minimal (one MapZone, one
  HMAC-SHA256 key, loopback TCP). For the **explicit per-envelope size check**,
  wrap the server's `dns.ResponseWriter` to record `len(packed)` per `WriteMsg`
  and assert every envelope ≤ 65535 (and ≤ 64000). (Over TCP a >65535 message
  can't be framed — 2-byte length prefix — so an oversize envelope fails the
  *server-side* Pack and aborts the transfer; the round-trip-success test already
  catches overflow, the recorder just makes it explicit.)
- **Oversized PQ apex** — apex alone spans envelopes; assert **every** emitted
  envelope packs < 65536 on a **TSIG-signed** transfer (exercises question+TSIG
  headroom; a pack-only test without `SetReply`+TSIG gives false confidence).
- **Single RRset > cap** — clean abort + log; no hang.
- **Producer-initiated oversize abort** (no client disconnect) — the abort fires
  on the producer before any send; assert channel closed, `tr.Out` exits, no leak.
- **Client disconnect mid-transfer** — producer aborts, no goroutine leak.
- **Round-trip** — normal zone, correct RR count/content.

---

## 5. Implementation order
1. **Step 0 — retire SliceZone** (behavior-neutral; unblocks single-loop batcher).
2. **(f)** guard + **Ready/Status gate** + **unsupported-store REFUSE** + remove
   TODO (cheap; all pre-spawn, no goroutine on REFUSE paths).
3. **(g)** transfer-local SOA, delete write-back (zero shared writes).
4. **Extract `safeMessageSize`** (dedupe) → **(a)+(b)+(d)** batcher rework +
   `safe`→64000.
5. **(e) + unified cleanup** — `done` channel, `sync.Once` close, teardown defer;
   route all producer sends through the `select`.
6. **Harness + tests** — a Project-A deliverable (incl. the producer-oversize
   abort test).

## 6. Risk / effort / LOC
**Risk: medium** — step 0 is low-risk but broad; the batcher rework + abort
lifecycle carry the medium risk (covered by the pack-<65536 + abort tests).
**Effort: ~3–4 h agent** (step 0 ~1–2 h + transfer fixes ~1.5–2 h).
**LOC: ~200 (retire) + ~130 (fixes) + ~300 (tests+harness) ≈ 630.**

## 7. Interaction with B/C
- After **B**, (g) collapses to `snapshot.Load()` — the immutable snapshot removes
  the residual torn-read and the SOA-copy dance. A's interim (g) is written so
  that is a simplification, not a rewrite.
- Step 0 hands B a **MapZone-only** codebase → B's snapshot is map-only, no
  store normalization.
- The harness is reused by **C** for IXFR-out tests.
