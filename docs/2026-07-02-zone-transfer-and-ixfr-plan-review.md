# Critical Review: Zone Transfer Improvements + IXFR Support Plan

**Reviewed:** 2026-07-02  
**Plan:** [`2026-07-02-zone-transfer-and-ixfr-plan.md`](2026-07-02-zone-transfer-and-ixfr-plan.md)  
**Method:** Line-by-line comparison of the plan against `tdns/v2` (and selected `tdns-mp/v2`, `miekg-dns` call sites). All anchors are current as of the review date; treat them as navigation hints, not stable API contracts.

---

## Executive summary

The plan correctly identifies the highest-impact outbound AXFR defects (batcher flush gate, apex bypass, producer hang, shared-state mutation during transfer, missing guards) and the right long-term shape (`ApplyChanges` choke point, AXFR fallback, phased delivery). Those diagnoses match the code.

The review found **several pre-flight gaps that would cause mid-flight surprises**:

1. **Dual-serial model (`IncomingSerial` vs `CurrentSerial`) is never specified for `IxfrChain`** — critical for secondaries, persist/unixtime modes, and IXFR request/response matching.
2. **Phase 3’s mutator inventory is incomplete** — query-path signing, transport signals, catalog writes, refresh callbacks, and all of `tdns-mp` mutate zone data outside the table.
3. **Phase 1’s snapshot plan is weaker than stated** — pointer capture does not isolate against in-place `RRtypes` mutation through shared stores; SOA re-sign during transfer must not write back to live apex.
4. **Internal contradictions** — refresh-flip “record a diff” vs “inbound AXFR = epoch reset”; audit oracle defined but not spec’d; NOTIFY policy for `ApplyChanges` omitted.
5. **Test/effort estimates assume infrastructure that does not exist** — zero `ZoneTransferOut` tests today; TSIG-signed envelope sizing tests will need substantial harness work.
6. **Stale/wrong references** — `sendNodata` does not exist; `dnsutils.go` TSIG TODO is obsolete; RFC 1982 helpers partially exist already.

**Recommendation:** Keep Phase 1 scope and sequencing, but add a “Serial & chain model” section, expand Phase 3 to an explicit closure checklist (including MP + callbacks), tighten Phase 1 snapshot/re-sign requirements, and resolve refresh-flip chain semantics before Phase 2 coding starts.

---

## What the plan gets right (verified against code)

| Plan claim | Verdict | Code anchor |
|---|---|---|
| AXFR and IXFR both call `ZoneTransferOut`; IXFR client serial ignored | **Confirmed** | `queryresponder.go:813-816` dispatches both to `ZoneTransferOut`; `ZoneTransferOut` never reads `r.Question` IXFR type or `r.Ns` client SOA |
| Inbound always requests AXFR | **Confirmed** | `zone_utils.go:312` — `ZoneTransferIn(..., "axfr", ...)` hardcoded |
| `ZoneTransferIn` can emit IXFR requests but IXFR responses flattened | **Confirmed** | `dnsutils.go:61-63` (`SetIxfr`); `96-98` (`SortFunc` per RR, no chain) |
| `IsIxfr` exists, unused | **Confirmed** | `zone_utils.go:668-685`; no callers in `tdns/v2` |
| Batcher flush gate measures current batch without pending RRset | **Confirmed** | `dnsutils.go:141-164` — triggers on `estimatedSize+newRRSize`, flushes only if `estimateEnvelopeSize(*bs.rrs) >= safeMessageSize` **before** append |
| Apex RRsets bypass batcher | **Confirmed** | `dnsutils.go:290-326` builds initial `rrs` directly; owner loop uses `maybeFlushBatch` from `339` |
| Final batch sent without size gate | **Confirmed** | `dnsutils.go:426-437` — `finalSize` logged only; unconditional `outbound_xfr <-` |
| Producer can block on unbuffered channel | **Confirmed** | `dnsutils.go:252` unbuffered chan; sends at `154`, `179`, `437`; consumer `tr.Out` in goroutine `257-263` |
| Missing apex/SOA can panic | **Confirmed** | `dnsutils.go:265-266` — `apex, _ := GetOwner(...)` then `GetOnlyRRSet(...).RRs[0]` with no nil/empty guard |
| SOA serial mutated + re-signed without `zd.mu` | **Confirmed** | `dnsutils.go:267-276` |
| Transfer reads without lock vs concurrent flip | **Confirmed** | `FetchFromUpstream`/`FetchFromFile` flip under `zd.mu` (`zone_utils.go:236-260`, `340-364`); `ZoneTransferOut` never acquires `zd.mu` |
| `IxfrChain` field exists, unused | **Confirmed** | `structs.go:140`, `509-514`; never appended in codebase |
| `ApplyChanges` / audit oracle do not exist | **Confirmed** | no matches in `tdns/v2` |

---

## Critical findings (would cause wrong behavior or blocked implementation)

### C1. Dual-serial model absent from the plan

The codebase maintains **two serial counters** with different meaning:

```135:136:tdns/v2/structs.go
	IncomingSerial    uint32 // SOA serial that we got from upstream
	CurrentSerial     uint32 // SOA serial after local bumping
```

Observed behavior:

- **Upstream tracking:** `DoTransfer` compares against `IncomingSerial` (`zone_utils.go:161-164`). Inbound transfer sets both from wire SOA (`dnsutils.go:105-106`).
- **Outbound serving:** `ZoneTransferOut` stamps `soa.Serial = zd.CurrentSerial` (`dnsutils.go:267`). Query path repeatedly overwrites apex SOA RDATA serial with `CurrentSerial` because apex SOA in `Data` often still carries upstream/`IncomingSerial` until stamped (`queryresponder.go:339-340`, `403-405`, `747-748`, `791-792`).
- **Refresh flip decouples them:** on non-first load, `IncomingSerial` ← upstream, `CurrentSerial++` separately (`zone_utils.go:343-348`, `239-244`).
- **Persist/unixtime modes** can move `CurrentSerial` ahead of inbound on load/refresh (`refreshengine.go:130-151`, `690-710`).

The plan’s `Ixfr{FromSerial, ToSerial}` (`structs.go:509-514`) and Phase 5 “walk chain client-serial → current” never state **which serial space** the chain uses.

**Impact:**

- Outbound IXFR must chain in **`CurrentSerial` space** (what downstreams last saw from us).
- Inbound IXFR requests must use **`IncomingSerial`** when talking to upstream (`FetchFromUpstream` already passes `zd.IncomingSerial` at `zone_utils.go:312`).
- `ApplyChanges` as specified (“reuse `nextOutboundSerial`”) only defines outbound bumps; it does not say how **`IncomingSerial` is updated** when applying upstream IXFR deltas on a secondary.
- Refresh `CurrentSerial++` **plus** per-delta `ApplyChanges` bumps could double-advance outbound serial relative to upstream unless rules are explicit.

**Required before Phase 2:** a short invariant block, e.g. “chain serials are outbound/`CurrentSerial`; inbound apply updates `IncomingSerial` to upstream `ToSerial`; apex SOA RDATA serial in responses/transfers always reflects `CurrentSerial`.”

---

### C2. Phase 1 snapshot does not deliver the consistency level the plan claims

Phase 1 (g) proposes capturing `Data`/`Owners` pointers under `zd.mu`. That **does not** isolate readers from concurrent in-place mutation:

- `GetOwner` returns a **struct copy** whose `RRtypes` pointer still aliases live storage (`zone_utils.go:475-485`, `468-493`).
- All mutators in the plan table (and many omitted ones) mutate via `owner.RRtypes.Set(...)` on shared `*RRTypeStore` handles.

Phase 1 (g) note acknowledges residual races until Phase 3 — good — but the summary text (“closes the transfer’s own mutation race and the flip torn-read”) overstates Phase 1.

**Additional Phase 1 gap:** online/inline signing during transfer re-signs **live apex**:

```270:276:tdns/v2/dnsutils.go
	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		if signed, err := zd.SignRRset(&soaRRset, ...); err != nil {
			...
		} else if signed {
			apex.RRtypes.Set(dns.TypeSOA, soaRRset)
		}
	}
```

The plan says “deep-copied SOA for the transfer” but does not **explicitly forbid writing signed SOA back to live apex**. That write is a real mutation + serial side effect and must be called out in Phase 1 acceptance criteria.

**Recommendation:** Phase 1 snapshot should sign a **transfer-local SOA copy** only; live apex must be untouched. Phase 2 snapshot accessor should document shallow snapshot semantics until Phase 3 completes.

---

### C3. Phase 3 mutator inventory is incomplete (completeness gate cannot pass as written)

The plan’s table (`§1`, Phase 3) is a good start but **misses active mutation paths** that would leave `IxfrChain` incomplete and break the audit oracle:

| Missing mutator / path | File:line | Notes |
|---|---|---|
| Query apex signing (`signApexRRsets`) | `queryresponder.go:103-115` | Writes signed SOA/NS back to apex on DO queries |
| CNAME chain signing | `queryresponder.go:449`, `514`, `534` | In-place `RRtypes.Set` during answers |
| Inline RRset signing on positive answers | `queryresponder.go:771-776` | `MaybeSignRRset` + `Set` during query |
| NXDOMAIN / NODATA SOA signing path | `queryresponder.go:700-709` | Signs and sets apex SOA before `sendNXDOMAIN` |
| `WriteZoneToFile` apex serial stamp | `dnsutils.go:669-670` | Mutates shared apex SOA (side effect on export) |
| `RepopulateDynamicRRs` | `zone_utils.go:1170-1224` | Post-flip, **outside** `zd.mu`; no serial bump |
| `CreateTransportSignalRRs` | `tsignal.go:307-309`, `420-422` | Mutates owner RRsets in zone |
| Catalog maintenance | `apihandler_catalog.go:167`, `524`, `565` | Direct `RRtypes.Set` |
| Refresh hooks | `parseconfig.go:1043-1068` | `OnZonePreRefresh` / `OnZonePostRefresh` callbacks mutate or trigger updates (`signal_republish.go:64+`, delsync proxy) |
| **`tdns-mp` signing/combiner paths** | `tdns-mp/v2/mp_signer.go:142`, `combiner_utils.go:163+`, `syncheddataengine.go:52+` | MP zones are production; plan scope says `v2` only |

**Impact:** Phase 5’s “only safe once **every** mutator feeds the chain” gate cannot be verified without a **closure checklist** and MP strategy (route through `ApplyChanges` vs disable outbound IXFR for MP zones until supported).

---

### C4. Refresh-flip chain semantics contradict themselves

Phase 3 proposes:

- “compute delta by diffing old vs new (`zoneDiff`) and record via `ApplyChanges`” **and**
- “Inbound AXFR = new epoch… may be recorded as a full replacement rather than a delta (**chain reset**).”

These conflict. For secondaries, **`FetchFromUpstream` is already a full replacement** (`zone_utils.go:340-361` pointer swap). Recording a zone-sized diff on every refresh is:

- Expensive (`~O(zone)` diff every refresh — plan acknowledges hardness but not steady-state cost on large zones).
- Redundant if the chain epoch resets anyway.

Existing diff primitives (`core.RRsetDiffer` in `tdns/v2/core/rrset_utils.go:49`) are per-RRset; a new `zoneDiff` is non-trivial and should justify itself vs **epoch reset + AXFR-only history**.

**Recommendation:** Pick one rule and document it:

- **Preferred:** full refresh/inbound AXFR ⇒ **clear `IxfrChain`, set baseline snapshot** (no giant synthetic delta). Incremental chain entries only for true incremental applies (RFC2136, signing passes, inbound IXFR steps).

---

### C5. Audit oracle is an invariant without a specification

Plan §2: `current_zone == last_full_snapshot + Σ deltas (RRset-canonical)`.

There is **no** existing canonicalization helper or snapshot type in `tdns/v2` (grep finds no `RRsetCanonical` / `zoneDiff`). `Ixfr` stores `[]core.RRset` (`structs.go:509-514`) but RRset equality/deletion semantics across types (DNSSEC, NSEC bitmaps, duplicate RRs) are unspecified.

**Impact:** Phase 3 “wire audit oracle across mutator test suite” cannot start without defining:

- Canonical key for an RRset (owner, type, rdata set, RRSIG handling),
- Whether NSEC/RRSIG churn collapses into one delta,
- How to snapshot “full zone” cheaply for tests.

---

### C6. NOTIFY policy omitted from `ApplyChanges` design

Today, dynamic updates call `BumpSerial()` (which notifies) from defer blocks:

```562:567:tdns/v2/zone_updater.go
	zd.mu.Lock()
	defer func() {
		zd.mu.Unlock()
		if updated {
			zd.BumpSerial()
		}
	}()
```

`BumpSerial` = `BumpSerialOnly` + `NotifyDownstreams` (`zone_utils.go:823-829`).

Phase 2 describes `ApplyChanges` as generalizing bump + delta but **does not** say when to NOTIFY. Inbound IXFR applying N upstream steps might need **one** NOTIFY, not N. Refresh already notifies once post-flip (`refreshengine.go:719`).

**Required:** `ApplyChanges` API flag or layered helpers (`ApplyChangesNoNotify`, `ApplyChangesAndNotify`).

---

## High findings (likely wrong estimates, test gaps, or RFC/interop risk)

### H1. No existing outbound transfer tests — harness work understated

Plan Phase 1 test plan (~150 LOC tests) assumes pack-every-envelope / TSIG-signed transfer tests. Current coverage:

- `transfer_fallback_test.go` covers **`DoTransfer` / `FetchFromUpstream` SOA probe fallback only** — no `ZoneTransferOut`, no batcher, no TCP transfer server.
- Grep: **zero** `_test.go` references to `ZoneTransferOut`, `maybeFlushBatch`, or `Ixfr`.

Building Phase 1 tests requires a **TCP AXFR/IXFR test server** (likely wrapping `miekg/dns.Transfer.Out`) plus TSIG verification parallel to `startTestSOAServerTSIG` in `transfer_fallback_test.go:55-105`.

---

### H2. TSIG / message size headroom — plan direction correct, implementation details missing

- `estimateEnvelopeSize` packs Answer RRs only (`dnsutils.go:214-226`).
- `miekg/dns.Transfer.Out` builds each response with `SetReply(q)` (adds Question) and appends TSIG after packing (`miekg-dns/xfr.go:223-233`).

Plan’s 59K→64K headroom rationale matches code. Also note:

- **`safeMessageSize` is duplicated** in `maybeFlushBatch` (`dnsutils.go:134`) and `ZoneTransferOut` (`dnsutils.go:285`) — refactor must centralize (plan mentions named constant but not duplication hazard).
- Stale comment at `dnsutils.go:29` — `// TODO: Add support for TSIG zone transfers.` contradicts implemented TSIG path (`checkInboundTSIG`, `SignForPeer`).

---

### H3. Inbound IXFR detection and request shape are underspecified

**Client request:** `SetIxfr` uses empty Ns/Mbox:

```61:63:tdns/v2/dnsutils.go
		msg.SetIxfr(zd.ZoneName, serial, "", "")
```

`miekg/dns.Transfer.inIxfr` reads client serial from **`q.Ns[0].(*SOA).Serial`** (`miekg-dns/xfr.go:144`). Empty strings may still produce an Authority SOA RR — verify; some upstreams require MNAME/RNAME.

**Server detection:** local `IsIxfr` only checks first two Answer RRs are SOA (`zone_utils.go:668-685`). `miekg` distinguishes IXFR vs AXFR by watching varying SOA serials mid-stream (`miekg-dns/xfr.go:186-199`). Phase 4 should reuse miekg’s envelope stream semantics, not only `IsIxfr` on individual RR slices.

**Post-apply state:** `ZoneTransferIn` always sets `CurrentSerial`/`IncomingSerial` from final apex SOA (`dnsutils.go:105-106`) — wrong for partial IXFR apply path where serial advances stepwise.

---

### H4. Outbound IXFR (Phase 5) missing wire-format and ordering requirements

Plan says “concatenate per-step deltas as successive difference sequences” but does not reference RFC 1995 bracketing:

- Each difference sequence: SOA(begin) → deletes → adds → SOA(end),
- Multiple sequences concatenated for multi-step catch-up,
- Final AXFR-style trailing SOA rules differ between IXFR and AXFR.

Phase 1 batcher assumes AXFR semantics (leading apex block + trailing SOA at `dnsutils.go:290-291`, `418-419`). IXFR outbound likely needs a **different emission driver**, not just “same batcher” without a detailed state machine.

---

### H5. `ZoneTransferOut` serves during loading / without readiness checks

- `GetOwner` gates on `Ready` (`zone_utils.go:458-459`).
- `FetchFromFile` sets `Ready = true` before flip with comment “this is a lie” (`zone_utils.go:223-225`).
- `ZoneTransferOut` does not check `Ready`, `GetStatus`, or refuse `ZoneStatusLoading`.

Concurrent refresh + transfer can expose partially flipped or repopulated zones (`RepopulateDynamicRRs` after flip without lock, `zone_utils.go:264-268`, `368-368`).

Phase 1 should specify refuse/SERVFAIL while `Status != Ready` or hold snapshot taken at request entry including status.

---

### H6. Unsupported zone store: partial transfer instead of hard refuse

On unknown/unsupported `ZoneStore`, code logs and falls through:

```413:416:tdns/v2/dnsutils.go
	default:
		zd.Logger.Printf("Zone %s: zone store %d: outbound zone transfer not supported. Sorry.",
```

Execution continues to send whatever is in `rrs` (apex prefix only) at `437`. Plan does not mention fixing this footgun (should REFUSE before streaming).

---

### H7. RFC 1982 helpers — plan reinvents partially existing pieces

`year68` constant exists for RFC 1982 (`dnsutils.go:25`) and more complete serial arithmetic lives in `cache/rrset_validate.go:1028-1040`. Phase 5’s “new `serialLT`/`serialGE` ~20 LOC” should **reuse or move** existing code to one module to avoid divergent arithmetic.

---

## Medium findings (documentation errors, omissions, sequencing nits)

### M1. Wrong function name: `sendNodata`

Plan Phase 3 cites `sendNXDOMAIN`/`sendNodata`/etc at `queryresponder.go:339,403,747,791`. **`sendNodata` does not exist** in `tdns/v2`. Line 791 is the **NODATA-like** branch (no matching qtype) — not a dedicated helper.

Additional SOA-stamping sites omitted from plan: `queryresponder.go:747-748` (positive SOA query path) matches the described bug pattern.

---

### M2. `SignRRset` table row oversimplifies

Plan lists `SignRRset` (`sign.go:116-230`) as mutating in-place without serial bump. True for the function body, but callers decide persistence:

- Transfer path writes back to apex (`dnsutils.go:275`).
- Query path writes via `Set` (multiple sites).
- Update/sign paths batch then bump separately.

Phase 3 should target **call sites that persist to zone**, not `SignRRset` alone.

---

### M3. `GenerateNsecChain` / `SignZone` multi-pass atomicity

`SignZone` calls `GenerateNsecChain` then signs per RRset, bumps once at end if any resign (`sign.go:771-775`, `894-902`). `ResignZone` calls `GenerateNsecChain` without its own serial bump (`sign.go:594-597`, `580-687`).

Plan says batch each pass into one `ApplyChanges` — good — but **NSEC regen + RR signing** may need **one** combined delta per operation to avoid chain entries that individually fail audit (NSEC present but RRSIGs stale mid-pass readers — mitigated today by per-RRset atomic `Set`, not by serial).

---

### M4. `ApplyChildUpdate` / `ApplyZoneUpdate` defer + lock interaction

Both hold `zd.mu` and call `BumpSerial()` in defer **after unlock** (`zone_updater.go:410-415`, `562-567`). `BumpSerial` re-acquires `zd.mu` (`zone_utils.go:788-789`). Conversion to `ApplyChanges` should replace this pattern with a single locked section; plan should warn against re-entrant lock + partial delta recording per RR in the loop (today: one serial bump at end, but **no** delta capture).

---

### M5. Dynamic zone replacement clears chain silently

`ModifyDynamicZone` replaces registry entry with fresh `ZoneData` (`dynamic_zones.go:960-981`) — **`IxfrChain` not carried forward** (implicit epoch reset). Plan mentions epoch on reload but not API-driven zone replacement / generation bump (`dynamic_zones.go:932-934`).

---

### M6. `XfrType` field unused for behavior

`ZoneData.XfrType` comment says `axfr | ixfr` (`structs.go:132`) but inbound path always sets `"axfr"` after parse (`dnsutils.go:550`). No code switches on `XfrType` for transfer policy — plan should either wire it or delete from design.

---

### M7. Phase 4 before Phase 5 ordering — dependency nuance

Plan correctly puts inbound IXFR before outbound. **However**, inbound IXFR applying via `ApplyChanges` on a secondary still requires clarity on:

- Interaction with post-refresh `SetupZoneSigning` (`refreshengine.go:713-716`) which re-signs entire zone and bumps serial again,
- Whether inbound IXFR remains enabled when upstream falls back to AXFR mid-stream (miekg handles this — `miekg-dns/xfr.go:186-199`).

---

### M8. Effort/risk table may undercount Phase 3 and test harness

| Phase | Plan LOC | Review note |
|---|---|---|
| 1 | ~260 | Reasonable impl; tests likely **>150 LOC** once TSIG+TCP harness exists |
| 2 | ~340 | Missing spec work (serials, NOTIFY, snapshot type) adds design time |
| 3 | ~1000 | **Undercount** if MP zones + callbacks + oracle spec included |
| 4–5 | ~520 each | RFC 1995 parser/emitter + interop tests often exceed estimate |

---

## Low findings / nits

- **`total_sent` accounting** in `ZoneTransferOut` mixes batch counts and final `len(rrs)` (`dnsutils.go:424-424`) — logging accuracy only.
- **`GetOwner` error ignored** at transfer entry (`dnsutils.go:265`) — Phase 1 (f) fixes panic but should distinguish `ErrZoneNotReady` vs empty apex.
- **`ZoneTransferOut` always closes `w`** (`dnsutils.go:441`) — verify this matches server expectations for TCP AXFR (may be fine; worth a test).
- **Plan anchor drift note** (§ intro) is good practice; consider adding anchors in `tdns-mp` when MP scope is included.

---

## Contradictions & ambiguities (summary table)

| # | Topic | Plan says | Code / review says |
|---|---|---|---|
| 1 | Snapshot strength | Phase 1 (g) closes flip/mutation races | Pointer snapshot + shared `RRtypes` ⇒ in-place mutators still visible; SOA re-sign writes live apex |
| 2 | Refresh flip | Record `zoneDiff` delta **and** chain epoch reset | Choose epoch reset OR full diff, not both |
| 3 | Client serial | IXFR from Authority SOA (Phase 5) | Correct; inbound request serial from `IncomingSerial`, outbound chain in `CurrentSerial` — plan silent |
| 4 | Query SOA fixes | `sendNodata` @ 791 | No `sendNodata`; multiple other mutation sites omitted |
| 5 | TSIG | TODO in `dnsutils.go:29` | TSIG transfer auth already implemented |
| 6 | Completeness | Phase 3 table exhaustive | MP, callbacks, transport signals, catalog, dynamic repopulate missing |

---

## Recommended plan amendments (before implementation)

1. **Add § “Serial spaces & chain epochs”** — define `IncomingSerial` vs `CurrentSerial` roles, when each advances, and IXFR request/response matching rules.
2. **Amend Phase 1 acceptance criteria** — transfer-local SOA copy; no live apex write; refuse if not `Ready`; fix unsupported `ZoneStore` path to REFUSE; centralize size constants.
3. **Replace Phase 3 table with closure checklist** — include MP strategy, refresh callbacks, `RepopulateDynamicRRs`, transport/catalog paths, query-path signing policy (copy vs mutate).
4. **Resolve refresh-flip chain policy** — prefer epoch reset on full AXFR/file flip; do not build `zoneDiff` for routine secondary refresh unless there is a concrete outbound-IXFR win.
5. **Spec the audit oracle** — canonical RRset key, snapshot representation, test vectors; stub in Phase 2 tests even if prod periodic audit is optional.
6. **Spec NOTIFY coalescing** on `ApplyChanges` before Phase 2 merges with update paths.
7. **Phase 4/5 add RFC 1995 wire-format appendix** — IXFR difference sequences, multi-step concatenation, AXFR fallback detection aligned with `miekg-dns/xfr.go`.
8. **Testing milestone** — build shared AXFR/IXFR TCP+TSIG test harness in Phase 1; reuse for Phases 4–5.

---

## Suggested implementation order tweak (Phase 1)

Plan order: (f)(g) → (a+b+d+safe) → (e).

Review agrees, with additions:

1. **(f)(g)** nil guard + transfer-local SOA (no write-back) + status/Ready gate.
2. **Extract constants** (`safeMessageSize`, etc.) before batcher rework.
3. **(a)(b)(d)** batcher fixes including apex through batcher.
4. **(e)** abort plumbing — then rerun batcher sends through `select`/done.
5. **Harness + TSIG size tests** — treat as Phase 1 deliverable, not follow-on.

---

## Conclusion

The plan is directionally sound and accurately describes today’s AXFR outbound defects. The largest pre-flight risks are **serial-space ambiguity**, **incomplete mutator closure (especially MP and query-side signing)**, and **under-specified IXFR wire semantics** — not the Phase 1 batcher mechanics themselves.

Addressing the § “Recommended plan amendments” items in the plan document (or a short addendum) should be enough to proceed with Phase 1 independently while Phase 2 design settles the choke-point contract.
