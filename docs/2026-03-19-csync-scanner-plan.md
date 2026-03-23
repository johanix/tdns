# CSYNC Scanner: Implementation Plan

**Date:** 2026-03-19
**Status:** All steps implemented
**Prerequisite:** CDS pipeline (2026-03-18) — all steps
done

## Background

RFC 7477 defines CSYNC: a child zone publishes a CSYNC
record at its apex to signal that the parent should
synchronize NS, A, and AAAA delegation records from the
child. This is the glue/NS counterpart to CDS (which
synchronizes DS records).

The CDS pipeline (implemented 2026-03-18) already handles
the NOTIFY->Scan->Update flow for CDS/DS. CSYNC follows
the same architectural pattern but operates on different
record types and has its own RFC-specified validation
rules.

## What Already Exists

**Working infrastructure (from CDS pipeline):**
- `NotifyResponder` already routes NOTIFY(CSYNC) to the
  scanner queue — same path as CDS, with
  `RRtype=dns.TypeCSYNC`
- Scanner dispatch already has a `ScanCSYNC` branch
  (currently returns "not implemented")
- `ScanTupleResponse` can carry results back to caller
- `OnDSChange` callback pattern for enqueuing
  CHILD-UPDATE
- `queryAllNSAndCompare()` for multi-NS consistency
  checks
- `DelegationBackend.GetDelegationData()` returns
  current NS/A/AAAA
- `ApplyChildUpdate` handles ClassINET/ClassNONE/
  ClassANY actions for any RR type

**Legacy CSYNC code (`scanner_csync.go`, ~450 lines):**
- `CheckCSYNC()` — complete RFC 7477 analysis with SOA
  stability checks, flag parsing, bitmap handling,
  serial tracking
- `CsyncAnalyzeNS/A/AAAA()` — per-type diff functions
  using `core.RRsetDiffer()`
- `NSInBailiwick()` — in-bailiwick NS detection
- `ZoneCSYNCKnown()` / `UpdateCsyncStatus()` — serial
  dedup
- Uses old `ChildDelegationData` struct (NS_rrs,
  A_glue, etc.)
- Queries single NS via `AuthQueryNG` (not all-NS
  consistency)
- Never applies changes (commented-out write code)

**What the legacy code does right:**
- Correct RFC 7477 flag parsing (immediate, soaminimum)
- Correct NS-first ordering of bitmap types
- SOA serial stability check (query before + after)
- MinSOA serial validation
- CSYNC dedup via serial tracking

**What the legacy code does wrong / is missing:**
- Queries only one NS, not all NS for consistency
- Uses flat `[]dns.RR` slices instead of `*core.RRset`
- Uses `ChildDelegationData` instead of
  `CurrentScanData`
- Has no DNSSEC validation (hardcoded
  `validated := true`)
- Returns `*ChildDelegationData` instead of populating
  `ScanTupleResponse`
- Never writes (correct! but also never reports results)

## Design Principles

Same as CDS pipeline:

- **Read-only scanner.** Query, compare, report. Never
  write. The caller (authserver callback) applies
  changes.
- **Query child NS directly** (AuthQueryNG/TCP), not
  via IMR, for authoritative answers.
- **All-NS consistency** via `queryAllNSAndCompare()` —
  all child nameservers must agree on CSYNC, NS, and
  glue.
- **Compare against backend.** Current delegation data
  comes from `DelegationBackend.GetDelegationData()`,
  not from in-memory zone data.
- **Scanner options gate behavior.** Same
  `no-dnssec-validation` option applies.

## New Concepts (CSYNC-specific, not in CDS)

### Multiple RR types in one scan

CDS produces exactly one result type: DS adds/removes.

CSYNC can produce changes to up to three types: NS, A,
AAAA. The type bitmap in the CSYNC RR controls which
types are processed. NS must be processed first (A/AAAA
glue depends on which NS are in-bailiwick).

### SOA serial stability

RFC 7477 requires querying the child SOA before and
after the analysis. If the serial changed, abort — the
zone was modified during the scan and results may be
inconsistent.

CDS has no equivalent requirement.

### CSYNC flags

- **immediate** (bit 0): Process now without operator
  approval. We only support immediate — log a warning
  and skip if not set.
- **soaminimum** (bit 1): The CSYNC's Serial field is a
  minimum SOA serial. Don't process if child's current
  SOA serial is less than this value.

### In-bailiwick glue

Glue records (A/AAAA) are only relevant for NS records
that are under the child zone (in-bailiwick).
Out-of-bailiwick NS names have their addresses resolved
elsewhere — the parent doesn't store glue for them.

Example: child `example.com.` with NS
`ns1.example.com.` (in-bailiwick, needs glue) and
`ns2.other.net.` (out-of-bailiwick, no glue needed).

### Serial dedup

To avoid re-processing the same CSYNC, the scanner
tracks which CSYNC serial has already been analyzed per
zone. If the same serial arrives again, skip it. This
uses an in-memory map (`KnownCsyncMinSOAs`).

## Result Reporting

`ScanTupleResponse` needs new fields for CSYNC results.
The existing `DSAdds`/`DSRemoves` only cover CDS->DS
changes.

CSYNC changes involve three RR types at different owner
names:
- NS changes at child apex (e.g., `child.parent.`)
- A changes at NS names (e.g., `ns1.child.parent.`)
- AAAA changes at NS names (e.g., `ns1.child.parent.`)

**New fields on `ScanTupleResponse`:**

```go
// CSYNC results: delegation record changes (NS + glue)
NSAdds      []dns.RR  // NS records to add at child apex
NSRemoves   []dns.RR  // NS records to remove from child apex
GlueAdds    []dns.RR  // A/AAAA glue records to add
GlueRemoves []dns.RR  // A/AAAA glue records to remove
```

Glue adds/removes carry their owner name in the RR
header, so the caller knows which NS name each glue
record belongs to. No separate per-NS grouping needed —
`ApplyChildUpdate` already handles per-owner dispatch
based on `rr.Header().Name`.

## Callback: OnCSYNCChange

Parallel to `OnDSChange`, a new callback for CSYNC
results:

```go
OnCSYNCChange func(parentZone string, zd *ZoneData,
    resp ScanTupleResponse)
```

Wired in `ScannerEngine`, builds Actions array:
- NS adds -> ClassINET NS RRs
- NS removes -> ClassNONE NS RRs
- Glue adds -> ClassINET A/AAAA RRs
- Glue removes -> ClassNONE A/AAAA RRs

Enqueues `UpdateRequest{Cmd: "CHILD-UPDATE",
UpdateType: "CSYNC", Trusted: true,
InternalUpdate: true}`.

**Alternative:** Merge into `OnDSChange` and rename to
`OnDelegationChange` — single callback that handles
both CDS and CSYNC results. The callback already
inspects the response fields to build Actions. Adding
NS/Glue fields to the response means the same callback
can handle both.

**Recommendation:** Single `OnDelegationChange`
callback. Simpler, less wiring, and both CDS and CSYNC
produce CHILD-UPDATE requests with the same structure.
The callback checks which fields are populated and
builds Actions accordingly.

## Implementation Steps

### Step 1: Extend ScanTupleResponse — DONE

Add `NSAdds`, `NSRemoves`, `GlueAdds`, `GlueRemoves`
fields to `ScanTupleResponse` in `api_structs.go`.

**Complexity:** Trivial — 4 new fields, no logic.
**Risk:** None. Additive struct change.

### Step 2: Extend CurrentScanData for CSYNC — DONE

The NOTIFY->ScanTuple bridge (in `ScannerEngine`)
already fetches current DS from `GetDelegationData()`
for CDS scans. For CSYNC scans, it needs to also
populate the current NS and glue data.

`GetDelegationData()` already returns NS/A/AAAA — the
data is there, it just needs to be extracted into
`CurrentScanData` fields.

**New fields on `CurrentScanData`** (if not already
present):
- `NS *core.RRset` — current NS at child apex
- `A_Glue []dns.RR` — current A glue records (multiple
  owners)
- `AAAA_Glue []dns.RR` — current AAAA glue records

Wait — `CurrentScanData` already has an `RRset` field
but it's generic. For CSYNC we need structured
delegation data. Two options:

**(a)** Add NS/Glue fields to `CurrentScanData`.
**(b)** Pass the raw `GetDelegationData()` map into the
scan function and let it extract what it needs.

**Recommendation:** Option (b). The
`GetDelegationData()` map
(`map[string]map[uint16][]dns.RR`) already has
everything organized by owner+type. Pass it to
`ProcessCSYNCNotify` as a parameter. This avoids
bloating `CurrentScanData` with CSYNC-specific fields.

The NOTIFY->ScanTuple bridge already calls
`GetDelegationData()` for CDS (to get DS). For CSYNC,
same call, pass the full map.

**Complexity:** Low. Plumbing change in the bridge code.
**Risk:** None.

### Step 3: ProcessCSYNCNotify — Core Logic — DONE

New function, parallel to `ProcessCDSNotify`. This is
the main implementation effort.

```go
func (scanner *Scanner) ProcessCSYNCNotify(
    ctx context.Context,
    tuple ScanTuple,
    parentZD *ZoneData,
    delegationData map[string]map[uint16][]dns.RR,
    scanType ScanType,
    options *edns0.MsgOptions,
    responseCh chan<- ScanTupleResponse,
)
```

**Logic (following RFC 7477 S3):**

1. **Get child NS from parent zone data.**
   Same as `ProcessCDSNotify`:
   `parentZD.GetOwner(childZone)` -> NS RRset. These
   are the nameservers to query.

2. **Query SOA from child (start serial).**
   `queryAllNSAndCompare(childZone, childZone,
   dns.TypeSOA, ...)` Extract serial. All NS must
   agree on SOA.

3. **Query CSYNC from child.**
   `queryAllNSAndCompare(childZone, childZone,
   dns.TypeCSYNC, ...)` All NS must return identical
   CSYNC. Extract flags + bitmap.

4. **Validate CSYNC flags.**
   - If `immediate` flag not set: log warning, abort
     (we only support immediate processing).
   - If unknown flags set: abort per RFC 7477.

5. **Serial validation.**
   - Check serial dedup (`ZoneCSYNCKnown`): if same
     serial already processed, abort.
   - If `soaminimum` flag set: check CSYNC.Serial <=
     SOA serial.

6. **DNSSEC validation gate.**
   Same pattern as CDS: check
   `no-dnssec-validation` option. If validation
   required but not available, log and proceed (same
   TODO as CDS for direct queries).

7. **Process each type in bitmap (NS first).**
   - **NS**: Query NS from child via
     `queryAllNSAndCompare`. Compare against current
     NS from `delegationData`. Compute adds/removes
     via `core.RRsetDiffer()`.
   - **A**: For each in-bailiwick NS (from new NS
     set), query A records from child. Compare against
     current A glue from `delegationData`. Compute
     adds/removes.
   - **AAAA**: Same as A but for AAAA records.

   In-bailiwick check:
   `dns.IsSubDomain(childZone, nsName)` (or the
   existing `NSInBailiwick` function).

8. **Query SOA again (end serial).**
   `queryAllNSAndCompare(childZone, childZone,
   dns.TypeSOA, ...)` If start_serial != end_serial,
   abort — zone changed during scan.

9. **Update serial tracking.**
   `KnownCsyncMinSOAs[zone] = csyncrr.Serial`

10. **Report results.**
    Populate `ScanTupleResponse`:
    - `NSAdds`, `NSRemoves` from NS diff
    - `GlueAdds`, `GlueRemoves` from A + AAAA diffs
    - `DataChanged = true` if any adds/removes
    - `ScanType = ScanCSYNC`

**Differences from legacy `CheckCSYNC`:**
- Uses `queryAllNSAndCompare` (all-NS consistency)
  instead of single-NS `AuthQueryNG`
- Gets current data from `delegationData` map instead
  of `ChildDelegationData` struct
- Reports results in `ScanTupleResponse` instead of
  returning `ChildDelegationData`
- Leverages CDS pipeline infrastructure (SOA
  consistency comes free from all-NS queries)

**Complexity:** Medium. ~150 lines. The logic is
well-understood from both the legacy code and the CDS
pipeline. The main work is adapting the RFC 7477
algorithm to use the new infrastructure.

**Risk:** Low-medium. The glue handling (per-owner
diffing for multiple NS names) is the trickiest part.
Need to diff A/AAAA per-owner, not as a flat list,
because different NS names are different owners in the
parent zone.

### Step 4: Wire Dispatch in ScannerEngine — DONE

The scanner dispatch already has a `ScanCSYNC` case that
returns "not implemented". Replace it with a call to
`ProcessCSYNCNotify`.

Changes needed in `ScannerEngine`:
- In the NOTIFY->ScanTuple bridge: when
  `RRtype == dns.TypeCSYNC`, fetch `delegationData`
  from backend and pass to tuple
- In the dispatch: route `ScanCSYNC` +
  `sr.ZoneData != nil` to `ProcessCSYNCNotify`

**Complexity:** Low. Pattern-match from CDS dispatch.
**Risk:** None.

### Step 5: Rename OnDSChange -> OnDelegationChange
— DONE

Rename the callback and extend it to handle CSYNC
results.

Current `OnDSChange`:
```go
OnDSChange func(parentZone string, zd *ZoneData,
    resp ScanTupleResponse)
```

The callback body builds Actions from `resp.DSAdds`
(ClassINET) and `resp.DSRemoves` (ClassNONE). Extend
to also process `resp.NSAdds`, `resp.NSRemoves`,
`resp.GlueAdds`, `resp.GlueRemoves`.

Set `UpdateType` to `"CSYNC"` when CSYNC fields are
present (vs `"CDS"` for DS fields).

The job-completion goroutine already calls the callback
for DS changes. Extend the condition to also trigger
for NS/Glue changes.

**Complexity:** Low. ~20 lines of additions to the
callback.
**Risk:** Low. Same CHILD-UPDATE path, different RR
types.

### Step 6: Glue Diffing Strategy — DONE

This deserves its own section because it's the most
subtle part.

**Problem:** Current delegation data from
`GetDelegationData()` is organized as
`map[owner]map[rrtype][]dns.RR`. Glue records live at
NS owner names (e.g., `ns1.child.parent.`), not at the
child apex.

When the child changes an NS from `ns1.child.parent.`
to `ns3.child.parent.`, we need to:
- Remove A/AAAA for `ns1.child.parent.` (if no longer
  referenced)
- Add A/AAAA for `ns3.child.parent.` (new in-bailiwick
  NS)
- Keep A/AAAA for `ns2.child.parent.` (unchanged NS)

**Approach:**

1. Compute new NS set and old NS set.
2. For each in-bailiwick NS in the **new** set: query
   A/AAAA from child, store as desired state.
3. For each in-bailiwick NS in the **old** set: get
   current A/AAAA from `delegationData`.
4. Diff per-owner:
   - NS in new but not old -> all its A/AAAA are adds
   - NS in old but not new -> all its A/AAAA are
     removes
   - NS in both -> diff A/AAAA per-owner with
     `RRsetDiffer`

This produces correct `GlueAdds` and `GlueRemoves`
with proper owner names in the RR headers.

**Complexity:** Medium. This is the most logic-dense
part.
**Risk:** Medium. Must get the per-owner diffing right.
But `ApplyChildUpdate` already handles per-owner
actions correctly (it dispatches by
`rr.Header().Name`), so as long as we produce correct
Actions, the application side works.

### Step 7: Clean Up Legacy Code — DONE

After `ProcessCSYNCNotify` is working:
- Remove `CheckCSYNC_NG` stub from `scanner.go`
- Decide whether to keep or remove legacy `CheckCSYNC`
  in `scanner_csync.go`. The legacy code might still be
  useful for API-triggered scans (non-NOTIFY path). If
  we keep it, update it to report results via
  `ScanTupleResponse` instead of returning
  `ChildDelegationData`.

**Recommendation:** Keep `scanner_csync.go` for now but
mark `CheckCSYNC` as legacy. The API-triggered scan
path can be updated later.

**Complexity:** Low.
**Risk:** None.

## Code Volume Estimate

| Step | New/Changed Lines | Files |
|------|-------------------|-------|
| 1. ScanTupleResponse fields | ~10 | api_structs.go |
| 2. CurrentScanData + bridge | ~20 | scanner.go |
| 3. ProcessCSYNCNotify | ~150 | scanner.go |
| 4. Dispatch wiring | ~15 | scanner.go |
| 5. OnDelegationChange | ~25 | scanner.go |
| 6. (included in step 3) | — | — |
| 7. Cleanup | ~-10 | scanner.go |
| **Total** | **~210** | **2 files** |

## Implementation Order

1. Step 1 (struct fields) — prerequisite for everything
2. Step 3 (ProcessCSYNCNotify) — core logic, biggest
   piece
3. Step 2 + 4 (bridge + dispatch) — wiring
4. Step 5 (callback) — connects results to zone updater
5. Step 7 (cleanup) — last

Steps 2, 3, 4 can be done together since they're all in
scanner.go and interdependent.

## Risks and Corners

**What could break:**

1. **Glue for removed NS.** When an NS is removed, its
   glue must also be removed. But the glue might be
   shared with another delegation in the same parent
   zone. The `ApplyChildUpdate` path should handle this
   correctly because it operates per-child — it only
   removes glue records at the child's delegation, not
   globally. But this should be verified.

2. **In-bailiwick detection edge cases.** An NS name
   exactly equal to the child zone name (e.g.,
   `child.parent.` is both the delegation point and an
   NS name) — this is valid but unusual.
   `NSInBailiwick` uses `HasSuffix` which would match.
   Verify this works correctly.

3. **Empty NS result.** RFC 7477 says the parent should
   reject an update that would remove all NS records.
   Add a safety check: if new NS set is empty (proven
   by NSEC/NSEC3), abort.

4. **Empty glue result.** RFC 7477 says reject if result
   would eliminate all glue for in-bailiwick NS. Check
   that each in-bailiwick NS has at least one A or AAAA
   after the update.

5. **queryAllNSAndCompare for glue.** The existing
   function queries all NS for a single (qname, rrtype)
   and checks consistency. For glue, we need to query
   each NS for the glue of *another* NS name. This
   works because `queryAllNSAndCompare(childZone,
   nsName, dns.TypeA, ...)` queries all child NS for
   `nsName A` — the child zone is authoritative for its
   own NS names if they're in-bailiwick.

6. **queryAllNSAndCompare called many times.** For a
   child with 4 NS, 2 in-bailiwick, we call it: 1xSOA
   + 1xCSYNC + 1xNS + 2xA + 2xAAAA + 1xSOA = 8 rounds
   of all-NS queries = 32 DNS queries. This is correct
   per RFC 7477 (query all data from authoritative
   servers) but could be slow. Not a problem for
   NOTIFY-triggered scans (infrequent) but worth
   noting.

## DNSSEC Validation

Same situation as CDS: direct queries via `AuthQueryNG`
don't provide DNSSEC validation. RFC 7477 requires all
data to be validated as "Secure". For now, gated by the
`no-dnssec-validation` option.

Future enhancement: query via IMR for DNSSEC validation,
then cross-verify with direct queries for freshness.

## Config

No new config needed. CSYNC scanning uses the same
`scanner.options` as CDS:
- `no-dnssec-validation` — accept without DNSSEC
- `at-apex` / `at-ns` — not applicable to CSYNC (these
  are CDS-specific RFC 8078/9615 mechanisms)

The `immediate`-only restriction is hardcoded (log
warning if CSYNC doesn't have immediate flag). This
could become a config option later if needed.
