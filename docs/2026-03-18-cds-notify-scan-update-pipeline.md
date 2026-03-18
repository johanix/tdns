# CDS/CSYNC NOTIFY → Scan → Parent Zone Update Pipeline

**Date:** 2026-03-18
**Status:** Plan (not started)
**Estimated size:** ~320-370 lines of new/changed code

## Problem

When a child zone publishes CDS records (signaling a DS change),
it sends NOTIFY(CDS) to the parent. The parent should look up
the child's CDS, verify it, convert to DS, compare against what
the parent currently has, and apply the difference — exactly as
if a DNS UPDATE had arrived.

Today this pipeline is broken at multiple points:

1. `NotifyResponder` crashes on nil IMR (race condition on
   startup — already fixed by reading `conf.Internal.ImrEngine`
   at call time instead of capturing at init)
2. `NotifyResponder` uses IMR recursive query to find the parent
   zone (should use local `FindZone` — the auth server knows its
   own zones)
3. Scanner receives `ScanRequest{ChildZone, RRtype}` but loops
   over empty `ScanTuples` — does nothing
4. `CheckCDS` only compares old CDS vs new CDS — doesn't convert
   CDS→DS or compare against parent's current DS
5. No code path from scan results → `ApplyChildUpdate()` on the
   delegation backend

## Design Principles

- **No IMR for CDS queries.** The parent already knows the
  child's nameservers (delegation NS in its own zone data).
  CDS queries go directly to child NS over TCP via
  `AuthQueryNG()`. This bypasses caching and gives fresh
  authoritative answers.
- **Compare against backend, not zone.** The current DS for
  the child comes from `DelegationBackend.GetDelegationData()`,
  not from in-memory zone data.
- **Reuse existing update path.** DS changes are applied via
  `UpdateRequest{Cmd: "CHILD-UPDATE"}` → `ZoneUpdaterEngine`
  → `DelegationBackend.ApplyChildUpdate()`. Same path as
  incoming DNS UPDATEs.
- **Scanner options gate behavior.** DNSSEC validation and
  RFC-specific verification methods are controlled by
  `scanner.options` in config.

## Files to Modify

- `notifyresponder.go` — fix parent zone lookup, add child
  delegation validation
- `scanner.go` — handle NOTIFY-triggered scans, new
  `ProcessCDSNotify` function, scanner options
- `api_structs.go` — add `DS` field to `CurrentScanData`,
  scanner options field
- `config.go` or `parseconfig.go` — read `scanner.options`
  from viper

No changes needed to `zone_updater.go` (existing CHILD-UPDATE
path works as-is).

## Step 1: Fix NotifyResponder Parent Zone Lookup

Replace the IMR-based `ParentZone()` call with local zone
lookup.

**In `notifyresponder.go`, CDS/CSYNC case:**

- Strip first label from qname
- Call `FindZone()` on the remainder to find parent zone
  (walks up labels, handles case-insensitive matching)
- Verify `zd.IsChildDelegation(qname)` — confirms qname is
  a real delegation point in our zone, not a random name
- Remove the IMR `ParentZone()` call and the manual
  `Zones.Get()` lookups

Keep nil IMR guard as secondary defense (already applied).

## Step 2: Scanner Options Config

Add `scanner.options` as a string slice in viper config.

```yaml
scanner:
   interval: 30
   options: [ no-dnssec-validation, at-apex ]
```

**Options:**

- `no-dnssec-validation` — accept CDS without DNSSEC
  validation (debug/lab use only)
- `at-apex` — RFC 8078 opportunistic onboarding: query CDS
  at child apex from all NS, require consistency. For
  bootstrapping (no existing DS), accept without DNSSEC.
- `at-ns` — RFC 9615 authenticated signals: query CDS at
  `_dsboot.<child>._signal.<ns>` under each nameserver's
  zone. Requires DNSSEC validation via the NS zone's chain
  of trust.

Store in `Scanner` struct. Add `scanner.HasOption(name) bool`
helper.

## Step 3: Bridge NOTIFY → ScanTuples

When `ScanRequest` arrives with `ChildZone` + `RRtype` (from
NOTIFY) but empty `ScanTuples`, convert it to a ScanTuple.

- Set `ScanType` based on `RRtype` (CDS → `ScanCDS`,
  CSYNC → `ScanCSYNC`)
- Fetch current DS from `DelegationBackend.GetDelegationData()`
  (compare against backend, not zone)
- Build `ScanTuple{Zone: ChildZone, CurrentData: {DS: currentDS}}`
- Add `DS *core.RRset` field to `CurrentScanData` in
  `api_structs.go`

## Step 4: ProcessCDSNotify — Core Logic (~120-150 lines)

New function in `scanner.go`. All CDS queries go directly to
child nameservers over TCP using `AuthQueryNG()`.

```go
func (scanner *Scanner) ProcessCDSNotify(
    ctx context.Context,
    childZone string,
    parentZD *ZoneData,
    currentDS *core.RRset,
    options *edns0.MsgOptions,
) (dsAdds []dns.RR, dsRemoves []dns.RR, err error)
```

**Logic:**

1. **Get child NS from parent zone data.**
   `parentZD.GetOwner(childZone)` → NS RRset. These are the
   delegation NS records the parent already has.

2. **Query CDS from all child NS via AuthQueryNG/TCP.**
   Default behavior: query each NS, require all to return
   identical CDS (reuses `queryAllNSAndCompare` pattern).
   Optionally dispatch to RFC-specific methods (steps 6-7).

3. **Validate DNSSEC** (unless `no-dnssec-validation` option).
   Check RRSIG on the CDS RRset returned by child NS. If
   existing DS: require validation. If bootstrapping + at-apex:
   skip (opportunistic). If at-ns: signaling queries validated
   via NS zone's chain of trust.

4. **Handle CDS removal sentinel.** CDS containing
   `0 0 0 0` (algorithm 0) signals "remove all DS" per
   RFC 8078. Must be DNSSEC-validated and existing DS must
   be present.

5. **Convert CDS → DS.** Wire format is identical — create DS
   RR with same rdata, different type code. (miekg/dns: CDS
   embeds DS struct.)

6. **Compare new DS vs current DS** (from backend). Use
   `core.RRsetDiffer()` to compute adds and removes.

## Step 5: Apply DS Changes via Delegation Backend

After `ProcessCDSNotify` returns adds/removes:

- Build `[]dns.RR` actions: adds with `ClassINET`, removes
  with `ClassNONE`
- Enqueue `UpdateRequest{Cmd: "CHILD-UPDATE", InternalUpdate: true,
  Trusted: true}` to `kdb.UpdateQ`
- `ZoneUpdaterEngine` dispatches to
  `DelegationBackend.ApplyChildUpdate()` (existing path at
  `zone_updater.go:110`)

Scanner needs access to `kdb.UpdateQ` — pass via `Scanner`
struct or `conf.Internal`.

## Step 6: RFC 9615 Signaling Name Queries (at-ns option)

New helper `queryCDSAtSignalingNames()`.

For each NS in the child's delegation:
- Skip in-bailiwick NS (under childZone — can't be
  independently authenticated)
- Build signaling name:
  `_dsboot.<childZone>._signal.<ns-hostname>`
- Query CDS at signaling name via IMR (DNSSEC-validated).
  Note: signaling names live in the NS operator's zone,
  not the child — so IMR is correct here (we need the NS
  zone's DNSSEC chain of trust).
- Require `resp.Validated == true`
- Also query CDS directly at child apex from each NS via
  AuthQueryNG/TCP (step 2 of RFC 9615)
- Verify signaling responses match direct responses
- Require ALL out-of-bailiwick NS to agree

## Step 7: RFC 8078 Opportunistic Onboarding (at-apex option)

Essentially the `queryAllNSAndCompare` pattern with
bootstrapping awareness.

- Query CDS from all child NS directly (AuthQueryNG/TCP,
  not cached)
- Require all to return identical CDS
- If bootstrapping (no existing DS): log opportunistic
  onboarding, proceed without DNSSEC validation
- If existing DS: require DNSSEC validation (unless
  `no-dnssec-validation`)
- Time-delay requirement (multiple checks over hours/days)
  is a future enhancement — TODO in code.

## Implementation Order

1. **Step 2**: Scanner options config (small, enables rest)
2. **Step 1**: Fix NotifyResponder parent zone lookup
3. **Step 3**: Bridge NOTIFY → ScanTuples
4. **Step 4**: `ProcessCDSNotify` (direct queries to child NS)
5. **Step 5**: Apply DS changes via UpdateRequest → backend
6. **Step 7**: RFC 8078 at-apex multi-NS verification
7. **Step 6**: RFC 9615 at-ns signaling name queries

Steps 1-5 (~210-240 lines) give a working end-to-end pipeline.
Steps 6-7 (~110-130 lines) add RFC-specified verification.

## CSYNC (Future)

CSYNC follows the same pattern but updates NS/A/AAAA instead
of DS. The CSYNC RR contains a bitmap of which types to sync.
Deferring CSYNC to a follow-up — CDS is the priority.

## Existing Code to Reuse

- `FindZone()` — `zone_utils.go:872`: walks up labels to find
  authoritative zone
- `IsChildDelegation()` — `zone_utils.go:739`: verifies qname
  is a delegation point
- `AuthQueryNG()` — `rrset_utils.go:257`: direct DNS query to
  specific NS over TCP, preserves RRSIGs
- `queryAllNSAndCompare()` — `scanner.go:321`: queries all NS
  for an RRtype, checks consistency
- `core.RRsetDiffer()` — compares two RRsets, returns
  adds/removes
- `DelegationBackend.GetDelegationData()` —
  `delegation_backend_db.go:91`: retrieves current delegation
  RRs from DB
- `ZoneUpdaterEngine` CHILD-UPDATE path —
  `zone_updater.go:110`: applies delegation changes via
  backend

## Verification

1. Configure authv2 with a parent zone and child delegations
2. Configure `scanner.options: [no-dnssec-validation]` for
   initial testing
3. Send `NOTIFY(CDS)` to authv2 for a child zone
4. Verify log shows: parent zone found locally, child
   validated, scanner receives request, CDS queried from
   child NS, DS compared, CHILD-UPDATE applied via backend
5. Check DB: `SELECT * FROM ChildDelegationData WHERE child=?`
   shows updated DS
6. Enable DNSSEC validation, repeat with signed child zone
7. Test at-apex option with multiple child NS
8. Test at-ns option with signaling names
