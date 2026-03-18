# CDS/CSYNC NOTIFY → Scan → Parent Zone Update Pipeline

**Date:** 2026-03-18
**Status:** All steps implemented

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
- **Read-only scanner.** The scanner queries, compares, and
  reports results (DS adds/removes) but never writes. The
  caller is responsible for applying changes. This enables
  future extraction of the scanner into a separate application
  where scan requests arrive over an API instead of a channel.
- **Scanner options gate behavior.** DNSSEC validation and
  RFC-specific verification methods are controlled by
  `scanner.options` in config.

## Architectural Decision: Read-Only Scanner

The original plan had the scanner directly enqueue
`UpdateRequest` to `kdb.UpdateQ` (step 5). This was revised
because the scanner will likely be extracted into a separate
application in the future.

**New design:** `ProcessCDSNotify` returns DS adds/removes in
`ScanTupleResponse.DSAdds` and `ScanTupleResponse.DSRemoves`.
The authserver code that consumes scanner results is
responsible for enqueuing `CHILD-UPDATE` requests. When the
scanner becomes a standalone app, the authserver will poll its
API for results instead of reading from a channel.

This means:
- Scanner struct has no reference to `UpdateQ` or `KeyDB`
- `ScanTupleResponse` carries `DSAdds []dns.RR` and
  `DSRemoves []dns.RR` fields
- Step 5 moves from scanner internals to a consumer/callback
  in the authserver

## Files Modified

- `notifyresponder.go` — replaced IMR parent zone lookup with
  local `FindZone` + `IsChildDelegation`, removed `imr`
  parameter
- `scanner.go` — `Options` field + `HasOption()`, NOTIFY→tuple
  bridge, `ProcessCDSNotify` function, dispatch branching
- `api_structs.go` — `DS` field on `CurrentScanData` +
  `CurrentScanDataJSON`, `DSAdds`/`DSRemoves` on
  `ScanTupleResponse`, `dns` import
- `tdns-es/es/notify_router.go` — updated `NotifyResponder`
  call site (removed `imr` parameter)

## Step 1: Fix NotifyResponder Parent Zone Lookup — DONE

Replaced IMR-based `ParentZone()` call with local zone lookup.

**In `notifyresponder.go`, CDS/CSYNC case:**

- Strip first label from qname via `strings.SplitN`
- Call `FindZone()` on the remainder to find parent zone
  (walks up labels, handles case-insensitive matching)
- Verify `zd.IsChildDelegation(qname)` — confirms qname is
  a real delegation point in our zone, not a random name
- Removed `imr *Imr` parameter entirely — no longer needed
  by any code path in `NotifyResponder`

## Step 2: Scanner Options Config — DONE

Added `scanner.options` as a string slice in viper config.

```yaml
scanner:
   interval: 30
   options: [ no-dnssec-validation ]
   # options: [ at-apex ]        # RFC 8078
   # options: [ at-ns ]          # RFC 9615
   at-apex:
      checks:    1     # consecutive all-NS checks (default: 1)
      interval:  300   # seconds between checks (default: 300)
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
  of trust (checked via `ImrResponse.Validated`).

**At-apex time-delay (RFC 8078 §3.3):**

- `scanner.at-apex.checks` — number of consecutive
  all-NS checks before accepting CDS (default: 1)
- `scanner.at-apex.interval` — seconds between checks
  (default: 300 = 5 minutes)
- Currently only one check is performed regardless of
  config; repeated checks are a future enhancement.

Stored in `Scanner.Options []string`,
`Scanner.AtApexChecks int`,
`Scanner.AtApexInterval time.Duration`. Helper method
`scanner.HasOption(name) bool` does case-insensitive match.
Read from viper in `ScannerEngine` at startup.

Sample config: `cmdv2/authv2/tdns-auth.sample.yaml`.

## Step 3: Bridge NOTIFY → ScanTuples — DONE

When `ScanRequest` arrives with `ChildZone` + `RRtype` (from
NOTIFY) but empty `ScanTuples`, the `ScannerEngine` dispatcher
synthesizes a tuple before the main processing loop.

- Maps `RRtype` → `ScanType` (CDS→ScanCDS, CSYNC→ScanCSYNC,
  DNSKEY→ScanDNSKEY)
- Fetches current DS from
  `DelegationBackend.GetDelegationData()` and populates
  `tuple.CurrentData.DS`
- Builds `ScanTuple{Zone: ChildZone, CurrentData: {DS: ...}}`
- Sets `sr.ScanTuples = []ScanTuple{tuple}`

Added `DS *core.RRset` field to `CurrentScanData` in
`api_structs.go` (with corresponding JSON serialization).

## Step 4: ProcessCDSNotify — Core Logic — DONE

New function in `scanner.go` (~120 lines). Dispatched when
`sr.ZoneData != nil` (NOTIFY path with parent zone data).
Existing `CheckCDS` still used for API-triggered scans.

```go
func (scanner *Scanner) ProcessCDSNotify(
    ctx context.Context,
    tuple ScanTuple,
    parentZD *ZoneData,
    scanType ScanType,
    options *edns0.MsgOptions,
    responseCh chan<- ScanTupleResponse,
)
```

**Logic:**

1. **Get child NS from parent zone data.**
   `parentZD.GetOwner(childZone)` → NS RRset. These are the
   delegation NS records the parent already has.

2. **Query CDS from all child NS via AuthQueryNG/TCP.**
   Reuses `queryAllNSAndCompare`. Requires all NS to return
   identical CDS; aborts if not in sync.

3. **Handle CDS removal sentinel.** CDS containing
   algorithm 0 signals "remove all DS" per RFC 8078. Returns
   all current DS as `DSRemoves`.

4. **Convert CDS → DS.** Creates `dns.DS` with same
   KeyTag/Algorithm/DigestType/Digest, different type code.

5. **Compare new DS vs current DS** (from backend). Uses
   `core.RRsetDiffer()` to compute adds and removes.

6. **Report results** in `ScanTupleResponse`: `DSAdds`,
   `DSRemoves`, `DataChanged`, `NewData` (CDS + computed DS).

DNSSEC validation is not yet implemented — gated by
`no-dnssec-validation` option (steps 6-7).

## Step 5: Apply DS Changes via Caller — DONE

**Revised from original plan.** The scanner no longer applies
changes directly. Instead, a callback closure in the
authserver consumes scan results and enqueues updates.

**Implementation:**

- Added `OnDSChange func(parentZone string, zd *ZoneData,
  resp ScanTupleResponse)` callback field to `Scanner` struct
- Callback wired in `ScannerEngine`: builds Actions array
  (`ClassINET` for adds, `ClassNONE` for removes), enqueues
  `UpdateRequest{Cmd: "CHILD-UPDATE", UpdateType: "CDS",
  Trusted: true, InternalUpdate: true}` to `kdb.UpdateQ`
- Called from job-completion goroutine for responses with
  DS changes
- Scanner remains read-only — the callback closure captures
  the authserver context (kdb, zone data)

## Step 6: RFC 9615 Signaling Name Queries (at-ns) — DONE

New helper `queryCDSAtSignalingNames()` (~70 lines).

**Implementation:**

- Skips in-bailiwick NS (under childZone) using
  `dns.IsSubDomain` — can't be independently
  authenticated
- Builds signaling name:
  `_dsboot.<child>._signal.<ns>`
- Queries CDS at signaling name via IMR (for NS zone's
  DNSSEC chain of trust)
- Requires all out-of-bailiwick NS signaling responses
  to agree
- Cross-verifies signaling CDS matches direct CDS from
  child NS (queried in step 4)
- Integrated into `ProcessCDSNotify`'s validation gate:
  when `at-ns` option set, signaling verification runs
  before CDS→DS conversion
- Checks `resp.Validated` on IMR responses — rejects
  unvalidated signaling CDS (unless
  `no-dnssec-validation` option set)

## Step 7: RFC 8078 Opportunistic Onboarding (at-apex) — DONE

**Implementation:**

- Bootstrapping detection added to `ProcessCDSNotify`
  (no existing DS = bootstrapping)
- When `at-apex` option set and bootstrapping: accepts
  CDS without DNSSEC validation per RFC 8078
- When existing DS: DNSSEC validation of direct CDS
  queries not yet implemented (would need IMR path
  instead of AuthQueryNG). Logged and proceeds.
- All NS consistency already enforced by
  `queryAllNSAndCompare`
- Time-delay config: `scanner.at-apex.checks` (default
  1) and `scanner.at-apex.interval` (default 300s).
  Currently only one check is performed; logs a message
  when `checks > 1` noting the limitation.

## Implementation Order

1. **Step 2**: Scanner options config — DONE
2. **Step 1**: Fix NotifyResponder parent zone lookup — DONE
3. **Step 3**: Bridge NOTIFY → ScanTuples — DONE
4. **Step 4**: `ProcessCDSNotify` — DONE
5. **Step 5**: Apply DS changes (callback consumer) — DONE
6. **Step 7**: RFC 8078 at-apex multi-NS verification — DONE
7. **Step 6**: RFC 9615 at-ns signaling name queries — DONE

Steps 1-4 (~200 lines) give a working scan pipeline that
reports DS changes. Step 5 (~30 lines) connects scan
results to the delegation backend via callback. Steps 6-7
(~100 lines) add RFC-specified verification.

## CSYNC (Future)

CSYNC follows the same pattern but updates NS/A/AAAA instead
of DS. The CSYNC RR contains a bitmap of which types to sync.
Deferring CSYNC to a follow-up — CDS is the priority.

## Existing Code Reused

- `FindZone()` — `zone_utils.go:872`: walks up labels to find
  authoritative zone
- `IsChildDelegation()` — `zone_utils.go:739`: verifies qname
  is a delegation point
- `AuthQueryNG()` — `rrset_utils.go:257`: direct DNS query to
  specific NS over TCP, preserves RRSIGs
- `queryAllNSAndCompare()` — `scanner.go`: queries all NS
  for an RRtype, checks consistency
- `core.RRsetDiffer()` — compares two RRsets, returns
  adds/removes
- `DelegationBackend.GetDelegationData()` —
  `delegation_backend_db.go`: retrieves current delegation
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
   validated as delegation point, scanner synthesizes tuple,
   CDS queried from child NS, CDS→DS converted, DS diffed
5. Verify `ScanTupleResponse` contains correct `DSAdds` and
   `DSRemoves`
6. (After step 5) Check DB:
   `SELECT * FROM ChildDelegationData WHERE child=?` shows
   updated DS
7. Test at-apex option with multiple child NS
8. Test at-ns option with signaling names
