# Code Review Triage: Agree/Disagree Assessment

Date: 2026-03-18

## Context

Code review with ~30 findings across multiple files. Each finding
verified against current code. Findings marked "agree" are real
bugs or clear improvements worth fixing. Findings marked "disagree"
are either not bugs, acceptable design choices, or not worth the
added complexity.

---

## Findings: AGREE (all fixed)

### 1. [DONE] delegation_backend.go:141-145 — TTL mutation of live zone RRs
The loop sets `rr.Header().Ttl = defaultTTL` directly on RRs from
`DirectDelegationBackend`'s zone data. This mutates live zone
objects. Fix: `dns.Copy(rr)` before modifying TTL.

### 2. [DONE] apihandler_funcs.go:339 — nil pointer panic in status timeout
The timeout branch does `resp.ErrorMsg = err.Error()` but `err` is
never assigned in this scope. Will panic on timeout. Fix: use a
string literal.

### 3. [DONE] agent/transport/dns.go:940-947 — SendStatusUpdate ignores Rcode
`sendNotifyWithPayload` and `Ping` both check `res.Rcode`, but
`SendStatusUpdate` discards the response with `_, _, err =`. Fix:
capture `res`, check `res.Rcode != dns.RcodeSuccess`.

### 4. [DONE] cli/parentsync_cmds.go:355-359 — uninitialized `scheme` variable
`schemestr` is bound to the `--scheme` flag but never converted to
`scheme uint8`. `SendDelegationCmd` always gets `scheme=0`. Same
pattern exists in `ddns_cmds.go`. Fix: parse `schemestr` into
`scheme` before the call.

### 5. [DONE] combiner_chunk.go:338-342 — detectDelegationChanges fires on replays
`AppliedRecords` is intentionally populated even for idempotent
operations (for SDE PENDING->ACCEPTED transitions). But
`detectDelegationChanges` inspects `AppliedRecords` to decide
whether to fire parent sync notifications. Result: replayed data
triggers spurious delegation change notifications. Fix: gate on
the `dataChanged` bool from the mutation path.

### 6. [DONE] delegation_sync.go:608-617 — CSYNC NOTIFY misses pure glue changes
Gate only checks `NsAdds/NsRemoves`. Pure A/AAAA glue changes
(without NS changes) won't trigger CSYNC NOTIFY. The
`DelegationSyncStatus` struct has `AAdds`, `ARemoves`, `AAAAAdds`,
`AAAARemoves` fields. Fix: add glue fields to the OR condition.

### 7. [DONE] delegation_utils.go:122-126 — AuthQuery error conflated with "no DS"
When `AuthQuery` fails with an error, `p_dsrrs` is nil and the DS
comparison is silently skipped -- same path as "parent has no DS".
This could lead to incorrect InSync assessment. Fix: only treat as
"no DS" when `err == nil && len(p_dsrrs) == 0`.

### 8. [DONE] hsync_transport.go:1781-1795 — EnqueueForSpecificAgent nil deref
`GetQueueStats` already guards `tm.reliableQueue != nil` but
`EnqueueForSpecificAgent` doesn't. Fix: add nil check, return
error.

### 9. [DONE] parseoptions.go:116-120 — Replace mode accepted but rejected at runtime
Config parser accepts `UpdateModeReplace` for `authOpt` but
`SyncZoneDelegationViaUpdate` rejects it with an error at runtime.
Fix: fail early at config parse time, reject replace, only accept
delta.

### 10. [DONE] config.go:151 — AddSignature/CombinerOptions inconsistency
The reconciliation logic already exists in `parseoptions.go`
(migrates `AddSignature` -> `CombinerOptions`). The real bug is
that two call sites still read from the deprecated `AddSignature`
bool directly: `combiner_utils.go:728` (`InjectSignatureTXT`) and
`main_initfuncs.go:652` (log statement). Fix: change both to read
`CombinerOptions[CombinerOptAddSignature]`.

### 11. [DONE] zone_updater.go:138-156 — Delegation sync enqueued before mutation
`ZoneUpdateChangesDelegationDataNG` + enqueue to `DelegationSyncQ`
+ `PublishCsyncRR` all happen before `ApplyZoneUpdateToZoneData`.
If the apply fails, we've already enqueued a sync for changes that
didn't happen. Fix: move delegation sync logic after successful
apply.

### 12. [DONE] zone_updater.go:894-898 — ClassANY DNSKEY removal doesn't record removes
ClassNONE DNSKEY removal (line 854-858) correctly appends to
`DNSKEYRemoves`, but ClassANY (remove entire RRset, line 894-898)
only sets `InSync=false` without recording what was removed or
clearing `NewDS`. Fix: populate `DNSKEYRemoves` from existing
RRset and set `NewDS = nil`.

### 13. [DONE] zone_updater.go:1199-1221 — computeNewDS ignores pending changes
Derives DS from current apex DNSKEYs, not the post-update set. If
`DNSKEYAdds`/`DNSKEYRemoves` exist in `dss`, the computed DS won't
reflect them. Fix: build effective DNSKEY set by applying
adds/removes before computing DS.

### 14. [DONE] sign.go:52-85 — Signing logs too noisy at Info level
Five Info-level logs per message signing including hex dumps of
packed message buffers. Fix: change to Debug level.

---

## Findings: DISAGREE (won't fix)

### cli/parentsync_cmds.go:291-294 — Missing --zone flag
The commands use `PrepArgs("zonename")` which sets
`tdns.Globals.Zonename` from positional args. This is the
established CLI pattern in this codebase.

### combiner_chunk.go:549-552 — senderID vs delivering agent
The combiner receives updates directly from agents. The `senderID`
IS the agent that delivered the update. There's no "forwarding" in
the combiner path. The STATUS-UPDATE goes back to the sender, which
is correct.

### combiner_chunk.go:643-644 — Thread root context through call chain
The `context.Background()` with 5s timeout in
`sendDelegationStatusUpdate` is fire-and-forget by design (runs in
a goroutine). Threading a parent context would couple the
notification lifetime to the message processing lifetime, which
isn't desirable. The goroutine should complete independently.

### combiner_msg_handler.go:91-96 — Channel receive comma-ok pattern
These channels use pointer types. When closed, receive returns nil,
which the existing `if item == nil { continue }` handles correctly.
The comma-ok pattern is marginally safer but the current code is
not buggy.

### delegation_sync.go:109-110 — notifyPeersParentSyncDone context
Same reasoning as combiner context threading. These are
fire-and-forget notifications with their own 5s timeout.
Independent context is appropriate.

### hsyncengine.go:131-136 — Blocking send to DelegationSyncQ
`DelegationSyncQ` is a buffered channel and the consumer
(`DelegationSyncher`) drains it continuously. Blocking here is
acceptable backpressure. A non-blocking send that drops requests
would be worse.

### hsyncengine.go:113-116 — StatusUpdate comma-ok pattern
Same as combiner_msg_handler. Nil check is sufficient.

### syncheddataengine.go:324-363 — Hydration loop context threading
The hydration loop runs at startup before the system is serving.
Adding context threading to `RequestAndWaitForEdits` and
`RequestAndWaitForKeyInventory` is a larger refactor. The 15s
internal timeouts prevent permanent blocking. Not a practical
issue.

### updateresponder.go:177-200 — Ancestor walk misses delegation point
The reviewer claims self-referential NS glue (`child.example. A
...` where `child.example.` is the delegation point) would be
misclassified. But the NS record for that delegation IS handled at
line 164-166 (`IsChildDelegation(ownerName)`), and the glue A
record at the delegation point itself is correctly classified as a
zone update (it lives in the parent zone's authoritative data).
The current behavior is defensible.

### zone_updater.go:473-475 — TTL normalization breaks exact-delete
Verified that `RemoveRR` uses `dns.IsDuplicate()` which explicitly
ignores TTL. TTL normalization does not affect delete matching.
**This finding is factually wrong.**

### db_schema_hsync.go:289-296 — DATETIME vs INTEGER timestamp
Cosmetic schema inconsistency. SQLite is type-flexible and both
work. Not worth a migration.

### parentsync_bootstrap.go:85-101 — Blocking send to DelegationSyncQ
Same reasoning as hsyncengine. Buffered channel with active
consumer. Backpressure is appropriate.

### syncheddataengine.go:740-747 — Key tag collision in buildKeyStates
Key tag collisions are theoretically possible but extremely rare in
practice (1-in-65536). This is a display/status function, not a
security-critical path. The complexity of composite keys isn't
justified.

### combiner_chunk.go:1778-1800 — warnNSTargetUnresolvable false positives
This is a warning log, not a blocking check. False positives on
batch operations are harmless -- the warning helps catch real
misconfigurations. Adding pending-batch awareness adds complexity
for minimal benefit.
