# Message-Type-Specific Confirmations + Remote Agent Two-Phase Confirmation

Date: 2026-02-13

## Context

### Problem: Confirmation is sync-only

The combiner's confirmation framework is hardcoded for sync messages. All responses — including errors for ping, beat, and unknown message types — flow through `sendErrorResponse()` (combiner_chunk.go) which always builds a `CombinerSyncResponse` and calls `sendConfirmResponse()`. This produces:

1. **Misleading logging**: `Sending confirmation for distribution 698de7fc zone "" status=error applied=0 removed=0 rejected=0` — applied/removed/rejected are meaningless for a ping error
2. **Broken ping error path**: The agent's ping sender calls `extractPingConfirmFromResponse()` which parses the response as `DnsPingConfirmPayload`. A sync-shaped error response has no nonce → "nonce mismatch"

**Current state of per-type handling**:
- `handlePing()` success path: builds its own `ping_confirm` with nonce, writes directly. **Correct.**
- `handlePing()` error path: calls `sendErrorResponse` → sync-shaped response. **Broken.**
- `handleBeat()` success path: builds its own `confirm` with beat message, writes directly. **Correct.**
- `handleBeat()` error path: calls `sendErrorResponse` → sync-shaped response. **Wrong shape.**
- Sync error path: calls `sendErrorResponse` → sync-shaped response. **Acceptable** (sync errors can legitimately use sync confirmation shape).

### Goal

Make error responses message-type-aware so each message type gets an appropriate error response shape. Then proceed with the remote agent two-phase confirmation work.

### Remote agent confirmations

**Remote agent confirmations are completely discarded.** `deliverToAgent()` in hsync_transport.go ignores the sync response.

**Goal**: Two-phase confirmation from remote agents:
1. **Immediate confirmation** (first unsolicited NOTIFY): "I received your sync and am working on it — don't resend."
2. **Final confirmation** (second unsolicited NOTIFY, same distID): "My combiner confirmed — here's per-RR detail."

### Why Two NOTIFYs

All NOTIFYs are "unsolicited" — each initiates a message exchange (NOTIFY + DNS response). The distinction matters for reliability:

- **Without first NOTIFY**: Originating agent doesn't know if the sync arrived, got lost, or was eaten by a grue. Must timeout and resend.
- **With first NOTIFY**: Originating agent knows the remote agent received the sync and is processing it. No resend needed.
- **Second NOTIFY**: Carries the actual per-RR detail (applied/removed/rejected) from the remote agent's combiner.

### Infrastructure Already Exists

- `DNSTransport.Confirm()` (dns.go) — sends NOTIFY(CHUNK) with `type:"confirm"` in EDNS0
- `handleConfirmation()` (chunk_notify_handler.go) — receives confirm NOTIFYs, routes to `OnConfirmationReceived`
- `OnConfirmationReceived` (hsync_transport.go) — forwards to SynchedDataEngine Confirmation channel
- `sendSyncConfirmation()` (hsync_transport.go) — exists but **never called**, only sends bare "success"
- `DnsConfirmPayload` (dns.go) — already has `AppliedRecords`, `RemovedRecords`, `RejectedItems`, `Truncated`

### Shared DistID Design

Currently: `EnqueueForCombiner` generates distID "A", `EnqueueForZoneAgents` generates separate distIDs "B", "C" per agent. `MarkRRsPending` only tracks distID "A".

**Change**: Generate one distID, use it for combiner + all agents. ReliableMessageQueue changes deferred to later.

## Implementation

### Phase 0: Message-type-specific responses on the combiner

**Files**: combiner_chunk.go, agent/transport/dns.go

**Design principle**: Each message type uses the *same* response struct for both success and error. The response struct has a `Status` field — the handler sets `Status:"error"` and a `Message` with the error description. No separate error functions. The receiving agent parses one struct and checks `Status`. This follows the TDNS `Error: bool` / `ErrorMsg: string` pattern.

**For `handlePing` errors**: Instead of calling `sendErrorResponse`, build the same `ping_confirm` struct used by the success path but with `Status:"error"` and the error in a `Message` field.

**For `handleBeat` errors**: Same approach — use the beat confirm struct with `Status:"error"`.

**For pre-parse errors**: At these points the combiner hasn't parsed the payload, so it doesn't know the message type. It also can't reliably send a response (the CHUNK query failure means the underlying transport is broken — any error response would likely share the same fate). **Log and return an error** (don't attempt to send a response). The agent will timeout and retry.

**For sync errors and unknown message type**: Keep using `sendErrorResponse` → `sendConfirmResponse` (sync-shaped). This is the correct shape for sync errors, and for unknown message types the sync shape is the best we can do.

**Extract `sendGenericEdns0Response()` helper** to deduplicate the EDNS0 response building pattern used by handlePing success, handleBeat success, sendConfirmResponse, and the new per-type error paths.

**Agent-side fix** (dns.go): Reorder checks in `Ping()` — check status *before* nonce. Currently if the combiner sends `status:"error"` with empty nonce, the agent gets "nonce mismatch" instead of the actual error. Add `Message` field to `DnsPingConfirmPayload`.

### Phase 1: Enrich `ConfirmRequest` with per-RR detail

**Files**: transport.go, dns.go

Add `AppliedRecords`, `RemovedRecords`, `RejectedItems`, `Truncated` fields to `ConfirmRequest`. Populate `DnsConfirmPayload` from `ConfirmRequest` in `DNSTransport.Confirm()`. Add size guard: if payload > 3500 bytes, nil out applied/removed records, set Truncated.

### Phase 2: Plumb `senderID` and `removed` through confirmation callback

**Files**: chunk_notify_handler.go, hsync_transport.go

Add `senderID` and `removed []string` to `OnConfirmationReceived` callback signature. Update `handleConfirmation()` call to pass both. Update wiring in hsync_transport.go.

### Phase 3: Shared distID — generation and usage

**Files**: hsync_transport.go, syncheddataengine.go

`EnqueueForCombiner` and `EnqueueForZoneAgents` accept distID parameter. Generate distID once in SynchedDataEngine, pass to both.

### Phase 4: Plumb originating distID through remote agent

**Files**: structs.go, hsync_transport.go, syncheddataengine.go, hsyncengine.go

Add `DistributionID` to `AgentMsgPost`. Set it in `routeSyncMessage()`. Add `OriginatingDistID` to `SynchedDataUpdate`. Pass through in `MsgHandler()`.

### Phase 5: Remote agent sends first NOTIFY (immediate ACK)

**Files**: hsync_transport.go, transport.go

After routing the sync to `agentQs.Msg`, send immediate "pending" confirmation back via `sendImmediateConfirmation()`. Add `ConfirmPending` status.

### Phase 6: Remote agent tracks and sends second NOTIFY (final)

**File**: syncheddataengine.go

Add `PendingRemoteConfirms` map to `ZoneDataRepo`. After combiner enqueue for remote updates, store mapping from combiner distID to originating distID/sender. In `ProcessConfirmation()`, check for pending remote confirms and trigger `OnRemoteConfirmationReady` callback.

### Phase 7: Wire callback — send final confirmation back

**File**: hsync_transport.go

Wire `OnRemoteConfirmationReady`. Replace `sendSyncConfirmation()` with `sendRemoteConfirmation()` that sends per-RR detail back to the originating agent using the originating distID.

### Phase 8: Originating agent processes both NOTIFYs

**File**: syncheddataengine.go

First NOTIFY (status="pending"): early return in `ProcessConfirmation`, log "pending confirmation from [agent]". Second NOTIFY (status="ok"/"partial"/"error"): match RRs by distID, handle already-confirmed RRs with informational logging.

### Phase 9: Operational diagnostic tools

**Files**: error_journal.go (new), combiner_chunk.go, apihandler_transaction.go (new), cli/transaction_cmds.go (new), apirouters.go, shared_cmds.go

**Error journal** (`ErrorJournal`): Bounded ring buffer (default 1000 entries, 24h max age), thread-safe. Attached to `CombinerChunkHandler`. Records errors at every error point in `HandleChunkNotify`: pre-parse failures, ping/beat errors, sync parse failures, sync processing errors, unknown message types. Sender identity extracted from QNAME control zone even for pre-parse failures.

**CLI commands (agent)**:
- `agent transaction open outgoing` — filters existing DistributionCache to non-confirmed only, shows Age instead of Time
- `agent transaction open incoming` — queries `PendingRemoteConfirms` on the agent side, shows Sender and Zone

**CLI commands (combiner)**:
- `combiner transaction errors --last 30m` — lists recent errors from the ErrorJournal. Output: DistID, Age, Sender, Operation, QNAME CHUNK
- `combiner transaction errors details --distid {distid}` — looks up a specific distID in the error journal, returns full detail or "no record" (which itself is diagnostic)

## Files Summary

| File | Changes |
|------|---------|
| combiner_chunk.go | Per-type error responses (ping/beat use own struct with Status:"error"); pre-parse errors log-only; `sendGenericEdns0Response` helper; `ErrorJournal` field; `recordError()` calls at all error points |
| error_journal.go | **New**: `ErrorJournal` bounded ring buffer; `ErrorJournalEntry`; `Record()`, `ListSince()`, `LookupByDistID()` |
| agent/transport/dns.go | Reorder status/nonce checks in `Ping()`; add `Message` to `DnsPingConfirmPayload`; populate per-RR fields in `Confirm()`; add size guard |
| agent/transport/transport.go | Add per-RR fields to `ConfirmRequest`; add `ConfirmPending` status |
| agent/transport/chunk_notify_handler.go | Add `removed`, `senderID` to `OnConfirmationReceived`; pass in `handleConfirmation` |
| hsync_transport.go | Shared distID in enqueue functions; `sendImmediateConfirmation()`; `sendRemoteConfirmation()`; plumb distID in `routeSyncMessage`; wire callbacks |
| hsyncengine.go | Pass `DistributionID` through `MsgHandler` |
| syncheddataengine.go | Shared distID generation; `PendingRemoteConfirms` map; `RemoteConfirmationDetail`; `OnRemoteConfirmationReady` callback; forward in `ProcessConfirmation`; early return for "pending"; additional-confirmation logging; add `OriginatingDistID` to `SynchedDataUpdate` |
| agent_structs.go | Add `DistributionID` to `AgentMsgPost` |
| apihandler_transaction.go | **New**: `APIagentTransaction()`, `APIcombinerTransaction()` handlers; `TransactionPost`, `TransactionResponse` structs |
| cli/transaction_cmds.go | **New**: `agent transaction open outgoing`, `agent transaction open incoming`, `combiner transaction errors`, `combiner transaction errors details` |
| apirouters.go | Register `/agent/transaction` and `/combiner/transaction` endpoints |

## Verification

```bash
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
```

End-to-end test (4 processes: agent A, agent B, combiner A, combiner B):
1. Agent A: `add-ns --rr "whisky.dnslab. 300 IN NS ns1.test."`
2. Agent A logs: "pending confirmation from [agent-B]" (first NOTIFY — delivery confirmed)
3. Agent A logs: "Received confirmation from [combiner-A]" (combiner confirmed)
4. Agent A logs: "Received confirmation from [agent-B]" with per-RR detail (second NOTIFY)
5. Agent A `show-synced-data`: `accepted`
6. Agent A: `del-ns --rr "whisky.dnslab. 300 IN NS ns1.test."`
7. Agent A logs: pending from agent-B → combiner-A removal confirmed → agent-B removal confirmed
8. Agent A `show-synced-data`: `removed`
9. Both combiners: `show-combiner-data` no longer includes ns1
