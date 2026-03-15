# Parent Sync End-to-End: From KEY Publication to Delegation Management

**Date:** 2026-03-15
**Status:** Plan
**Depends on:** SIG(0) KEY Publication via Combiner (DNS-147/148/149, completed)

## Context

The SIG(0) KEY is now published by the combiner at both `at-apex` (MP zone) and `at-ns`
(`_signal` names in provider zones). The next step is wiring up the full parent sync flow:
child agent bootstraps trust with the parent, parent verifies the key, and eventually the
child can send signed UPDATEs to manage its delegation data.

Reference: `drafts/draft-ietf-dnsop-delegation-mgmt-via-ddns/draft-ietf-dnsop-delegation-mgmt-via-ddns-01.md`

## Current State

### What works
- KEY generation, publication to combiner, and distribution to provider zones
- `BootstrapSig0KeyWithParent()` — sends self-signed UPDATE to parent's DSYNC target
- `UpdateResponder` — parent receives UPDATEs, validates SIG(0), stores in TrustStore
- DSYNC RRset publication on parent side
- `LookupDSYNCTarget()` — child discovers parent's UPDATE target via DSYNC DNS queries
- KeyState EDNS(0) wire format and response signing on parent side
- `UpdateKeyState()` — child queries parent for key status via KeyState EDNS(0)

### What's missing or broken
- **Gap 1:** `onLeaderElected` publishes KEY but never triggers `BootstrapSig0KeyWithParent()`
- **Gap 2:** Parent stores child's self-signed KEY in TrustStore as `trusted=false` but never
  verifies it via DNS lookup (no at-apex or at-ns key lookup on parent side)
- **Gap 3:** `ProcessKeyState` auto-bootstrap path has a TODO — not implemented
- **Gap 4:** HSYNCPARAM `parentsync` field is parsed but not used in any control flow
- **Gap 5:** No CLI tooling for debugging KeyState inquiries
- **Gap 6:** Parent can only "direct insert" verified UPDATEs into the zone — no other output methods

## Stages

### Stage 1: Wire Child Agent to Trigger Bootstrap

**Goal:** After the multi-provider agent publishes its KEY via the combiner, it should
automatically bootstrap trust with the parent by sending a self-signed UPDATE.

#### 1a. KeyState inquiry before bootstrap

In `onLeaderElected` (main_initfuncs.go), after the KEY is confirmed published by the
combiner, the agent should NOT immediately bootstrap. In most cases the key is already
bootstrapped and trusted by the parent (e.g. agent restart). The correct flow is:

1. KEY confirmed published by combiner (ACCEPTED)
2. Query parent via KeyState EDNS(0) inquiry for this key
3. If parent says `KeyStateTrusted` → done, no bootstrap needed
4. If parent says `KeyStateUnknown` → initiate `BootstrapSig0KeyWithParent()`
5. If parent says `KeyStateBootstrapAutoOngoing` → poll periodically
6. If KeyState query fails (parent unreachable, no DSYNC) → log warning, retry later

This avoids unnecessary bootstraps and duplicate self-signed UPDATEs. The KeyState
inquiry is lightweight (single DNS query) and gives the agent accurate state.

Trigger from the SDE confirmation handler: when the KEY's distribution state transitions
to ACCEPTED for the combiner, fire the KeyState inquiry. This avoids blocking the leader
election callback.

The `HSYNCPARAM.GetParentSync()` field should gate this: only trigger if `parentsync=agent`.
If `parentsync=owner`, the zone owner handles parent sync manually.

#### 1b. Adapt BootstrapSig0KeyWithParent for multi-provider

`BootstrapSig0KeyWithParent()` currently uses `Globals.ImrEngine` directly. In the
multi-provider case, the IMR engine is accessed via the TransportManager or config.
Ensure the function works in both single-provider and multi-provider contexts.

The function should also be callable on-demand via CLI for debugging:
`agent parentsync bootstrap --zone whisky.dnslab.`

#### 1c. Only the delegation sync leader bootstraps

Only the agent that won leader election should send the bootstrap UPDATE. Other agents
must not send duplicate bootstraps. The leader election state is already tracked in
`LeaderElectionManager`. Guard the bootstrap with a leader check.

#### Files to modify
- `main_initfuncs.go` — add bootstrap trigger after KEY publication
- `ops_key.go` — adapt `BootstrapSig0KeyWithParent` for multi-provider context
- `parentsync_leader.go` — add leader guard for bootstrap
- CLI: new `agent parentsync bootstrap` command

---

### Stage 2: Parent Receives Bootstrap and Verifies Key

**Goal:** When the parent receives a child's self-signed KEY upload, it should verify that
the key is actually published in the child zone (via DNS lookup), DNSSEC-validate it, and
update the TrustStore accordingly.

#### 2a. Parent-side key verification mechanism config

The parent needs to know which KEY verification mechanisms it supports. Eventually this
will be advertised via DSYNC (so children know what the parent accepts), but for now we
configure it via a yaml key:

```yaml
delegationsync:
  parent:
    key-verification:
      mechanisms:
        - "at-apex"     # look up KEY at child zone apex
        - "at-ns"       # look up KEY at _signal names per RFC 9615
      # "manual" is implicit: operator can always manually trust via CLI
```

The verification functions are gated on this list. If only `at-apex` is configured, the
parent never queries `_signal` names. If only `at-ns`, it never queries the child apex.

#### 2b. Parent-side key verification after TrustStore insertion

After `UpdateResponder` stores a child KEY in the TrustStore (with `trusted=false`), it
should trigger a verification task. This task:

1. Reads the configured `key-verification.mechanisms` list
2. For each supported mechanism, looks up the child's KEY:
   - **at-apex**: Query `<childzone>. KEY` directly
   - **at-ns**: For each NS serving the child zone, query
     `_sig0key.<childzone>._signal.<ns>.` for KEY records
3. DNSSEC-validates the response (the KEY lookup must be DNSSEC-signed)
4. Compares the looked-up KEY against the stored KEY in TrustStore
5. On match + DNSSEC valid: update TrustStore to `dnssecvalidated=true`, `trusted=true`
6. On mismatch or DNSSEC failure: leave as `trusted=false`, log the reason

Any single mechanism succeeding is sufficient for trust (they are alternatives, not
all required). The verification should be asynchronous (don't block the UPDATE response)
with retry logic (the KEY may not have propagated yet). Use `time.AfterFunc` timers like
the existing KeyBootstrapper pattern.

#### 2c. Key lookup implementation

The parent needs functions to look up a child's KEY:

```
func LookupChildKeyAtApex(childZone string, imr *Imr) ([]dns.RR, bool, error)
func LookupChildKeyAtSignal(childZone string, imr *Imr) ([]dns.RR, bool, error)
```

Both return the KEY RRs, a boolean indicating DNSSEC validation success, and any error.

`LookupChildKeyAtSignal`:
1. Queries the child zone's NS records
2. For each NS target, queries `_sig0key.<childzone>._signal.<ns>.` for KEY
3. DNSSEC-validates each response
4. Returns the union of validated KEY records

`LookupChildKeyAtApex`:
1. Queries `<childzone>. KEY` directly
2. DNSSEC-validates the response
3. Returns the KEY records

#### 2d. TrustStore state machine

Current states are boolean flags (`validated`, `dnssecvalidated`, `trusted`). The
verification flow needs clear state transitions:

```
child-key-upload → stored (validated=false, trusted=false)
                 → dns-lookup-pending (verification in progress)
                 → dnssec-validated (key found + DNSSEC valid)
                 → trusted (auto-bootstrapped or manually trusted)
```

Consider adding a `verification_state` column or repurposing existing flags. The `source`
column already distinguishes `child-update` from `dns` from `file`.

#### 2e. CLI tools for TrustStore debugging

Enhance the existing `agent keystore sig0-trust list` command (or equivalent combiner/auth
command) to show verification state clearly:

```
tdns-cliv2 auth truststore list --zone dnslab.
Zone              KeyID  State       Source         Verified  DNSSEC
whisky.dnslab.    38193  untrusted   child-update   pending   no
romeo.dnslab.     12345  trusted     dns            yes       yes
```

#### Files to modify
- `config.go` — add `key-verification.mechanisms` config
- `updateresponder.go` or `truststore.go` — trigger verification after KEY insertion
- New: `truststore_verify.go` — key lookup at at-apex and at-ns, DNSSEC validation,
  mechanism gating, async retry logic
- `truststore.go` — state transition logic
- CLI: enhance truststore list command

---

### Stage 3: KeyState Inquiry CLI and End-to-End

**Goal:** Implement CLI tooling for KeyState EDNS(0) inquiries and ensure the full
query/response flow works end-to-end.

#### 3a. CLI tool for KeyState inquiry

A new CLI command that lets the operator (or child agent) query the parent's view of a
key's trust state:

```
tdns-cliv2 agent parentsync keystate --zone whisky.dnslab.
```

or for direct query without going through the agent:

```
tdns-cliv2 keystate query --zone whisky.dnslab. --keyid 38193 --parent-ns ns1.dnslab.
```

This sends a DNS query with the KeyState EDNS(0) option to the parent's DSYNC UPDATE
target and displays the response:

```
Zone: whisky.dnslab.
KeyID: 38193
Parent says: KeyStateTrusted
Extra: "auto-bootstrapped 2026-03-15T14:00:00Z"
Response signed by: dsync-update.dnslab. (verified: yes)
```

#### 3b. Fix ProcessKeyState auto-bootstrap

`ProcessKeyState` in keystate.go has a TODO for the auto-bootstrap path
(`KeyStateRequestAutoBootstrap`). Implement it:

1. Receive auto-bootstrap request from child
2. Check policy (already implemented)
3. Launch verification task (same as Stage 2a) for the specified key
4. Return `BootstrapAutoOngoing` immediately
5. Verification task completes → TrustStore updated → next KeyState inquiry returns
   the new state

#### 3c. Child-side KeyState polling

After bootstrap, the child agent should periodically check KeyState to know when the
parent has verified and trusted the key. Once trusted, the child can proceed to send
delegation UPDATEs (CDS, NS changes, etc.).

The polling interval should be configurable and use exponential backoff. The existing
`KeyBootstrapper` timer mechanism is the right pattern.

#### 3d. Integration with onLeaderElected

Wire the KeyState check into the post-bootstrap flow:

1. Leader publishes KEY → combiner confirms
2. Leader sends bootstrap UPDATE → parent acknowledges
3. Leader polls KeyState → waits for `KeyStateTrusted`
4. Leader marks zone as "parent-sync-ready" (local state)
5. Future: leader can now send CDS/NS updates to parent

#### Files to modify
- CLI: new `agent parentsync keystate` command
- CLI: new `keystate query` standalone command
- `keystate.go` — implement auto-bootstrap in `ProcessKeyState`
- `keybootstrapper.go` — add KeyState polling after bootstrap
- `main_initfuncs.go` — wire KeyState check into post-bootstrap flow

---

### Stage 4: Parent Handles Verified UPDATEs (Text File Output)

**Goal:** When the parent receives a verified, trusted UPDATE from a child (e.g. CDS record
addition, NS change), write the delegation data to a text file that can be `$INCLUDE`d into
the parent zone file.

#### 4a. Output method: text file

New output method for the parent `UpdateResponder`. Instead of (or in addition to) directly
modifying the parent zone, write delegation data to a file:

```
/var/lib/tdns/delegations/whisky.dnslab.zone
```

Content (standard DNS zone file format):
```
; Delegation data for whisky.dnslab.
; Last updated: 2026-03-15T14:00:00Z by agent.alpha.dnslab. (KeyID 38193)
whisky.dnslab.     3600  IN  NS   ns2.alpha.dnslab.
whisky.dnslab.     3600  IN  NS   bilbo.echo.dnslab.
whisky.dnslab.     3600  IN  NS   frodo.echo.dnslab.
whisky.dnslab.     3600  IN  CDS  ...
```

The parent zone file includes it via:
```
$INCLUDE /var/lib/tdns/delegations/whisky.dnslab.zone
```

#### 4b. Configuration

New config section for the parent:

```yaml
delegationsync:
  parent:
    output:
      method: "textfile"          # "direct" (current), "textfile", "combiner" (future)
      directory: "/var/lib/tdns/delegations"
      notify-command: ""          # optional: shell command to run after file update (e.g. rndc reload)
```

The `notify-command` allows integration with any DNS server: write the file, then
`rndc reload dnslab.` or `pdns_control reload` or similar.

#### 4c. Per-child file management

Each child zone gets its own file. The parent maintains a directory of delegation files.
When a child sends an UPDATE:

1. Validate signature + trust
2. Apply the update to the child's delegation file
3. If `notify-command` is configured, run it
4. Return SUCCESS rcode

The file should be written atomically (write to temp, rename) to avoid partial reads.

#### 4d. CLI tools

```
tdns-cliv2 auth delegations list                        # list all managed delegations
tdns-cliv2 auth delegations show --zone whisky.dnslab.  # show current delegation data
tdns-cliv2 auth delegations regenerate --zone dnslab.   # regenerate all files from TrustStore + last known data
```

#### Files to modify
- `updateresponder.go` or new `delegation_output.go` — text file output method
- `config.go` — new config section
- CLI: delegation management commands

---

## Future Work (not in scope)

- **Combiner output method**: parent agent sends verified UPDATEs to a "delegation combiner"
  that manages the parent zone. Requires a new zone type in the combiner.
- **DB output method**: parent agent writes to a database table, external software generates
  the parent zone.
- **CDS→DS automation**: parent processes CDS records and generates DS records automatically.
- **CSYNC processing**: parent processes CSYNC records to update NS + glue.
- **Multi-key rollover**: handling KEY rollover where child has both old and new keys during
  transition.

---

## Complexity Assessment

| Stage | Complexity | Estimated LOC | Risk |
|-------|-----------|---------------|------|
| 1. Child bootstrap trigger | Low | ~80 | Low — mostly wiring existing functions |
| 2. Parent key verification | Medium-High | ~300 | Medium — DNS lookups, DNSSEC validation, async retry |
| 3. KeyState CLI + e2e | Medium | ~200 | Low — building on existing EDNS(0) implementation |
| 4. Text file output | Low-Medium | ~150 | Low — straightforward file I/O |
| **Total** | | **~730** | |

Stage 2 is the most complex because it involves DNS lookups with DNSSEC validation across
potentially multiple nameservers, with async retry logic. The rest is mostly wiring and
CLI plumbing.

---

## Verification

Each stage should be testable independently in the lab:

1. **Stage 1**: Agent wins election → KEY published → bootstrap UPDATE sent to parent.
   Verify via `tcpdump` or parent log showing received UPDATE.
2. **Stage 2**: Parent receives bootstrap → DNS lookup of child KEY → TrustStore shows
   `trusted=true`. Verify via `tdns-cliv2 auth truststore list`.
3. **Stage 3**: `tdns-cliv2 keystate query --zone whisky.dnslab.` → shows `KeyStateTrusted`.
   Child agent log shows successful KeyState polling.
4. **Stage 4**: Child sends CDS UPDATE → parent writes delegation file. Verify via
   `cat /var/lib/tdns/delegations/whisky.dnslab.zone`.
