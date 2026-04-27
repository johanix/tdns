# Automated KSK Rollover: Testing and Fixes

**Status**: Active testing log
**Started**: 2026-04-24 (Phase 4A test plan)
**Last updated**: 2026-04-27
**Related**: `2026-04-23-automated-ksk-rollover.md` (design spec) —
this document assumes familiarity with §5 (policy), §6 (DS push),
§7 (parent confirmation), §8 (worker tick), and §3.4 (atomic
rollover).

This document covers both the **test plan** for the automated KSK
rollover work (Phases 4A through 4D + ongoing operational testing)
and the **fixes** applied along the way as bugs surfaced during
real-traffic testing on the bravo.dnslab. testbed.

The body of the document is organised as:

- §1. Test environment and progress summary
- §2. Bugs found and fixes applied (chronological)
- §3. Open issues and pending fixes
- §4. Phase 4A test plan (original 2026-04-24 content; still current
  for the pipeline-fill + DS-push + observe parts of the loop)
- Appendix: command cheatsheet, gotchas, status-output examples

---

## 1. Test environment and progress summary

### 1.1 Environment

- **Child**: `bravo.dnslab.` on `pri.bravo.dnslab` (172.16.91.2),
  running tdns-authv2.
- **Parent**: `dnslab.` on `master.dnslab.` (172.16.1.100), running
  tdns-authv2 on port 5354 with a BIND9 secondary on port 53. The
  BIND9 secondary serves the public dnslab. zone via AXFR from the
  tdns-auth primary; bravo is a delegation from `dnslab.`.
- **DSYNC target**: `updates.dnslab. → 172.16.1.100:5354` (UPDATE
  scheme), discovered via the parent's published DSYNC RRset.
- **Network**: lab-internal, all-tdns, no middleboxes. Internal
  IMR resolves all names; no reliance on `/etc/resolv.conf`.

### 1.2 Phase status

| Phase | Status | Notes |
|---|---|---|
| 1 — Policy config + schema | landed | Pre-existing |
| 2 — DS push | landed | Pre-existing |
| 3 — Parent-agent DS-poll client | landed | Pre-existing |
| 4A — Pipeline + DS push/observe | landed | Pre-existing; tested end-to-end |
| 4B — Scheduled rollover backbone | **landed and tested** | This session |
| 4C — Manual-ASAP CLI + status/reset | **landed and tested** | This session |
| 4D — K-step TTL clamping | **landed and tested** | This session |
| 4E — Double-signature worker branch | pending | Not started |
| 5 — Import | pending | Not started |
| 6 — Rapid-rollover validation | pending — testbed in active use | This session |
| 7 — Docs & samples | partial | Sample yaml updated |

### 1.3 What's been tested end-to-end

- Pipeline-fill: `num-ds=3` KSKs created and held in pipeline.
- DS push to parent: SIG(0)-signed UPDATE accepted.
- Parent observation: parent-agent DS query returns matching set,
  worker advances `created → ds-published`.
- `ds-published → standby` after `kasp.propagation_delay`.
- Scheduled trigger: `rolloverDue` fires `AtomicRollover`,
  `active_at + ksk.lifetime` reached.
- AtomicRollover swap: active→retired, oldest-standby→active,
  `rollover_in_progress=true`, phase advances to
  `pending-child-publish`.
- `pending-child-publish` waits `kasp.propagation_delay`, then
  `pending-parent-push` issues a fresh DS UPDATE for the new key
  set (with retired key DS retained).
- `pending-parent-observe` confirms parent has the new DS RRset.
- `pending-child-withdraw` advances retired SEP keys to `removed`
  after `effective_margin = max(margin, max_observed_ttl)`.
- Cycle returns to `idle` and a new pipeline KSK is generated to
  refill the pipeline.
- Multi-cycle: at least three full rollover cycles observed back-
  to-back without manual intervention.

### 1.4 What still needs testing

- **Mid-`pending-child-withdraw` restart resumes correctly.**
- **Restart mid-`AtomicRollover` (i.e. crash inside the TX): no
  partial state visible.** Hard to reproduce without a fault
  injector.
- **Parent absent or rejecting**: confirm-timeout hard-fail and
  recovery via `auto-rollover reset --keyid=N`.
- **Manual-ASAP** (`auto-rollover asap`): never exercised in this
  session because scheduled rollovers cycled fast enough.
- **K-step clamp visible at multiple step boundaries.** With a
  short ksk.lifetime + long-enough margin, only K=1 ever runs.
  Need a config that produces multiple visible K transitions.
- **Validate that `ttls.max_served` actually pulls
  `max_observed_ttl` down across a full sign cycle**, so
  `effective_margin` shrinks to `policy.clamping.margin`. Last
  observed: stuck at the inbound-zonefile TTL value because the
  signer hasn't run since the policy change. See §3 below.
- **Run with `service.resign: true`** and observe that the
  periodic ticker behaves correctly given the new b59f85a
  channel-driven force-resign-on-trigger logic.
- **Phase 4E (double-signature)**: not started.
- **Phase 5 (import)**: not started.

---

## 2. Bugs found and fixes applied (chronological)

This list is ordered roughly by when each bug was found during
testing, not by severity. Each entry references the commit that
fixed it.

### 2.1 SIG(0) verification fails for §2.5.2 delete-RRset records

**Symptom**: SIG(0)-signed DNS UPDATE messages from the child
contained a §2.5.2 delete-RRset record (class ANY, rdlength 0) over
a typed-RR placeholder (e.g. DS). Parent received the bytes
correctly but `sig.Verify` rejected the signature with `dns: bad
signature`. Manual updates with the same content shape failed
identically; manual updates without DEL-RRSET worked.

**Root cause**: `ValidateUpdate` calls `r.Pack()` to obtain the wire
bytes for SIG(0) verification. miekg/dns's unpack constructs typed
zero-value RR structs even for rdlength=0 records, then on repack
the per-type `pack()` writes fixed-size scalar fields (KeyTag,
Algorithm, DigestType, ... = 4 bytes for DS). The repack ends up 4
bytes longer than the wire and the hash mismatches.

Domain-name-only RR types (NS, CNAME, MX, etc.) escape this because
`packDomainName` special-cases the empty string. Fixed-scalar types
(DS, DNSKEY, A, AAAA, RRSIG, SVCB, ...) all repack with phantom
rdata.

**Fix (commit `6e884ee`)**: in `ValidateUpdate`, walk `r.Ns` before
re-packing and replace any class-ANY+rdlength-0 record with a
`*dns.ANY` placeholder. `*dns.ANY.pack()` writes 0 bytes, repack
matches the wire, signature verifies.

**Permanent fix**: this is a miekg/dns bug. The repack should honor
"empty rdata → 0 bytes" symmetrically with the noRdata short-
circuit on unpack. Future work: fix in the miekg-dns fork and
revert the tdns workaround.

### 2.2 ValidateUpdate returns NOERROR on signature failure

**Symptom**: When SIG(0) verification failed, the response carried
rcode=0 (NOERROR) instead of an error rcode. The child's rollover
state machine treated that as "DS push accepted" and advanced into
`pending-parent-observe`, polling the parent for a DS RRset that
would never appear.

**Root cause**: `UpdateStatus.ValidationRcode` was implicitly
zero-initialized to `dns.RcodeSuccess`. The per-key signature
verification loop only assigned `ValidationRcode` on success; if
every key failed, the field stayed at the zero value.

**Fix (commit `a8f9841`)**: initialize `us.ValidationRcode =
dns.RcodeBadSig` at the top of `ValidateUpdate`. Each successful
verification lifts it to `RcodeSuccess`. Fail-closed by default
matches DNSSEC's security disposition.

### 2.3 handleDSQuery walks one zone too far up

**Symptom**: After a successful DS push that was applied to the
parent zone via `delegation-backend: direct`, `dig
@parent bravo.dnslab. DS` returned NOERROR/empty even though the
DS records were visible in the parent's zone via AXFR.

**Root cause**: `handleDSQuery` always called
`imr.ParentZone(zd.ZoneName)` to find the parent of the matched
zone. Correct for "DS-at-our-apex" queries (we're the child,
walking up). Wrong when `qname` is a child name and `zd` is
already the parent — the responder walked up to root, didn't
host root, returned SOA-only.

**Fix (commit `90f8c97`)**: split into two cases by the
`qname`/`zone` relationship:
- `qname` is a strict child of `zd.ZoneName` → serve DS from
  `zd`'s own zone tree.
- `qname == zd.ZoneName` → walk up via `imr.ParentZone()`.

### 2.4 DSYNC target A/AAAA resolution via stdlib resolver

**Symptom**: After SIG(0) bug fix, DS push reached `dsync_lookup`
and discovered the DSYNC target name (e.g. `updates.dnslab.`).
Then failed with `lookup updates.dnslab. on 172.16.0.5:53: server
misbehaving` — `172.16.0.5` was the system resolver from
`/etc/resolv.conf`, which couldn't resolve internal-only names.

**Root cause**: `LookupDSYNCTarget` had the IMR receiver in hand
for DSYNC discovery but then dropped to `net.DefaultResolver.
LookupHost` for the target's A/AAAA.

**Fix (commit `3d92028`)**: use `imr.ImrQuery` for the A/AAAA
lookup. Same IMR that just resolved the DSYNC RRset.

### 2.5 CreateUpdate bails on missing local db.file

**Symptom**: `tdns-cliv2 auth zone update create -z dnslab. --signer
bravo.dnslab.` produced `Error from NewKeyDB(): error: DB filename
unspecified`. Followup commit message in `d03f360` already
mentioned this.

**Fix (commit `a7b026f`)**: `CreateUpdate` falls back to the
configured server's `/config status` DBFile when the CLI's local
viper has no `db.file`. Required threading a `role` parameter
through the cobra tree.

### 2.6 yaml/mapstructure tags missing for dnssec_policy /
multi_signer

**Symptom**: `online-signing is ignored because the DNSSEC policy
is not set` — even though the zone's template configured
`dnssec_policy: fastroll`. Logs showed
`templates[N].dnssec_policy` in the "unknown config keys ignored"
warning.

**Root cause**: `ZoneConf` and `TemplateConf` had `DnssecPolicy`
fields without struct tags. mapstructure's default key for an
untagged field is the lowercased field name with no separators
(`dnssecpolicy`), so `dnssec_policy:` was silently dropped.

**Fix (commits `9fd3645` then `e7bbda3`)**: first attempt added
`yaml:"dnssec_policy"` tags, which made `dnssec_policy:` work but
broke `dnssecpolicy:`. Second commit settled on
`yaml:"dnssecpolicy"` (no underscore) since that's the convention
elsewhere in the config (`dnssecpolicies:` itself, etc.). The
operator config that was already deployed used the no-underscore
form, so this restored compatibility.

**Outstanding**: ideally we'd accept both forms via a
mapstructure DecodeHook. Tracked under "future cleanup."

### 2.7 Bootstrap-active KSK never registered in RolloverKeyState

**Symptom**: `auto-rollover status` showed the active KSK with
`rollover_index=-` (no row in `RolloverKeyState`). `rolloverDue`
returned false because `active_at` was unset. No scheduled
rollovers ever fired.

**Root cause**: `EnsureActiveDnssecKeys` mints a KSK directly into
`active` state when a zone is signed for the first time. It bypasses
the rollover pipeline entirely — no `RolloverKeyState` row, no
`active_at`, no `rollover_index`.

**Fix (commit `efe25ba`)**: new `RegisterBootstrapActiveKSK`
function called from `EnsureActiveDnssecKeys`. Inserts the row +
stamps `active_at`. Plus a self-heal pass `healBootstrapActiveAt`
in every `RolloverAutomatedTick` that backfills any active SEP KSK
without proper bookkeeping (handles zones that booted under an
older binary).

### 2.8 Parent re-pack of received UPDATE differed by 4 bytes

This is the same root cause as 2.1 but observed from the wire.
Captured here for the test trail.

`tcpdump` of the child sending: 346 bytes UDP payload.
`ValidateUpdate: packed message buflen=350` on the parent.
4-byte mismatch was the per-type `*dns.DS.pack()` writing phantom
rdata bytes for the §2.5.2 delete-RRset record.

### 2.9 Outbound SOA serial config split across two knobs

**Symptom**: After restart, BIND9 secondary thought it was ahead
of the tdns-auth primary because the primary loaded the zonefile's
serial, which was lower than the last-served serial.

**Fix (commit `4c7dbd3`)**: combined `service.reset_soa_serial`
(bool) and `dnsengine.options: [persist-outbound-serial]` into a
single `dnsengine.outbound_soa_serial: keep|unixtime|persist`
field. `persist` saves the bumped serial to DB and restores it on
restart, so secondaries don't see regression.

### 2.10 Active SEP KSK not re-signing DNSKEY after rollover

**Symptom**: After `AtomicRollover` swapped 52409 (active→retired)
with 26154 (standby→active), `dig DNSKEY +dnssec` returned the
DNSKEY RRset still signed only by 52409 (the now-retired key).

**Root causes** (two interacting):
1. **`ResignerEngine` ignored `triggerResign` in inactive mode.**
   With `service.resign: false`, the engine just drained the
   channel without acting on it.
2. **`SignRRset` never removed RRSIGs by retired keys.** The
   signing loop only considered RRSIGs whose KeyTag matched a
   *current* signing key.

**Fix (commits `b59f85a` + `dd97292`)**:
1. Resigner now always force-resigns the zone on `triggerResign`
   arrivals, regardless of `service.resign`. The flag now only
   controls the periodic ticker.
2. `SignRRset` pre-loop scrub: drop any RRSIG whose KeyTag isn't
   in the current `signingkeys` set. Logged at INFO with a counter
   so we can spot unexpected drops.

### 2.11 `active_seq` semantics

**Symptom**: `rollover_index` reflected RolloverKeyState insertion
order, not the order in which keys were active. Confusing for
operators reading the status output.

**Fix (commit `f5c5803` + heal-pass extension `fe3a339`)**: added
a separate `active_seq` column allocated only at standby→active
transitions. Status CLI shows `active_seq` instead of
`rollover_index`. Pipeline-only keys show `-`. Heal pass back-
fills `active_seq` for active SEP KSKs that were promoted under
an older binary.

### 2.12 Heal pass overwrote active_at on every restart

**Symptom**: After restarting the parent several times during
testing, scheduled rollovers stopped firing as expected. T_roll
appeared to keep pushing forward.

**Root cause**: `RegisterBootstrapActiveKSK` (called from heal
pass) stamped `active_at = now()` unconditionally. With a 10-minute
ksk.lifetime and restarts every few minutes, T_roll was perpetually
in the future.

**Fix (commit `80f24ef`)**: stamp `active_at` only when currently
NULL. Same idempotency that `active_seq` already had.

### 2.13 ttls.max_served added

**Symptom (motivation, not a bug)**: testing
`pending-child-withdraw` with `ksk.lifetime: 10m, margin: 5m`
should have completed in 5m. Instead took 1h, because the zone's
RRsets had 3600s TTLs from the source zonefile, so
`max_observed_ttl` was 3600 → `effective_margin = 1h`.

**Fix (commit `1777952`)**: new `ttls.max_served` policy field.
When set, `SignRRset` clamps every served TTL down to
`min(operator_ttl, K*margin if K>0, max_served)`. Validation:
`max_served >= 60s` (warn-and-bump if lower); reject hard if
`max_served < clamping.margin` when clamping is enabled.

### 2.14 CLI ergonomics

The auto-rollover CLI commands had several usability problems:

- `log.Fatal*` errors went to the CLI logfile, not stderr.
  Commands silently exited with no terminal output.
- `auto-rollover when` produced no output when
  `ComputeEarliestRollover` returned an error.
- The startup banner (`*** TDNS tdns-cliv2 version ...`,
  `Logging to file: ...`, etc.) clogged every CLI invocation.
- `status` output was a flat list of attribute=value lines that
  didn't visually separate sections.
- `status` was scoped to KSK-only; ZSKs invisible.
- Long `last_error` text wrapped awkwardly.
- No `state_since` per key.
- No estimate of when the current phase would advance.

**Fixes (commits `7bd9c7f`, `749f9c8`, `0fefdec`)**: stderr-routed
errors via new `cliFatalf` helper; banner suppressed for AppTypeCli
unless `-v`; status output reorganised into KSK + ZSK sections with
formatted column tables; `published` column shows DS+KEY/DS/none
per key derived from state; `state_since` column shows when each
key entered its current state; `next_transition` line under phase;
`-v` lists the multi-ds FSM phase sequence with an arrow next to
the current phase.

---

## 3. Open issues and pending fixes

### 3.1 max_observed_ttl doesn't converge until next rollover

After setting `ttls.max_served`, the next `SignZone` pass clamps
header TTLs but the `max_observed_ttl` recorded in
`ZoneSigningState` is still the pre-clamp value (the loop reads
TTLs *before* `SignRRset` mutates them). Only the *second* sign
pass records the clamped value. With `service.resign: false`, sign
passes only happen at rollover events — so `effective_margin`
takes a full extra cycle to shrink.

**Plan**: force a sign pass when policy is loaded with
`max_served` set, or change the sign loop to record post-clamp
TTLs (consult `UnclampedTTL` and the active clamp ceiling rather
than the header).

### 3.2 ApproveUpdate-rejected updates also return NOERROR

The response is written at `updateresponder.go:302` after Validate
+ Trust succeed, *before* `ApproveUpdate` runs the policy check.
If approve rejects (e.g. RR type not allowed), the response was
already sent with `RcodeSuccess`. Operator sees NOERROR for an
update that was actually rejected on policy grounds.

**Plan**: reorder so `ApproveUpdate` runs before `WriteMsg`, or
delay `WriteMsg` until the final disposition is known.

### 3.3 Proper fix in miekg-dns fork

The §2.5.2 delete-RRset workaround in `ValidateUpdate` (commit
`6e884ee`) is a tdns-side bandage. The real fix is in
miekg/dns: either (a) `UnpackRRWithHeader` returns `*dns.ANY` for
any rdlength=0 record, or (b) every per-type `pack()` honors
"empty struct → 0-byte rdata" symmetrically with the noRdata
unpack short-circuit. Option (b) probably cleaner; needs a careful
audit of every per-type pack().

After the upstream fix lands, the workaround in
`tdns/v2/sig0_validate.go` should be reverted.

### 3.4 CLI tooling for rollover phase manipulation

Several times during testing we needed to unstick a zone (reset
phase, clear stuck `pending-parent-observe`, etc.) and resorted
to direct sqlite ALTER/UPDATE. A proper CLI command —
`auto-rollover set-phase --zone Z --phase idle` or similar —
would replace the sqlite-hack workflow.

### 3.5 Compose dnssec_policy / dnssecpolicy YAML alias

Both `dnssec_policy` (with underscore) and `dnssecpolicy` (without)
are reasonable. Currently we accept only the no-underscore form.
A mapstructure DecodeHook could accept both.

---

## 4. Phase 4A test plan (original 2026-04-24 content)

The remainder of this document is the original Phase 4A test plan,
preserved as reference. It's still current for the parts of the
loop that 4A implements: pipeline-fill, DS push, and parent
observation. Phase 4B/4C/4D content is captured in §1-3 above.

---

## 1. What 4A Actually Exercises

Phase 4A implements the **pre-publication pipeline** end-to-end for
multi-DS rollover:

- Pipeline fill: keep `num-ds` SEP keys alive in the keystore
- Whole-RRset DS push to parent, SIG(0)-signed via DSYNC UPDATE target
- Confirmation via parent-agent DS query (§7.2 exponential backoff,
  §7.5 match algorithm)
- Two-range bookkeeping: submitted vs. confirmed (§6.1)
- Key-state advance `created → ds-published` (transactional, §9.4)
- Time-based advance `ds-published → standby` after
  `kasp.propagation_delay`
- Bootstrap promotion `standby → active` when no active SEP key
  exists

Testing 4A in anger surfaces issues that unit tests cannot: parent
misbehavior, propagation timing, SIG(0) key lifecycle, DSYNC
configuration, and the worker's handling of partial failures.

## 2. Topology

Minimum viable setup: two cooperating `tdns-authv2` processes plus
an IMR the child can use to look up the parent's DSYNC target and
to query parent-agent DS.

```
  child.example.  ─── signed by tdns-auth (rollover machinery)
                   │
                   │  DS UPDATE (SIG(0))  ─────▶  DSYNC UPDATE target
                   ▼
  example.        ─── signed by a separate tdns-auth (or any
                       authoritative server that supports accepting
                       SIG(0) DS updates and publishes DSYNC at the
                       delegation point)
```

Both zones served over localhost on different ports works fine.
The IMR needs to find both zones — either put stub delegations in
the IMR's config pointing at the right ports, or run IMR in a mode
that trusts the local zones.

A single-host lab, a pair of NetBSD VMs, or two separate hosts all
work. This document does not prescribe the lab topology; only the
behavior to look for.

## 3. Parent-Side Preconditions

Phase 4A assumes these; none of them are created or bootstrapped by
the rollover worker. §3.8 of the design spec lists the failure-mode
matrix if any is missing.

1. **Parent serves the parent zone** with a DSYNC RR published at
   the child delegation point, pointing at an UPDATE receiver:
   ```
   _dsync.example.  IN DSYNC  DS dns <port> <update-target>.
   ```
2. **Parent has the child's SIG(0) KEY** — either published under
   the agreed transport name in the child zone, or bootstrapped
   through the mechanism in
   `2026-03-07-delegation-sync-refresh-plan.md`.
3. **Parent authorizes the child's SIG(0) key** to modify the DS
   RRset at the child's delegation point. (Same delegation-sync
   machinery.)
4. **Parent-agent is resolvable and query-answering** — whoever
   the child is configured to ask for the DS RRset. For a first
   test, pointing `parent-agent` at the parent's own authoritative
   server is the simplest choice.

If any of these are missing, the worker will hard-fail or retry
cleanly per §3.8, but you'll learn more from exercising the
happy path first and then intentionally breaking each precondition.

## 4. Child-Side Configuration

Write a DNSSEC policy for the child zone. Keep `margin` and
`confirm-timeout` short for testing; production values would be
longer.

```yaml
dnssec-policies:
  multi-ds-test:
    mode:             ksk-zsk
    algorithm:        ECDSAP256SHA256
    ksk:
      lifetime:       24h
      sig-validity:   12h
    zsk:
      lifetime:       24h
      sig-validity:   12h
    rollover:
      method:         multi-ds
      num-ds:         3
      parent-agent:   parent-ns.example:53    # where child queries DS
      confirm-initial-wait: 2s
      confirm-poll-max:     60s
      confirm-timeout:      5m   # 1h is default; short for testing
      dsync-required:       true
    ttls:
      dnskey:         2h
    clamping:
      enabled:        true
      margin:         15m
```

Note on `lifetime: 24h`: 4A does not yet run scheduled
`atomic_rollover` (that's Phase 4B), so the lifetime value is recorded
but does not drive behavior yet.

Note on `clamping`: the parser accepts these fields, but 4A does
not yet wire clamping into the signing path. `clamping.enabled:
true` is safe to set now and will take effect when Phase 4D lands
`ComputeNextClampBoundary`.

Also adjust the global `KaspConf` so the `ds-published → standby`
transition runs on a testable timescale:

```yaml
kasp:
  propagation_delay: 30s
  check_interval:    10s
```

`propagation_delay` is what
`TransitionRolloverKskDsPublishedToStandby` waits for after the DS
is observed at the parent. `check_interval` controls how often the
`KeyStateWorker` (and thus the rollover tick) fires. Short values
make the pipeline observable in real time; production values would
be minutes to hours.

Finally, assign the named policy to the child zone in its zone
config.

## 5. Expected Happy-Path Sequence

Start `tdns-authv2` on both the parent and child sides. Tail the
`lgSigner` output on the child. The expected sequence, roughly in
order:

**1. Pipeline fill** (a few seconds after startup):
```
rollover: generated pipeline KSK  zone=child.example. keyid=<N>
```
Repeated up to `num-ds = 3` SEP keys in state `created`. If the
zone had no KSKs at startup, all three begin in `created`.

**2. Arming DS push** (next worker tick):
```
rollover: arming DS push  zone=child.example.
```
Phase transitions `idle → pending-parent-push`. No push on this
tick — arming counts as the advance.

**3. DS UPDATE sent** (next tick):
```
rollover: DS UPDATE accepted, arming observe  zone=child.example. first_poll_at=...
```
The whole DS RRset is constructed from the keystore, signed with
the child's active SIG(0) key, and sent. On NOERROR, the observe
schedule is armed with `first_poll_at = now + confirm-initial-wait`
(default 2s).

**4. Parent-agent DS query** (after `confirm-initial-wait` elapses):
On successful match:
```
rollover: parent DS observed, advanced created keys  zone=child.example. advanced=3
```
Every SEP key whose `rollover_index` is in the confirmed range
advances `created → ds-published` in one transaction. Phase resets
to `idle`. Observe schedule clears.

If the parent hasn't published yet, the query returns no match;
`observe_next_poll_at` doubles (2s → 4s → 8s → … capped at
`confirm-poll-max`).

**5. Propagation wait** (`kasp.propagation_delay` after
observation):
```
rollover: ds-published→standby  zone=child.example. keyid=<N>
```
SEP keys in `ds-published` advance to `standby` once
`now - ds_observed_at >= propagation_delay`.

**6. Bootstrap activation** (if the child had no active SEP key):
```
rollover: promoted standby KSK to active (no active KSK)  zone=child.example. keyid=<N>
```
The lowest-keytag standby SEP key becomes active. From this point
the child zone is signed by this KSK.

**7. Steady state.** Nothing further happens in 4A. The pipeline
has three KSKs: one active, two standby (or in whichever mix the
propagation timer produced). Advancing the active KSK to retired
and bringing the next standby into active is Phase 4B's `atomic_rollover`
and is NOT exercised here.

## 6. Database Inspection

State lives in the sqlite keydb. These queries reveal what the
worker is doing at any moment.

**Key states:**
```sql
SELECT zonename, keyid, flags, state
FROM DnssecKeyStore
WHERE zonename = 'child.example.';
```
Expect: SEP-flagged keys (flags = 257) in `created`, then
progressing through `ds-published`, `standby`, `active`.

**Per-key rollover bookkeeping:**
```sql
SELECT zone, keyid, rollover_index, rollover_method,
       rollover_state_at, ds_submitted_at, ds_observed_at,
       last_rollover_error
FROM RolloverKeyState
WHERE zone = 'child.example.';
```
Every new SEP key should have a monotonically increasing
`rollover_index`. `ds_observed_at` is set when the parent confirms.
`last_rollover_error` should be NULL on a healthy run.

**Per-zone rollover coordination:**
```sql
SELECT zone,
       last_ds_submitted_index_low, last_ds_submitted_index_high,
       last_ds_confirmed_index_low, last_ds_confirmed_index_high,
       rollover_phase, rollover_phase_at,
       observe_started_at, observe_next_poll_at, observe_backoff_seconds
FROM RolloverZoneState
WHERE zone = 'child.example.';
```
- Submitted range: what the child has pushed to the parent.
- Confirmed range: what the parent is observed to hold.
- `rollover_phase`: current position in the §8.8 sub-phase machine.
- Observe-schedule fields: only populated while phase is
  `pending-parent-observe`; cleared when phase returns to `idle`.

**Parent DS (from the child's perspective):**
Issue a manual query from any DNS tool:
```
dig +dnssec DS child.example. @<parent-agent>
```
Compare the answer RRset keytags against the child's
`RolloverKeyState.rollover_index` column. The match is what the
worker's observe phase checks.

## 7. Error-Path Tests

These matter at least as much as the happy path. Each exercises a
specific design decision in §3.5 (failure and recovery), §3.8
(preconditions), §7.2 (backoff), or §9.4 (two-store consistency).

### 7.1 Parent that NOERRORs but never publishes

Point `parent-agent` at an NS that does not have the child's DS
RRset (or run a stub that swallows UPDATEs). Keep
`confirm-timeout: 5m` so you see the failure quickly.

Expected behavior:
- DS push succeeds (NOERROR).
- Observe phase enters; backoff schedule runs: 2s, 4s, 8s, 16s,
  32s, 60s, 60s, ...
- After 5m (`confirm-timeout`), hard-fail:
  ```
  rollover: DS observation timed out; keys marked with last_rollover_error ...
  ```
- Each waiting SEP key has `last_rollover_error` set to an
  explanatory message.
- Zone phase resets to `idle`.

This exercises the §7.2 + §3.5 fix from the Phase 4A review.

### 7.2 Missing SIG(0) key

Delete the child's active SIG(0) key before (or during) the first
DS push.

Expected:
- `PushWholeDSRRset` fails cleanly (logged warning).
- Phase stays at `pending-parent-push`.
- Worker retries on next tick — still fails, same log.
- When the SIG(0) key is restored, the next tick succeeds and the
  observe schedule arms.

This exercises the SIG(0)-signing precondition (§3.8 R1).

### 7.3 DSYNC absent

Remove the DSYNC RR from the parent's zone while `dsync-required:
true`.

Expected:
- `PushWholeDSRRset` returns an error (DSYNC lookup returns
  NXDOMAIN or empty).
- Phase stays at `pending-parent-push` and retries each tick.
- Flip `dsync-required` to `false`, restart: worker logs and skips
  the zone on each tick without error.

This exercises §3.8 R3 (DSYNC-required fail-closed vs. retry).

### 7.4 DSYNC with non-UPDATE scheme

Publish a DSYNC that advertises a non-UPDATE scheme (e.g. `https`).

Expected:
- DSYNC lookup succeeds in the sense that records are returned.
- `PushWholeDSRRset` finds no usable UPDATE target and returns
  an error.
- Worker keeps retrying — this is a hard-fail class per §3.8 R4
  in the design, but 4A's implementation treats it as a transient
  retry. Worth noting and possibly flagging for Phase 4B's hard-fail
  handling (the precondition matrix in design-doc §3.8 says this
  should be a hard-fail; 4A treats it as a transient retry).

### 7.5 Foreign DS at parent

Inject a DS RR at the parent's delegation point whose keytag does
not match any of the child's managed keys. The match algorithm
(§7.5) says foreign DS records must be tolerated, not used as a
match failure.

Expected:
- Observe match succeeds as long as the child's expected DS RRs
  are all present.
- Child does NOT attempt to "clean up" the foreign record via
  subsequent UPDATE. (4A's target set is derived from the
  keystore only; foreign records are ignored by construction.)

This is a correctness test for §7.5, not a failure test.

### 7.6 Multiple digest types per key

Publish both SHA-256 and SHA-384 DS records at the parent for the
same keytag. Expected DS set from the child uses SHA-256 (default).

Expected:
- Match succeeds. The additional SHA-384 DS is foreign-by-digest
  and must not fail the match.
- No code-level support exists in 4A for the child to publish
  multiple digest types per key. That's a policy enhancement for
  later.

### 7.7 Restart mid-phase

Kill the child process during `pending-parent-observe` (before the
match is observed). Start it again.

Expected:
- Worker reads `rollover_phase = pending-parent-observe` from
  `RolloverZoneState`.
- `observe_started_at`, `observe_next_poll_at`,
  `observe_backoff_seconds` are persisted — polling resumes at
  the next scheduled poll time (or immediately if it's elapsed).
- If total elapsed since `observe_started_at` exceeds
  `confirm-timeout`, hard-fails on the first tick post-restart.

Restart-safety is a primary design goal (§12 R2). This test
exercises it.

### 7.8 Crash during observation match

Harder to test without code injection, but valuable: simulate a
crash between `saveLastDSConfirmedRangeTx` and
`UpdateDnssecKeyStateTx` inside
`confirmDSAndAdvanceCreatedKeysTx`. The transaction should roll
back; no change should be visible. On restart, the next tick
should re-query, re-match, and re-advance — the whole sequence
idempotently.

This exercises §9.4 two-store consistency. A panic-injection test
inside the TX would be the clean way to verify it.

## 8. What 4A Does NOT Let You Test

Be explicit about scope so you don't spend time looking for
behavior that isn't there yet.

- **Scheduled rollover.** `rollover_due()` time-based trigger is
  Phase 4B. The KSK `lifetime` value in policy is persisted but
  not acted on.
- **`atomic_rollover(z)`.** Phase 4B. There is no automatic
  `active → retired` transition in 4A. The bootstrap promotion is
  the only `standby → active` path; once a KSK is active, it
  stays active.
- **`pending-child-publish` / `pending-child-withdraw` phases.**
  Phase 4B. 4A implements only `idle`, `pending-parent-push`, and
  `pending-parent-observe`. The full §8.8 five-phase machine is 4B.
- **`rollover_in_progress` flag.** Phase 4B. The column exists,
  but 4A never sets or clears it. Import-during-rollover protection
  (§15.6) is therefore not active yet.
- **Manual-ASAP CLI** (`rollover when`, `rollover asap`, `rollover
  cancel`). Phase 4C. Also `rollover status` and `rollover reset`
  are 4C.
- **`ComputeEarliestRollover`.** Phase 4C.
- **Clamping effect on published RRSIGs and TTLs.** Phase 4D. The
  `clamping` policy subtree parses cleanly, but no code consults
  it yet. Clamping-enabled zones still publish the operator-
  configured TTLs and RRSIG validity verbatim.
- **Double-signature method.** Phase 4E. `method: double-signature`
  is valid config but `RolloverAutomatedTick` early-returns on it.
- **Import workflow.** Phase 5. `rollover import` CLI does not
  exist.

## 9. Useful Log-Filter Examples

The rollover machinery logs via `lgSigner` with structured fields.
Useful grep patterns when tailing:

```
rollover:                        # all rollover events for this zone
rollover.*pipeline               # key generation
rollover.*DS push                # submissions
rollover.*parent DS observed     # successful confirmations
rollover.*timed out              # hard-fail events
rollover.*arming                 # phase transitions
```

If running multiple zones, add `zone=<name>` to filter.

## 10. Test Scenario Matrix

Suggested order for a first-time walk-through:

| # | Scenario                     | Expected outcome             | Design reference |
| - | ---------------------------- | ---------------------------- | ---------------- |
| 1 | Happy-path end-to-end        | pipeline → active in ~30–60s | §5 in this doc   |
| 2 | Restart during observe       | Resumes at persisted poll    | §7.7             |
| 3 | Parent never publishes       | Hard-fail after 5m           | §7.1             |
| 4 | Missing SIG(0) key           | Retry loop until restored    | §7.2             |
| 5 | DSYNC absent                 | Retry loop; skip if !required | §7.3            |
| 6 | Foreign DS at parent         | Match succeeds, ignored      | §7.5             |
| 7 | Manual `RolloverKey` CLI     | Keystore changes, observe what worker does | §2 of spec |

Checking off 1–4 gives confidence the core mechanism is sound;
5–7 exercise edge cases.

## 11. Next Steps After Testing

If 4A holds up under this matrix:

- Identify any test gaps (R-reset semantics, foreign-DS digest
  variants, multi-digest-per-keytag) that the Phase 4A review
  flagged and consider adding unit tests.
- Document any parent behaviors you observed that the design did
  not anticipate — those are candidates for Phase 4B scope adjustment.
- Decide whether to start on Phase 4B (scheduled rollover backbone:
  `atomic_rollover` + child-side phases + scheduled trigger), or
  let 4A soak. Subsequent sub-phases (4C manual-ASAP CLI, 4D clamp
  wiring, 4E double-signature) build on 4B; see design doc §11
  "Phase 4 breakdown" for ordering and dependencies.

If 4A breaks:

- File issues tied to specific §§ of the design doc.
- Revisit the §3.8 precondition matrix — a "broken" run often
  indicates a missing precondition rather than a worker bug.
