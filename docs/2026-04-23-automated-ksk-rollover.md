# Design Spec: Automated KSK Rollover in tdns-auth

**Status**: Draft (Phases **1** and **2** implemented in `tdns/v2`; worker
integration and parent DS confirmation remain future phases.)
**Date**: 2026-04-23 (implementation status note: 2026-04-24)
**Scope**: tdns-auth (single-signer). Non-MP zones only.
**Related**: `2026-03-07-delegation-sync-refresh-plan.md` (delegation
sync + KeyState EDNS(0), landed), `2026-03-14-signal-key-publication.md`

## 1. Context and Motivation

tdns-auth is an authoritative nameserver built on the `tdns/v2`
library. It can already:

- sign zones online/inline (ZSK + KSK pipeline)
- generate DNSSEC keys and stage them through a state machine
  (`created → published → standby → active → retired → removed`)
- run a periodic `KeyStateWorker` that advances `published → standby`
  and `retired → removed` on timer, and maintains a configured count
  of standby ZSKs/KSKs
- send SIG(0)-signed DNS UPDATEs to a parent (used today for
  delegation NS/glue sync via `SyncZoneDelegationViaUpdate`)
- discover parent UPDATE targets via DSYNC
  (draft-ietf-dnsop-delegation-mgmt-via-ddns)
- query and respond to the KeyState EDNS(0) option
  (draft-berra-dnsop-keystate-02), with SIG(0)-signed responses from
  parents

What is *not* yet implemented is the orchestration that ties these
pieces together into a fully automated KSK rollover:

- no schedule/policy for *when* a KSK should roll (policy types and
  validation exist; the rollover worker does not consume them yet)
- no automated `active → retired` transition for KSKs (only ZSKs
  transition cleanly today, because ZSKs don't need parent
  coordination)
- no **worker-driven** automated DS push yet; the library can build the
  target DS set, construct the whole-RRset UPDATE, and send it
  (`PushWholeDSRRset`, Phase 2), and the CLI exposes `keystore dnssec
  ds-push` for manual operation
- no automated confirmation by the child that the parent has
  published the new DS records before retiring the old KSK
- no parameter coupling — the timing constants in `KaspConf`
  (`propagation_delay`) and in `DnssecPolicy` (`SigValidity`) are
  independent of each other and independent of key lifetime

The goal of this project is to close those gaps and enable rapid KSK
rollover as an experimental capability — rolling KSKs weekly, daily,
or faster — which in turn requires the timing parameters to be
coupled rather than individually configured. For v1, parent-side
DS confirmation uses a DS-query-at-parent-NS pattern (§7); using
KeyState EDNS(0) for confirmation is deferred to future work (§16).

## 2. Goals and Non-Goals

### Goals

- Fully automated KSK rollover in tdns-auth, driven by a per-zone
  policy (cadence + method)
- Support both rollover methods: **multi-DS** (parent pre-publishes
  one or more DS records for not-yet-published DNSKEYs) and
  **double-signature** (child pre-publishes DNSKEY + signs with both
  old and new KSK)
- Automatic DS push to parent via SIG(0)-signed DNS UPDATE, with
  DSYNC-discovered target
- Automatic confirmation of parent DS publication via DS query at
  parent NS (BIND9-style "parent-agent" pattern). KeyState EDNS(0)
  as a confirmation channel is deferred to future work (§16).
- Per-zone policy that supports **rapid cadence** (days or less) by
  coupling dependent timing parameters to a single driver (key
  lifetime or cadence)
- Persistence of rollover progress across tdns-auth restarts

### Non-Goals (this project)

- ZSK rollover (already works; untouched)
- Algorithm rollover (single-algorithm rollover only)
- Multi-signer / multi-provider coordination (tdns-mp has its own
  KeyStateWorker and MPDnssecKeyStore; addressed separately)
- CDS/CDNSKEY signaling (RFC 8078) — DS publication is driven by
  explicit UPDATE in this design
- NSEC3 parameter rollover

### Portability Note

Where practical, the rollover logic and policy types should live in
`tdns/v2/` in a form reusable by tdns-mp when its keystore catches
up. Concretely: policy parsing, the rollover state machine, and the
DS-push builder are library code; only the `KeyStateWorker` wiring
and the non-MP `DnssecKeyStore` access paths are specific to this
project.

## 3. Rollover Semantics

This section defines the two supported rollover methods, the events
and delays involved, and how the child decides to advance each step.
Specific timing values are policy inputs (§5); the flow is fixed.

### 3.1 Terminology

- **KSK-old**: the currently active KSK being rolled out
- **KSK-new**: the incoming KSK
- **DS-old**, **DS-new**: DS RRs corresponding to KSK-old, KSK-new
- **DNSKEY_TTL**: TTL of the child's DNSKEY RRset
- **DS_TTL**: TTL of the parent's DS RRset
- **Dprop_child**: time for a DNSKEY change to propagate to all child
  secondaries and caches (≥ DNSKEY_TTL, plus a safety margin)
- **Dprop_parent**: time for a DS change to propagate across the
  parent's zone and caches (≥ DS_TTL, plus safety)
- **Dsig**: RRSIG validity period for the child zone
- **Dconfirm**: max time to wait for parent DS confirmation before
  giving up / alerting

See §3.1.1 for the mapping from these local names to RFC 7583.

### 3.1.1 Cross-reference with RFC 7583

This document uses descriptive local names to keep the prose
readable. The following table maps each local name to its RFC 7583
equivalent so implementers and reviewers can cross-reference.

| Local name       | RFC 7583 name   | Meaning                                                       |
| ---------------- | --------------- | ------------------------------------------------------------- |
| `DNSKEY_TTL`     | `TTL_key`       | TTL of the child's DNSKEY RRset                               |
| `DS_TTL`         | `TTL_ds`        | TTL of the parent's DS RRset                                  |
| `Dprop_child`    | `Dprp_C`        | Propagation delay of DNSKEY changes across child NS + caches  |
| `Dprop_parent`   | `Dprp_P`        | Propagation delay of DS changes across parent NS + caches     |
| `Dsig`           | `SigValidity`   | RRSIG validity period for apex/zone signatures                |
| `Dconfirm`       | *(none)*        | Max wait for DS-at-parent confirmation (this doc, §7)         |
| `L` (`ksk.lifetime`) | `IretKSK` (partial) | KSK operational lifetime (in 7583: the *interval* between key introductions) |
| `margin`         | *(none direct)* | Operator hold-time for retired KSK; subsumes several 7583 safety margins |
| `R`              | *(none)*        | Time remaining until next rollover (this doc, §5.2)           |
| `T_roll`         | `T_retire` / `T_sub` | Moment of atomic rollover (old retires, new activates) |

Notes:
- `margin` in this document is a single tunable (§5.2) that
  conflates several distinct safety margins in RFC 7583. This is
  intentional — the project favors a small number of operator
  knobs over precise RFC-7583 fidelity.
- `R` and `Dconfirm` have no RFC 7583 analogue because they are
  operational constructs specific to this automation design, not
  rollover-timing parameters.
- RFC 7583 treats KSK and ZSK rollovers symmetrically with
  parameters like `IretKSK` and `IretZSK`; this project has no
  ZSK-rollover logic beyond what's already in tdns-v2, so only the
  KSK-side parameters are mapped.

### 3.2 Multi-DS rollover (RFC 7583 §3.3.3 generalized, preferred)

Parent pre-publishes the DS(es) for one or more future KSKs before
the child publishes the corresponding DNSKEYs. The child **does not
publish a KSK's DNSKEY until it is time to actually sign with it** —
the DNSKEY is withheld from the apex until its DS has been live at
the parent long enough to be safe to use.

The "multi-DS" name (as opposed to "double-DS") reflects that the
child is free to have N future KSKs queued at the parent as DS
records simultaneously. Nothing in the design limits this to two.

**Rationale — Shor's Clock**: once a public key is observable in the
DNS, a quantum adversary can begin attacking it. A DS record is a
cryptographic *hash* of the DNSKEY and is quantum-opaque: publishing
the DS does not start Shor's Clock against the key. Multi-DS
therefore minimizes the window during which each KSK's public key is
exposed — at any moment, not all DNSKEYs corresponding to the
published DS records need be present at the apex. At least one must
be (the currently active KSK), but future KSKs with pre-published
DS records have their DNSKEYs withheld until it is time to use them
for signing.

Key-state flow (per KSK):
```
  created → ds-published → standby → published → active → retired → removed
```
- **created**: key material generated and stored in keystore; DNSKEY
  not at the apex; DS not yet in the DS RRset pushed to parent
- **ds-published**: parent has **accepted and published** the DS
  (confirmed by observing the expected DS RRset at any parent NS;
  see §7). DS-propagation delay counter now runs from this point.
  DNSKEY still NOT at the apex.
- **standby**: DS has been cached long enough to be safely used as a
  validation trust anchor (DS propagation delay elapsed). DNSKEY
  still NOT at the apex.
- **published**: DNSKEY now appears at the apex. In multi-DS this
  is almost instantaneous before `active` — see note below.
- **active**: key is in active signing use
- **retired**: no longer signing; DNSKEY still at the apex until old
  RRSIGs and the DNSKEY RRset expire from caches
- **removed**: DNSKEY withdrawn from the apex

Note on `published` vs. `active` in multi-DS: because we intentionally
delay DNSKEY publication until the moment the key becomes active, the
time spent in `published` is essentially zero. We keep the two states
distinct anyway — they are well-known DNSSEC terminology, and the
zero gap is a policy choice we make here, not a change to the state
machine. The double-signature path (§3.3) has a real, non-zero
`published` → `standby` → `active` progression.

Note on DS removal after `removed`: once a KSK is in state `removed`,
its DNSKEY is gone from the apex and the key is no longer usable.
Whether its DS is still in the parent's DS RRset at that point is a
garbage-collection concern, not a property of the key state machine.
The DS RRset is recomputed on each pipeline tick (§5.1.1) and a
`removed` key's DS drops out naturally when a successor is added to
keep the RRset at `num-ds` entries.

Timeline for a single rollover (KSK-old → KSK-new). Note that
multiple state machines tick in parallel — the transition of KSK-old
from `active` to `retired` MUST coincide exactly with KSK-new's
transition from `standby` (via `published`) to `active`, because
there must always be exactly one active KSK:

```
  T0: KSK-new generated (state: created). Sitting in the pipeline
      as part of the RRset of size num-ds.
  T1: child sends DS RRset to parent including DS-new.
  T2: parent accepts and publishes DS-new
      (confirmation by observing DS RRset at parent NS; §7)
      → state: ds-published. DS-propagation delay begins.
  T3: parent's DS for KSK-new has been cached long enough to be safe
      → state: standby.
  ...time passes, possibly days...
  T_roll: rollover event. Atomic transitions across multiple keys:
      KSK-old: active → retired
      KSK-new: standby → published → active (effectively one step;
               in multi-DS, `published` is held for zero time since
               the DNSKEY is only added to the apex at this moment)
      Child signer cuts over to signing with KSK-new.
  T_roll + (Dsig_remaining + Dprop_child):
      cached RRSIGs made by KSK-old and cached DNSKEY RRsets
      containing KSK-old have expired from caches.
      KSK-old: retired → removed (DNSKEY withdrawn from apex;
      Shor's Clock stops).
      On the next DS-RRset recomputation (§5.1.1) a successor key
      fills the pipeline slot and DS-old drops out of the published
      DS RRset.
```

Invariants:

- **Validation chain**: every RRSIG-over-DNSKEY the child publishes
  is chainable via at least one DS in the parent's cached DS RRset.
- **Exactly one active KSK**: at any instant exactly one KSK is in
  state `active`. The `retired` state for KSK_n and `published`/
  `active` for KSK_n+1 begin at the same instant.
- **Minimal DNSKEY exposure**: a KSK's DNSKEY is only present at the
  apex between the transition into `published` and the transition
  into `removed`. Outside that window, only its DS hash is visible.

### 3.3 Double-signature rollover (RFC 7583 §3.3.1)

Child pre-publishes the new KSK's DNSKEY at the apex and signs with
both KSKs; DS change at parent comes later. Higher bandwidth at the
apex, longer Shor's Clock window for the new KSK (DNSKEY is visible
before it's being used), but does not require the parent to accept
a DS before the key's DNSKEY exists.

Key-state flow (per KSK):
```
  created → published → ds-published → standby → active → retired → removed
```

Note how this differs from multi-DS (§3.2): here `published`
precedes `ds-published`, and `standby` means "DNSKEY has been
visible long enough to be safely used for signing" (child-side
propagation), not "DS has been visible long enough at the parent"
(parent-side propagation).

Timeline:
```
  T0: KSK-new generated (state: created)
  T1: child publishes KSK-new's DNSKEY at the apex, signs DNSKEY
      RRset with both KSK-old and KSK-new → state: published
  T2: child sends DS RRset to parent containing DS-new
  T3: parent accepts and publishes DS-new → state: ds-published
  T4: after Dprop_child + Dprop_parent → state: standby
      (i.e. the DNSKEY RRset has been cached everywhere AND the
       parent's DS has been cached everywhere)
  T_roll: KSK-old: active → retired, KSK-new: standby → active
  T_roll + (Dsig_remaining + Dprop_child):
      KSK-old: retired → removed (DNSKEY withdrawn).
      DS RRset recomputed; DS-old drops out on next push.
```

### 3.4 State machine — method-specific

The two methods need different state machines. They share the same
state *names* but the ordering differs:

**Multi-DS** (§3.2):
```
  created → ds-published → standby → published → active →
  retired → removed
```
- `created`: key material generated; DNSKEY not at apex; DS not yet
  in the DS RRset pushed to parent
- `ds-published`: parent has accepted and published the DS
  (confirmed by observing DS RRset at any parent NS; §7)
- `standby`: DS-propagation delay elapsed; DS safe for validators
- `published`: DNSKEY now at the apex
  (held for ~zero time in multi-DS before transitioning to `active`)
- `active`: signing with this KSK
- `retired`: no longer signing; waiting for old RRSIGs/DNSKEY RRset
  to expire from caches
- `removed`: DNSKEY withdrawn from apex (Shor's Clock stops).
  The DS remains in the parent's DS RRset until pipeline maintenance
  replaces it — a garbage-collection concern, not a key-state one.

**Double-signature** (§3.3):
```
  created → published → ds-published → standby → active →
  retired → removed
```
- `published`: DNSKEY at the apex (signing begins in parallel with
  old KSK)
- `ds-published`: DS accepted and published at parent
- `standby`: both child- and parent-side propagation are complete
  (`Dprop_child + Dprop_parent` elapsed since `ds-published`);
  validators holding the old DNSKEY RRset have refreshed and can
  chain through the new KSK
- `active`: only this KSK signs (old KSK retired)
- `retired` → `removed`: as in multi-DS

**Modeling**: we express this in code by making the key's state
column an enum large enough for all states, plus a `rollover_method`
field on the key (set at rollover start, immutable for that key's
lifecycle) that drives which transition table the worker uses. The
worker's FSM switches on `rollover_method` and looks up the next
allowed state + gate condition.

**Invariant — exactly one active KSK**: at any instant there is
exactly one KSK in state `active` for the zone. Rollover is atomic:
the transition of KSK_n from `active` to `retired` happens at the
same tick as KSK_n+1's transition through `published` to `active`.
The worker MUST NOT run a rollover tick where either state is
observable in isolation by an outside validator.

**Design decisions** (resolved in §15):

- The existing state enum
  (`created/published/standby/active/retired/removed`) is extended
  with one new value, `ds-published`, and no others (§15.1).
- `rollover_method` is persisted per-key on `RolloverKeyState` and
  is immutable for that key's lifecycle (§15.2). Deriving from
  zone policy on each tick would break if policy changed
  mid-rollover.

### 3.5 Failure and recovery

Each parent-coordinated step has three outcomes:

- **confirmed** (proceed)
- **timeout** (parent didn't confirm within `Dconfirm`): stay in
  current state, log, retry the DS push (idempotent) on next worker
  tick
- **hard-fail** (parent returned REFUSED/NXDOMAIN/SIG(0) verify
  fail): stop the rollover for this key, set `last_rollover_error`,
  surface via metrics + log. Operator intervenes via CLI
  (`rollover reset`) to clear the error and resume.

**Restart safety**: because the key's state + `rollover_method` are
persisted on each transition, the worker resumes from the last
confirmed state on restart. No in-memory state is authoritative.

### 3.6 KSK/ZSK split vs. CSK

A DNSSEC zone can use either of two signing arrangements:

- **KSK/ZSK split (classic)**: the KSK (DNSKEY flags 257, SEP bit
  set) signs only the DNSKEY RRset at the apex. A separate ZSK
  (flags 256) signs every other RRset in the zone. The parent's DS
  points at the KSK.
- **CSK (Combined Signing Key)**: a single key (flags 257, SEP bit
  set — indistinguishable from a KSK at the protocol level) signs
  both the DNSKEY RRset AND every other RRset in the zone. There
  is no ZSK.

The choice is per-zone, expressed in the named `dnssec-policy`
the zone references. A policy declares either `ksk-zsk` or `csk`
mode (concrete config name in §5 — this subsection describes
semantics only).

**The CSK/KSK distinction is purely local to the child zone.** The
parent sees only a flags-257 DNSKEY and a DS that hashes it — it
has no way to tell, and no need to care, whether that key also
signs other RRsets inside the child. All parent-side coordination
(multi-DS pipeline, DS UPDATE, DS-at-parent confirmation per §7)
operates identically regardless of whether the child runs KSK/ZSK
or CSK.

**Implications for the rollover FSM**:

- The rollover state machine defined in §3.2 – §3.5 applies
  unchanged to the zone's flags-257 key in both modes. CSK is not
  a separate rollover type; it is rolled exactly like a KSK, with
  the same multi-DS / double-signature methods, the same state
  transitions, the same parent-coordination via DS UPDATE and
  DS-at-parent observation (§7).
- In `ksk-zsk` mode, a parallel ZSK state machine runs alongside
  the KSK one. ZSKs use the existing
  `created/published/standby/active/retired/removed` flow without
  parent coordination — no DS changes, no parent queries. This
  is what the existing `KeyStateWorker` already does for ZSKs and
  remains untouched by this project.
- In `csk` mode, there is no parallel ZSK machine. The worker
  simply does not generate, publish, or transition ZSKs for zones
  whose policy is `csk`.

**Implications for the signer** (critical, spell out for
implementer):

- In `ksk-zsk` mode, the active KSK signs **only** the DNSKEY
  RRset. The active ZSK signs every other RRset (SOA, NS, A,
  AAAA, MX, TXT, NSEC/NSEC3, …). Existing behavior.
- In `csk` mode, the active KSK signs **every RRset in the zone**,
  including but not limited to the DNSKEY RRset. This is a
  material change to the signer's per-key responsibilities: the
  same key that the parent's DS points at is now also responsible
  for all non-apex signatures.

The signer must therefore consult the zone's policy mode when
deciding which key to use for a given RRset. Pseudocode:

```
  sign_rrset(zone, rrset):
      policy = zone.dnssec_policy
      if rrset.type == DNSKEY:
          signing_key = active_KSK(zone)    # both modes
      else:
          if policy.mode == csk:
              signing_key = active_KSK(zone)
          else:   # ksk-zsk
              signing_key = active_ZSK(zone)
      RRSIG = sign(rrset, signing_key)
```

All other aspects of the rollover design — multi-DS pipeline,
ε-sequencing, clamping, parent confirmation — behave identically
in both modes. The only difference is which keys exist and what
they're used to sign.

### 3.7 Epsilon-sequencing: from math model to real operations

The timelines in §3.2 and §3.3 and the worked example in §4.1 show
*logical* ordering — multiple state transitions "happen at T+0" or
"happen at T+15min." In practice, the worker executes the steps
behind each logical instant as a small ordered sequence with real
dependencies: a DS change at the parent must wait for the child
zone change to be published and propagated first (and vice versa,
when adding new KSKs).

The governing invariant, from §3.2: **every RRSIG-over-DNSKEY the
child publishes must be chainable via at least one DS in the
parent's cached DS RRset.** The ε-sequencing rules exist to
preserve this at every intermediate moment, not just at the
bookkeeping transitions.

**At T_roll (rollover event). Old KSK retires, new KSK activates.**

Ordering:
1. In a single DB transaction: KSK_old `active → retired`,
   KSK_new `standby → published → active`.
2. Update the signer's "active KSK" setting to KSK_new.
3. Re-sign the DNSKEY RRset with KSK_new. (The DNSKEY RRset still
   contains both KSK_old and KSK_new; only the signing key changes.)
4. Bump SOA, re-sign apex. Publish zone.
5. Propagate to child secondaries. Wait until
   `observed_serial == new_serial` at all secondaries, or until a
   bounded timeout.

No DS-RRset change at the parent is triggered at T_roll. KSK_old's
DS stays in the parent's DS RRset because KSK_old's DNSKEY is
still at the apex (state `retired`). This is correct: validators
that still hold cached RRSIGs signed by KSK_old can still chain
through DS_old.

**At T_roll + margin (retired key's DNSKEY withdrawal + DS RRset
recomputation).**

Ordering is strict — child-side change first, parent-side change
second:
1. Remove KSK_old's DNSKEY from the apex (state:
   `retired → removed`).
2. Re-sign DNSKEY RRset with KSK_new (now contains only KSK_new,
   plus any other published KSKs).
3. Bump SOA, re-sign apex. Publish.
4. Propagate to child secondaries. Wait until confirmed.
5. **Only now** recompute the target DS RRset (§6.1). DS_old drops
   out; if a successor key has entered `created`, its DS joins.
6. Send the DS UPDATE to the parent.
7. On NOERROR: update `last_ds_submitted_index_range_*` and
   `last_ds_submitted_at` on `RolloverZoneState`.
8. Poll parent NS for the expected DS RRset (§7). On observation:
   update `last_ds_confirmed_index_range_*` and
   `last_ds_confirmed_at`. The successor key advances
   `created → ds-published`. KSK_old's DS being removed is
   reflected by the persisted confirmed range having advanced
   past its index — not via a key-state transition (there is no
   key state "ds-removed").

Reverse ordering would be wrong: if DS_old were removed at the
parent before KSK_old's DNSKEY were withdrawn from the child, a
validator could briefly fetch the child DNSKEY RRset still
containing KSK_old, with no DS_old at the parent to chain to → bogus.

**At pipeline fill (new KSK entering the pipeline, e.g. KSK_{n+2}
in the worked example).**

Ordering — parent-side first:
1. Generate key material (state: `created`). DNSKEY NOT added to
   the apex; it is deliberately withheld until this key is needed
   for signing (Shor's Clock goal, §3.2).
2. Recompute target DS RRset including the new key's DS.
3. Send DS UPDATE to parent.
4. On NOERROR: update `last_ds_submitted_index_range_*` (§6.1).
   The key's state does NOT yet advance — NOERROR means the parent
   accepted the UPDATE, not that publication is observable.
5. Poll parent NS for the expected DS RRset (§7). On first
   observation: update `last_ds_confirmed_index_range_*` and
   `ds_observed_at` on the key; state advances
   `created → ds-published`.
6. Wait `DS_TTL + margin` post-observation for cache propagation.
   State then advances `ds-published → standby`.

No child-side re-sign happens here — this step touches only the
DS RRset at the parent and the keystore, not the child's DNSKEY
RRset.

**General rules**, derivable from the above:

- **A DS UPDATE that *removes* a DS** must be sent only after the
  corresponding DNSKEY has been withdrawn from the child's apex
  and the change has propagated to all child secondaries.
- **A DS UPDATE that *adds* a DS** may be sent at any time before
  the child intends to start signing with that key. In multi-DS,
  this is deliberately done far in advance.
- **The signer's "active KSK" pointer must be updated before the
  next re-sign event**, not in parallel with it. Otherwise a
  re-sign could use the old active KSK after the transaction
  declared the new one active.
- **Waiting for child-secondary propagation** between a zone
  publish and a subsequent parent update is a real bounded wait.
  The worker re-enters this step on each tick until propagation is
  confirmed; it does not block the goroutine.
- **All ε-waits are bounded**. If propagation or confirmation does
  not complete within a policy-configured timeout, the step fails
  and falls under §3.5 (timeout → retry; hard-fail → operator
  reset).

### 3.8 Preconditions for DS UPDATE

A DS UPDATE from child to parent requires several pieces of
infrastructure to already be in place. The rollover worker
assumes them and hard-fails cleanly when they are missing; the
operator is expected to provide them before enabling automated
rollover. This section enumerates the preconditions and their
failure modes so the implementer builds the right error paths.

**Required:**

1. **Child SIG(0) signing key.** The child must have a SIG(0) key
   that the parent recognizes (published as a KEY RR at the DSYNC
   target or bootstrapped via the mechanism in
   `2026-03-07-delegation-sync-refresh-plan.md`).
2. **DSYNC record at parent.** The parent zone must publish a
   DSYNC RR advertising an UPDATE endpoint for DS records.
3. **Parent willingness to accept UPDATEs.** The parent must
   authorize the child's SIG(0) key to modify the child's DS
   RRset.

**Failure-mode matrix:**

| Condition                                   | Classification | Action                                                     |
| ------------------------------------------- | -------------- | ---------------------------------------------------------- |
| No SIG(0) signing key for child zone        | hard-fail      | `last_rollover_error`; operator must generate/import one   |
| SIG(0) key present but expired/retired      | hard-fail      | `last_rollover_error`; operator rotates or extends         |
| DSYNC lookup returns NXDOMAIN / no records  | config-gated   | if `dsync-required: true`: hard-fail; else: retry each tick |
| DSYNC advertises only non-UPDATE schemes    | hard-fail      | Design is UPDATE-only (see §2 non-goals); not recoverable  |
| DSYNC lookup times out                      | retry          | Exponential backoff; eventually transient-failure log      |
| Parent returns REFUSED                      | hard-fail      | Parent doesn't authorize our key; operator investigates    |
| Parent returns NOTAUTH                      | hard-fail      | Same as REFUSED                                            |
| Parent returns FORMERR / SERVFAIL           | retry          | Likely transient                                           |
| Parent unreachable (network, timeout)       | retry          | Exponential backoff per §7.2                               |
| Parent accepts NOERROR but never publishes  | hard-fail      | Caught by §7 observation timeout (`confirm-timeout`)       |
| First-ever push; parent already has DS from another signer | see §8.7 | Import/probe logic handles; NOT a precondition failure |

Hard-fails surface via `rollover status` and `last_rollover_error`.
Retries are transparent to the operator (logged but not surfaced
in status output until `confirm-timeout` is exceeded).

**Not preconditions (but related):**

- `num-ds` > 1 for multi-DS: a policy choice, not an
  infrastructure precondition. Enforced at config parse (§5.1.1,
  §15.3).
- Active KSK exists: the worker creates one via pipeline-fill
  (§8.1) if the zone has no KSKs. Not a precondition failure.

## 4. Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│ tdns-auth                                                │
│                                                          │
│  ┌────────────────────┐       ┌──────────────────────┐   │
│  │  KeyStateWorker    │       │  ResignQ consumer    │   │
│  │  (periodic ticker) │       │  (signing path)      │   │
│  └─────────┬──────────┘       └──────────────────────┘   │
│            │                                             │
│            │ per zone, per tick:                         │
│            │  1. advance time-based ZSK states (today)   │
│            │  2. advance zone rollover sub-phase (new)   │
│            │     ├─ PendingChildPublish  (wait 2ndary)   │
│            │     ├─ PendingParentPush    (send UPDATE)   │
│            │     ├─ PendingParentObserve (poll DS)       │
│            │     └─ PendingChildWithdraw (remove DNSKEY) │
│            │  3. advance per-key state per rollover_method│
│            │                                             │
│            ▼                                             │
│  ┌────────────────────┐       ┌──────────────────────┐   │
│  │  DS-push builder   │──────▶│  SendUpdate (DNS)    │───┼──▶ parent
│  │  (DSYNC lookup,    │       │  SIG(0)-signed       │   │    NS
│  │   CreateChildUpdate│       └──────────────────────┘   │
│  │   for DS RRset)    │                                  │
│  └────────────────────┘                                  │
│                                                          │
│  ┌────────────────────┐       ┌──────────────────────┐   │
│  │  DS-at-parent poll │──────▶│  DNS query Z. DS     │───┼──▶ parent
│  │  (backoff, §7)     │       │  (parallel NS)       │   │    NS
│  └────────────────────┘       └──────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │  DnssecKeyStore  (state enum ext: ds-published)  │    │
│  │  RolloverKeyState  (rollover_method, timestamps) │    │
│  │  RolloverZoneState (zone phase, DS-range, manual)│    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

No new goroutines; the existing `KeyStateWorker` tick calls into
`RolloverTick` for the new logic. DS-at-parent poll and DS push
are helpers called synchronously from the tick (timeouts bounded).
The DS-push builder is library code in `ksk_rollover_ds_push.go`,
reusing `CreateChildUpdate` from `childsync_utils.go`.

### 4.1 Worked example: L=24h, num-ds=3, margin=15m

Concrete walkthrough of one steady-state cycle to validate the
model. Zone owner chose DNSKEY TTL = 900s (for this example we
equate it to `margin` for simplicity; normally it would be larger
and ramp down toward `margin` as R → 0). RRSIG validity at the
moment of rollover is clamped to 1800s (2·margin).

Notation: `[A, B, C]` means the DS RRset at the parent contains
DS records for KSK_A, KSK_B, KSK_C, in order. `active=X` marks
which KSK is currently signing.

| time         | DS RRset at parent    | active  | event                                                                   |
| ------------ | --------------------- | ------- | ----------------------------------------------------------------------- |
| T-ε          | `[n-1, n, n+1]`       | n-1     | data signed with KSK_{n-1}, TTL=900s, sig-validity=1800s                |
| **T+0**      | `[n-1, n, n+1]`       | **n**   | rollover: KSK_{n-1} → retired, KSK_n → active. DS RRset unchanged.      |
| T+15min      | `[n, n+1, n+2]`       | n       | margin elapsed. KSK_{n-1} → removed. DS RRset recomputed; DS_{n+2} joins (new key previously `created` → `ds-published`). |
| T+8h         | `[n, n+1, n+2]`       | n       | no change                                                               |
| T+16h        | `[n, n+1, n+2]`       | n       | no change                                                               |
| **T+24h**    | `[n, n+1, n+2]`       | **n+1** | next rollover: KSK_n → retired, KSK_{n+1} → active. DS RRset unchanged. |
| T+24h+15min  | `[n+1, n+2, n+3]`     | n+1     | KSK_n → removed; DS_{n+3} joins.                                        |

Key observations:

- **DS RRset changes lag rollover by `margin`**, not at rollover.
  At the rollover moment itself, only the *active* pointer moves;
  the DS set stays put because KSK_{n-1} is still in `retired` with
  its DNSKEY at the apex.
- **Steady-state DS RRset size = num-ds = 3.** The transient at
  T+15min keeps the set size stable: one DS drops out (retired
  key's DNSKEY gone) and one DS joins (successor key pre-published).
- **Pipeline fill timing**: KSK_{n+2} must reach `standby` (i.e. DS
  has been cached ≥ DS_TTL) well before T+24h so it's available as
  a candidate standby for the T+24h rollover. With L=24h and DS_TTL
  roughly in the minutes-to-hours range, this is easy.
- **Exactly one active KSK** at every horizontal slice of the
  table. Rollover is an instant; there's no row where active=∅ or
  active=two.

## 5. Policy Configuration

Policy is **per-zone**, expressed on the existing `DnssecPolicy`
struct (`structs.go:229`). A zone references a named policy; multiple
zones can share a policy.

### 5.1 New fields

```yaml
dnssec-policies:
  fast-experimental:
    mode:             ksk-zsk           # ksk-zsk | csk (see §3.6)
    algorithm:        ECDSAP256SHA256
    ksk:
      lifetime:       24h               # KSK rollover cadence
      sig-validity:   12h               # zone-owner choice (clamped near rollover)
    zsk:
      lifetime:       24h               # ignored when mode = csk
      sig-validity:   12h               # ignored when mode = csk
    rollover:
      method:         multi-ds          # multi-ds | double-signature | none
                                        # (none = no automated KSK rollover;
                                        # operator rolls manually via
                                        # `rollover asap` or imports keys;
                                        # ZSK/CSK lifecycle unaffected)
      num-ds:         3                 # size of DS RRset at parent
                                        # (multi-ds only): current +
                                        # N-1 future KSKs pre-published
      confirm-initial-wait: 2s          # wait after UPDATE NOERROR
                                        # before first DS-at-parent query
      confirm-poll-max:     60s         # cap on exponential-backoff
                                        # interval between DS polls
      confirm-timeout:      1h          # overall timeout; hard-fail after
      dsync-required:      true         # fail closed if DSYNC lookup fails
    ttls:
      dnskey:         2h                # zone-owner steady-state TTL
      # ds-expected observed from parent, not configured here
    clamping:
      enabled:        true              # clamp TTLs + sig-validity as R→0
      margin:         15m               # retired-KSK hold time + floor
```

### 5.1.1 The DS RRset size (`num-ds`) — multi-DS only

With multi-DS, the child maintains a pipeline of future KSKs whose
DS records have been pre-published at the parent. `num-ds` sets the
steady-state size of the DS RRset:

- `num-ds: 1` — degenerate case, equivalent to a naive rollover
  (no pre-publication). Not useful for the Shor's-Clock goal.
- `num-ds: 2` — RRset contains DS_current + DS_next. Minimal
  multi-DS; one KSK queued for future use.
- `num-ds: 3` — RRset contains DS_current + DS_next + DS_next+1.
  Recommended starting point: the parent always has at least one
  fully-propagated DS for a future key, so a KSK emergency rollover
  doesn't have to wait a full DS_TTL propagation.
- `num-ds: N` — generalizes. Larger N increases parent UPDATE size
  and the number of DS records queried by every validator, but
  buys deeper emergency-rollover headroom.

At steady state the KeyStateWorker maintains `num-ds` keys in the
DS RRset (states `{ds-published, standby, published, active,
retired}`). When a retired key transitions to `removed` (DNSKEY
withdrawn from apex), its DS drops out of the DS RRset on the next
recomputation (§6.1) and a new key enters the pipeline in `created`
→ `ds-published`, keeping the RRset size stable at `num-ds`.

For double-signature, `num-ds` is ignored (or must be 2 — the
method doesn't support deeper pre-publication because it implies
publishing the corresponding DNSKEYs, defeating the Shor's Clock
benefit).

### 5.2 Zone-owner TTLs and RRSIG validity, clamped on approach to rollover

TTLs and RRSIG validity are **policy choices of the zone owner**, not
values derived from the KSK lifetime. One zone owner may choose
`dnskey-ttl: 2h`, another `12h`; both are valid steady-state choices
and the signer publishes the zone-owner value at steady state.

What the signer does own is **clamping near a rollover**: as the
next rollover approaches, the operator's chosen TTL and RRSIG
validity values are clamped so that records published just before
the rollover will have drained from caches shortly after it.

Single tunable — `margin`:

- **`margin`** is the operator's chosen hold time for a retired KSK:
  after rollover, we want all cached data that depends on the old
  KSK to be flushed within `margin`, at which point the retired KSK
  transitions `retired → removed`.
- `margin` subsumes what earlier drafts of this document called
  "overlap," "safety margin," and "`_min` floor." They are the
  same value: the TTL of the last record published before the
  rollover, and equivalently the minimum TTL/RRSIG-validity floor
  used during clamping.

Default: `margin: 15m`. Strong reason to keep short under CRQC
threat model; longer values delay `retired → removed`.

Clamping rule. Let `R = T_next_roll - T_now`, where `T_next_roll`
is always the time of the **next** scheduled rollover. At the
moment a rollover fires, `R` resets: `T_next_roll` advances by
`ksk.lifetime`, and `R` jumps from ≈0 back to `ksk.lifetime`. `R`
is never negative.

At each signing event, the signer publishes records with:

```
  dnskey_ttl_used = min(dnskey_ttl, R + margin)
  sig_validity_used = min(sig_validity, R + margin)
```

and similarly for other clamped parameters (see §5.3). The clamp is
bounded below by `margin` (the floor): records published at
`R = 0` get TTL = `margin`.

- Steady state (R large): clamp inactive; operator values used
  verbatim. Weekend-safe.
- Approaching rollover (R small): clamp drives TTL and RRSIG
  validity down; the last records signed before rollover carry
  TTL ≈ `margin` and RRSIG validity ≈ `margin`.
- At rollover (R = 0): newly signed records carry TTL = `margin`.
- `margin` after rollover: all pre-rollover cached data has
  expired; KSK_n transitions `retired → removed`.

Implementation notes:

- Re-signing frequency must be high enough to observe the clamp as
  it tightens. If the signer only re-signs every N hours but the
  clamp is driving RRSIG validity down to 30 minutes in the final
  hour, the published RRset may still carry a stale long value.
  Trigger re-sign on `next-clamp-boundary` in addition to the usual
  re-sign threshold.
- DS TTL is set by the parent, not the child; `ds_ttl_used` is the
  child's **expectation** of what the parent has published. If the
  parent's observed DS TTL is larger than the clamp, the worker logs
  a warning and uses the observed value for its timing math.
- Clamping is optional and can be disabled (`clamping.enabled:
  false`) for zones that want fixed TTLs at the cost of a longer
  retired window.

Constraints validated at config parse (warn, not reject):

- `dnskey-ttl ≤ ksk.lifetime / 4` — at least a few TTL windows per
  key lifetime, so the clamp has somewhere to ramp from
- `sig-validity ≤ ksk.lifetime` — RRSIGs should not outlive the key
  that signed them
- `margin ≥ 60s` — below one minute, clamp granularity is
  indistinguishable from clock skew

YAML sketch (replaces both the `ttls:` and `ramping:` blocks of the
previous draft):

```yaml
    ttls:
      dnskey:       2h       # zone-owner choice, steady-state value
      # ds-expected is observed from parent, not set here
    rrsig:
      ksk-validity:  14d
      zsk-validity:  7d
    clamping:
      enabled:      true     # clamp TTLs and RRSIG validity as R→0
      margin:       15m      # floor AND retired-KSK hold time
```

Clamping scope is resolved in §15.4: when `clamping.enabled: true`,
clamping applies **uniformly to every RRset signed or published**
by the zone — DNSKEY, DS-expectation, NSEC/NSEC3, SOA MINIMUM, and
every other TTL and RRSIG validity. No per-type exception list.

### 5.3 Coupled parameters: list

Parameters that the clamping machinery (§5.2) touches in a
rapid-rollover configuration. All items marked ✅ are clamped
uniformly (§15.4); the one remaining non-trivial coupling is the
re-sign trigger cadence.

- ✅ DNSKEY TTL
- ✅ DS TTL (child's expectation of parent; actual parent TTL is
  observable via DS query)
- ✅ RRSIG validity (KSK, ZSK, and every other RRSIG in the zone)
- ✅ Propagation delays (child, parent) — derived from TTLs
- ✅ KSK / ZSK lifetime — zone-owner input (ZSK inherits KSK when
  mode=csk)
- ✅ NSEC / NSEC3 TTLs — clamped along with all other TTLs
- ✅ SOA MINIMUM — clamped along with all other TTLs
- ⚠ **RRSIG re-sign cadence**: the signer must re-sign often enough
  that clamped RRSIG validity values are actually reflected in
  published RRSIGs. Phase 4 adds a new helper
  `ComputeNextClampBoundary(z, now)` returning the next time any
  clamped value would change by more than a minor threshold
  (e.g. TTL halves, RRSIG validity drops below currently-published
  value). The rollover worker nudges the zone onto `ResignQ`
  whenever that boundary passes. Without this, rapid-cadence
  policies publish stale long RRSIG values until the signer's own
  refresh-cycle timer fires.
- ⚠ Parent's own TTL for DS — we can observe but not control it.
  Policy should record the observed value and warn if it exceeds
  the child's clamped `ds-expected`. This is a diagnostic, not a
  correctness issue (parent's DS TTL controls parent cache
  behavior; child clamping controls child cache behavior).

## 6. DS Push to Parent

### 6.1 Whole-RRset semantics

The child **always sends the complete DS RRset** in every UPDATE to
the parent. No add/remove diffing. The UPDATE expresses "this is the
DS RRset that should be at the delegation point" as an outright
replacement.

This is the natural fit for:
- multi-DS, where the RRset routinely contains more than two DS
  records (current KSK + next KSK + next-next KSK + …)
- rollover progression, where advancing from "pre-publish new" to
  "retire old" is just another whole-RRset push
- operator clarity — the DS RRset is the ground truth being
  expressed; diffing is an implementation concern we don't need

**Per-zone rollover index.** Each KSK gets a monotonically
increasing integer index when it is generated: KSK_0, KSK_1, KSK_2,
… This `rollover_index` is a new persisted column on the keystore
row (see §9) and is per-zone, independent of the RFC 4034 DNSKEY
keytag (which can collide). The index makes DS-RRset identity
straightforward for both the worker and the operator:

- The zone is "on KSK_n" when KSK_n is `active`.
- At steady state the target DS RRset is
  `{DS_n, DS_{n+1}, …, DS_{n+num-ds-1}}` — a contiguous range of
  indices starting at the active key.
- A status field `current_ds_index_range = [n, n+num-ds-1]`
  identifies exactly what the parent is expected to hold.
- Operator-facing commands can speak in indices:
  `rollover status` → "active=KSK_76, DS set=[76,77,78]".

The DS RRset pushed at each step is computed from the keystore:
include a DS for every KSK whose current state is `ds-published`,
`standby`, `published`, `active`, or `retired` (i.e. every KSK that
*should* have a DS at the parent right now, per §3.2/§3.3). Exclude
KSKs in `created` (not yet announced) or `removed` (DNSKEY already
withdrawn from the apex).

Special case: a KSK in `created` that the worker wants to add to
the set on this tick is included in the computed RRset for this
push. On observation at parent (§7), the key's state advances to
`ds-published`. NOERROR alone from the parent is NOT sufficient.

**Two distinct persisted ranges.** The worker maintains two
integer ranges on `RolloverZoneState`, not one. Conflating them is
a bug vector (a NOERROR UPDATE that is never actually published by
the parent would cause the worker to advance key states on the
basis of "we sent it" rather than "parent has it"):

- `last_ds_submitted_index_range_low/high` + `last_ds_submitted_at`
  — updated on NOERROR from the parent. Drives the
  **push-needed?** decision: if the computed target range differs,
  send the UPDATE; if it matches, the UPDATE has already been
  accepted, no need to re-send.
- `last_ds_confirmed_index_range_low/high` + `last_ds_confirmed_at`
  — updated when the expected DS RRset is actually observed at any
  parent NS (§7). Drives all **key-state transitions that depend
  on parent publication**: `created → ds-published`, removals
  being gated on old DS no longer observed.

Decision rules in code form:

```
push_needed(z) :=
    compute_target_range(z) != last_ds_submitted_range(z)

advance_created_to_ds_published(z, k) :=
    k.state == created AND
    k.rollover_index ∈ last_ds_confirmed_range(z)

removal_confirmed(z, k) :=
    k.state == retired AND
    k.rollover_index ∉ last_ds_confirmed_range(z)
```

The distinction is small in code but critical for correctness: a
parent that NOERRORs every UPDATE but never actually publishes is
caught at the observation step, not the submission step.

### 6.2 Flow

**Phase 2 note:** `PushWholeDSRRset` implements steps 3–7 (and parent
resolution) for manual/CLI use; the worker-driven loop (steps 1, 8–9)
awaits Phase 4. DSYNC is resolved via `Imr.LookupDSYNCTarget` (UPDATE
scheme; tries `TypeDS` then `TypeANY`), which wraps the same discovery
machinery as `DsyncDiscovery` in `dsync_lookup.go`.

1. Worker determines a state transition would change the target DS
   RRset for zone Z.
2. DSYNC lookup: reuse `DsyncDiscovery(ctx, Z)` from
   `dsync_lookup.go` to find the parent's UPDATE target for DS.
   - Scheme MUST be `UPDATE` (`dns` in DSYNC terms). Other schemes
     (future HTTPS API) are out of scope.
   - If no DSYNC found: if `dsync-required: true`, fail-close and
     enter `failed` phase; else log and skip until next tick.
3. Compute the target DS RRset (§6.1).
4. Build the UPDATE as a whole-RRset replacement: DEL ANY DS at the
   child's owner name, then ADD the full set of DS RRs.
5. SIG(0)-sign the UPDATE with the child zone's active SIG(0) key
   (same key used by delegation sync today).
6. `SendUpdate(msg, Z, parentTargets)` — existing helper. Parse
   rcode + EDE for diagnostics.
7. On NOERROR: update `last_ds_submitted_index_range_*` and
   `last_ds_submitted_at` on `RolloverZoneState` when the submitted DS
   set's rollover indices are fully known (Phase 2 skips the write if any
   KSK in the set lacks `RolloverKeyState.rollover_index`). Keys retain
   their current state — NOERROR means "parent accepted the
   UPDATE," NOT "parent has published." State advances require
   observation (§7).
8. Schedule DS-at-parent poll (§7.2). On successful observation,
   update `last_ds_confirmed_index_range_*` and
   `last_ds_confirmed_at`; any KSK newly added to the set
   transitions `created → ds-published`.
9. On non-NOERROR: log + EDE; stay in current state; next tick
   retries. Whole-RRset push is naturally idempotent.

### 6.3 DS RR construction

- Compute DS from the DNSKEY RR in the keystore using the digest
  algorithm(s) configured for the zone (default SHA-256; SHA-384
  optional).
- Support publishing multiple DS digests per key if configured. Not
  required for v1.

### 6.4 What changes in which call

- `SyncZoneDelegationViaUpdate` stays as-is for NS/glue.
- **`v2/ksk_rollover_ds_push.go`** (Phase 2):
  - `BuildChildWholeDSUpdate(parent, child, newDS)` — whole-RRset UPDATE
    (DEL ANY DS at the child owner, then INSERT `newDS`).
  - `ComputeTargetDSSetForZone(kdb, childZone, digest uint8)` — walks
    `DnssecKeyStore` for SEP keys in states `ds-published`, `standby`,
    `published`, `active`, `retired`; joins `RolloverKeyState` for
    `rollover_index` when present. Returns the DS RRset, optional
    index low/high, and whether every row had a rollover index (used
    to decide whether `last_ds_submitted_index_*` may be updated).
  - `PushWholeDSRRset(ctx, zd, kdb, imr)` — resolves parent (`zd.Parent`
    or `Imr.ParentZone`), DSYNC UPDATE target (`LookupDSYNCTarget`, DS
    then ANY scheme), SIG(0)-signs via `SignMsg`, `SendUpdate`. On
    NOERROR and known index range, persists `last_ds_submitted_*` on
    `RolloverZoneState`. Digest is SHA-256 only in this phase.
- **`v2/cli/ksk_rollover_cli.go`**: `keystore dnssec ds-push` with
  `--dry-run` for operator testing before the worker calls
  `PushWholeDSRRset`.

## 7. Parent Confirmation via DS Query at Parent Agent

After a DS UPDATE completes NOERROR, the child must confirm the
parent has actually published the new DS RRset before advancing
the affected key(s) to `ds-published`.

The original plan was to use the KeyState EDNS(0) option to let the
parent actively report DS publication state. On reflection that
requires extending draft-berra and is out of scope for this
project; we therefore adopt a simpler approach modeled on BIND9's
"parent-agent" pattern. KeyState EDNS(0) confirmation remains a
future optimization (§16).

### 7.1 Model: parent-agent DS query

The "parent agent" for zone Z is any parent NS — the set of NS
records at the delegation point. Confirmation works by querying
parent NS for `Z. DS` and matching the answer against the expected
DS indices (§6.1).

The child considers the parent to have **published** a change when
any parent NS returns the expected DS RRset. This is conservative
in favor of the validation-chain invariant: if any parent NS has
the new data, at least some validators can chain through it, and
by the time propagation completes all validators can.

"Observed at any parent NS" only starts the DS propagation clock.
Advancing from `ds-published → standby` still requires waiting
`DS_TTL + margin` past the observation time, so validators that
may have cached the old RRset before publication have had time to
expire it.

### 7.2 Poll schedule

After the DS UPDATE returns NOERROR:

1. **Initial wait**: `confirm-initial-wait` (default 2s). Gives the
   parent's signer/publisher time to push the change to its own
   secondaries before the first query.
2. **First query**: query all parent NS in parallel for `Z. DS`.
3. **Match**: if any response contains the expected DS RRset
   (indices match §6.1's `current_ds_index_range`), record the
   "first observed at parent" timestamp and advance to step 5.
4. **Backoff**: if no match, wait 2 × previous interval and retry.
   Cap at `confirm-poll-max` (default 60s). Continue until overall
   elapsed time reaches `confirm-timeout` (default 1h).
5. **Propagation wait**: once observed, wait
   `DS_TTL_observed + margin` before advancing any keys from
   `ds-published → standby`. (This wait is tracked as a timestamp
   on the key, not as an active sleep — the worker checks on each
   tick.)

Example backoff: 2s, 4s, 8s, 16s, 32s, 60s, 60s, 60s … until
`confirm-timeout`.

### 7.3 Outcomes

- **Observed**: per §7.2 step 5; advance proceeds normally.
- **Timeout** (`confirm-timeout` elapsed with no observation): the
  worker sets `last_rollover_error` on every key that was waiting
  on this push and operator intervention is required. Per §3.5,
  this is a hard-fail — the parent has accepted the UPDATE
  (NOERROR) but never published; something is structurally wrong
  and automatic retry would mask it.
- **Parallel NS divergence**: if different parent NS return
  different DS RRsets, treat any NS seeing the expected set as
  sufficient (per §7.1). Log the divergence for operator
  visibility; do not require consensus.

### 7.4 Relationship to removals

A DS push that *removes* a DS (because a KSK advanced to `removed`
and its DS dropped out of the target set) follows the same
confirmation pattern:

- Expected post-push DS RRset is the new `current_ds_index_range`.
- "Observed" means any parent NS returns a DS RRset matching the
  new set by the algorithm in §7.5 below.
- The zone's persisted `last_ds_confirmed_index_range_*` is
  advanced only when observed.

No separate removal-specific logic is needed; the index-range
comparison in §6.1 handles both additions and removals uniformly.

### 7.5 DS RRset match algorithm (normative)

"Match the expected DS RRset" is more precise than
keytag-equality. The following algorithm MUST be used:

**Inputs:**
- `expected` = set of DS records computed from the target
  `current_ds_index_range` (§6.1) via `ComputeTargetDSSet`.
- `observed` = set of DS records in the ANSWER section of the
  parent's response (for `Z. DS` query, owner name = Z).

**Canonical form of a DS record** (for comparison):
```
(keytag : uint16, algorithm : uint8, digest_type : uint8, digest : bytes)
```

TTL is **ignored**. RDATA ordering within the RRset is
**ignored** (compare as sets). CLASS is assumed `IN`; any other
class = match failure.

**Matching rule:**

```
observed MATCHES expected IFF:
    ∀ e ∈ expected: ∃ o ∈ observed such that canonical(o) == canonical(e)
    AND
    ∀ o ∈ observed with keytag ∈ keytags(expected):
        ∃ e ∈ expected such that canonical(o) == canonical(e)
```

Informally:
1. Every DS we expect must be present in the parent's response
   (exact canonical match).
2. Every DS in the response whose keytag belongs to *our* managed
   keys must be one we expected. (This catches a parent that has
   published a stale or wrong DS for one of our keys.)
3. DS records in the response whose keytag does NOT match any of
   our managed keys are **allowed**. These are foreign DS records
   (another signer, an operator-added DS, etc.). Log them (§8.7)
   but do not fail the match.

**Multiple DS per key** (same keytag, different digest-type):
allowed both in `expected` and `observed`. Each (keytag,
digest_type, digest) tuple must match independently.

**Transport:**
- Use TCP for the DS query (avoids truncation issues with larger
  DS sets — `num-ds ≥ 3` with multiple digest types can exceed
  512 bytes).
- If UDP is tried and the TC bit is set, retry over TCP; do not
  evaluate truncated responses.

**DNSSEC validation:**
- DS responses from parent NS are not independently validated by
  the child (we do not require the child to be a validator). The
  child trusts its DNS stack's recursive resolver if queries are
  sent there, or trusts the direct authoritative response if
  queried directly.

## 8. KeyStateWorker Extension

### 8.1 New per-tick logic (overview)

The full per-tick checklist is in §8.8. The loop below is a
high-level summary for orientation.

```
for each zone z with signing enabled and dnssec_policy != nil:
    if policy.rollover.method == none:
        # No automated KSK rollover. Operator may still trigger
        # via `rollover asap`. ZSK/CSK lifecycle (where applicable)
        # runs normally. Skip pipeline-fill, skip scheduled trigger.
        continue_to_zsk_logic_only(z)
        continue

    # (a) keep the pipeline full
    if policy.rollover.method == multi-ds:
        pipeline = count(KSKs in z with state in
                         {created, ds-published, standby, published,
                          active, retired})
        while pipeline < policy.rollover.num-ds:
            GenerateAndStageKey(z, KSK, policy.algorithm)
            pipeline += 1
    else:   # double-signature
        active_ksk = keystore.GetActiveKSK(z)
        if active_ksk == nil or
           (now - active_ksk.ActiveSince) > policy.ksk.lifetime:
            if no KSK in {created, published, ds-published, standby}:
                GenerateAndStageKey(z, KSK, policy.algorithm)

    # (b) zone sub-phase machine runs one step (see §8.8 for the
    # full ordered checklist including atomic_rollover trigger,
    # DS push, parent-observe polling, retired-key withdrawal)
    advance_rollover_phase(z, now)

    # (c) per-key time-based advances that don't depend on the
    # phase machine (e.g. ds-published → standby when DS
    # propagation delay has elapsed since ds_observed_at)
    for key in keystore.GetKSKsInZone(z):
        advance_time_based(z, key, policy)

    # (d) existing behavior: ZSK standby counts, published → standby
    #     and retired → removed timers for ZSKs
    existing_logic(...)
```

`rollover_due(z, now)` returns true if any of:
- **scheduled rollover**: time since active KSK entered `active`
  exceeds `policy.ksk.lifetime`; prerequisites (next KSK in
  `standby`) must also hold or the rollover is deferred.
- **manual-ASAP rollover**: operator requested via the CLI
  (§10.2) and the computed `T_earliest` has been reached.

`atomic_rollover(z)` preserves the "exactly one active" invariant
(§3.4). It runs in a single DB transaction:

1. Pick the standby KSK with the oldest `standby_at` as KSK-new.
2. KSK-old `active → retired`; KSK-new
   `standby → published → active` (multi-DS collapses these two
   transitions).
3. Set `rollover_phase = pending-child-publish` on
   `RolloverZoneState`; set `rollover_in_progress = TRUE`.
4. Trigger re-sign (commit-before-resign ordering; see §12 R3).

Steps 5+ (push DS RRset, observe at parent, withdraw retired key)
are handled by the sub-phase machine on subsequent ticks.

### 8.2 Why keep it in one worker, not one-goroutine-per-zone

- Current pattern in tdns-v2 is one worker iterating zones.
- Rollover operations are all non-blocking I/O with bounded
  timeouts (DNS UPDATE has a short deadline; DS-at-parent poll is
  1 RTT per NS, in parallel).
- Parallelism is a future optimization if needed — can be introduced
  without changing the FSM.

### 8.3 Triggering signing

- Entering/leaving a KSK from the active set must trigger re-sign
  (for DNSKEY RRset at minimum; full apex for method-dependent
  reasons). Reuse the existing `triggerResign(conf, zoneName)`
  helper (`key_state_worker.go:261`).

### 8.4 Persistence & restart

- Worker reads key `state` + `rollover_method` + `rollover_state_at`
  on each tick.
- No in-memory FSM state.
- Restart is indistinguishable from any other tick — the worker
  picks up each key in its persisted state and re-attempts the next
  action (which is idempotent at the parent).

### 8.5 Earliest-rollover computation and manual override

Rapid-cadence policies (e.g. `L = 10d`) will eventually schedule a
rollover for an inconvenient time (Christmas Eve, middle of a long
weekend). Operators need a way to roll "ASAP" ahead of schedule,
and the system must compute what "ASAP" means consistent with the
rollover invariants.

**`ComputeEarliestRollover(z)`** returns:

- `t_earliest time.Time` — the earliest moment a rollover can
  safely fire
- `from_idx, to_idx int` — rollover_index of the active KSK and
  its scheduled successor
- `gates []Gate` — the set of constraints that produced `t_earliest`
- `err error` — non-nil if a rollover cannot be scheduled (e.g. one
  is already in progress)

```
ComputeEarliestRollover(z):
    if rollover_already_in_progress(z):
        return error("rollover already in progress for z")

    next_ksk = oldest_standby_ksk(z)
    if next_ksk == nil:
        return error("no standby KSK available; pipeline not ready")

    // Constraint 1: max TTL of any record currently published by z
    // must expire, minus one margin (records published at T_roll
    // get TTL = margin, so we need the previous max-TTL to expire).
    max_ttl_expiry   = now + max_published_ttl_in_zone(z) - margin

    // Constraint 2: max RRSIG validity currently in the zone must
    // expire similarly.
    max_sig_expiry   = now + max_published_rrsig_validity(z) - margin

    // Constraint 3: next KSK's DS must be fully propagated at
    // parent. If next_ksk is already in `standby`, this is 0.
    ds_ready_at      = next_ksk.ds_observed_at + ds_ttl + margin
                        if next_ksk.state != standby else now

    t_earliest = max(now, max_ttl_expiry, max_sig_expiry, ds_ready_at)
    return (t_earliest, active_ksk.rollover_index, next_ksk.rollover_index,
            gates_from_above, nil)
```

**Manual-ASAP request.** When the operator runs `rollover asap`
(§10.4), the worker:

1. Calls `ComputeEarliestRollover(z)`. On error (rollover already
   in progress, no standby KSK), rejects the request.
2. Sets `manual_rollover_requested_at = now` and
   `manual_rollover_earliest = t_earliest` on the zone row.
3. Starts clamping immediately: from this moment on, all re-signs
   use TTL = margin and RRSIG validity = 2·margin. This means the
   *new* records published carry short TTLs; the constraint on
   `t_earliest` comes from records published *before* the manual
   request.
4. Returns the scheduled timestamp to the operator.

On each subsequent tick until `t_earliest`:

- Re-evaluate `ComputeEarliestRollover(z)`. Because clamping is
  active, `max_ttl_expiry` and `max_sig_expiry` walk toward `now`
  as old records expire; `t_earliest` may advance earlier (never
  later, barring external changes like a manual zone publish).
- If a tick finds `now >= t_earliest`, fire `atomic_rollover(z)`.

**Cancel** (`rollover cancel`): clears the two manual-* columns.
Clamping returns to normal `R`-driven behavior. Records published
during the cancelled override retain their short TTLs but those
expire naturally.

**Interlock with scheduled rollovers**: if a scheduled rollover
comes due while a manual request is pending, the manual request
wins — its `t_earliest` is by construction ≤ the scheduled time
(otherwise the manual request wouldn't have been accepted). No
special handling needed; `rollover_due(z, now)` is a simple OR.

### 8.6 Bootstrap (first-ever rollover for a zone)

Bootstrap is **not a special path**. The same rules, states, and
FSM transitions apply whether a zone is brand-new, just had its
first KSK generated, or has been signed by this system for years.
The worker simply observes "this zone has N KSKs in states X, Y,
Z" and acts accordingly.

Two bootstrap scenarios:

**Bootstrap from zero keys.** A zone with signing enabled and no
keys in the keystore. On the first tick, pipeline-fill (§8.1 step
a) generates KSK_0 in state `created`. The normal FSM then
progresses it: `created → ds-published` (after DS push to parent +
observation), `ds-published → standby` (after DS propagation),
`standby → active` (when the pipeline-fill logic promotes it
because there is no currently-active KSK). Pipeline-fill continues
generating KSK_1, KSK_2, … up to `num-ds`, and those advance
through their normal state flow on their own schedules.

The zone is not cryptographically signed until KSK_0 reaches
`active`. If that delay is unacceptable, the operator should use
§8.7 (import) instead.

**Bootstrap from an already-signed zone.** If the zone is
currently signed by keys managed in a different system (another
signer, an operator script, etc.), those keys must be **imported**
(§8.7) rather than re-generated. Bootstrap-from-zero would replace
them, which would break the zone's validation chain.

### 8.7 Importing existing keys

A zone may already be signed by keys produced outside this system.
Importing brings those keys into the keystore with an
operator-asserted state, so the worker can manage them from that
point forward.

**Command:**

```
tdns zone keystore dnssec import \
  --zone=Z \
  --key=path/to/keyfile \
  --state=<created|published|ds-published|standby|active|retired> \
  [--rollover-index=N] \
  [--rollover-method=<multi-ds|double-signature>] \
  [--state-at=<ISO8601>]
```

Defaults:
- `--rollover-index` defaults to `max(existing indices for z) + 1`,
  or 0 if none.
- `--rollover-method` defaults to the zone's current policy method.
- `--state-at` defaults to `now`. Pass an earlier timestamp only if
  you know the actual transition time and want propagation math
  (e.g. `standby → active` wait) to be accurate.

**Importable states and what they mean:**

| state          | DNSKEY at apex? | DS at parent? | signing? | typical use                                         |
| -------------- | --------------- | ------------- | -------- | --------------------------------------------------- |
| `created`      | no              | no            | no       | rare; key material only                             |
| `published`    | yes             | no            | no       | double-signature pre-publish state, imported mid-flight |
| `ds-published` | no              | yes           | no       | multi-DS pre-publish state, imported mid-flight     |
| `standby`      | varies          | yes           | no       | ready-to-activate key from another system           |
| `active`       | yes             | yes           | yes      | **most common** — migrating a live zone's current KSK |
| `retired`      | yes             | yes           | no       | key being aged out from a previous system           |

`removed` is not accepted for import — it has no operational
effect (key is historical).

**Trust model:** the operator's `--state` assertion is taken at
face value. The system does not verify that the DNSKEY is actually
at the apex, nor that the parent has the DS, nor that propagation
has completed. If the operator asserts `state=active` on a key
that isn't yet visible to validators, they'll create a validation
gap — that's their problem. The system's job is to manage from
whatever state was asserted, not to audit it.

**Reject during rollover:** import is rejected with a clear error
if `RolloverZoneState.rollover_in_progress` is TRUE for the zone.
See §15, resolution 6.

**Parent DS state discovery after import.** When the worker first
ticks after an import, it probes the parent to populate the
submitted and confirmed index ranges on the zone row:

1. Query parent NS (as in §7) for `Z. DS`, using the match
   algorithm in §7.5.
2. Match observed DS records against imported keys' rollover
   indices (by keytag + algorithm + digest).
3. For each imported key in state `ds-published`, `standby`,
   `active`, or `retired` whose DS is present at the parent,
   record the index as part of both
   `last_ds_submitted_index_*` and `last_ds_confirmed_index_*`.
   The probe establishes a "we and the parent agree on this set"
   baseline for both ranges.
4. If any imported key in those states has its DS *absent* at the
   parent, log a warning (operator asserted DS is there, but it
   isn't) and set `last_rollover_error` on that key. The worker
   will push the DS RRset on the next tick like any other
   recomputation, so the state self-heals.
5. If the observed DS RRset contains keytags not matching any
   imported key, log those (foreign DS records — the parent has
   something we don't know about). Per §7.5 the match does NOT
   fail, and the worker does NOT push a DS UPDATE that would
   remove foreign records until the operator imports the
   corresponding keys or explicitly reconciles.

This probe happens once per imported-key batch; subsequent ticks
use the persisted submitted/confirmed ranges as normal.

**Pipeline-fill after import.** Once the active KSK is imported,
the normal pipeline-fill logic generates successor KSKs as needed
to reach `num-ds`. Those new keys go through `created → ds-published
→ standby` on their own schedules, so the zone transitions from
"single imported KSK" to "full multi-DS pipeline" over time without
operator intervention.

**Typical migration flow:**

1. Zone is signed by an external system with KSK tag 12345, currently
   active.
2. Operator copies the private key and runs:
   ```
   tdns zone keystore dnssec import --zone=Z \
       --key=ksk-12345.private --state=active
   ```
3. First worker tick: parent-DS probe populates
   `last_ds_submitted_index_range = last_ds_confirmed_index_range
   = [0, 0]` (only KSK_0 is active).
4. Pipeline-fill generates KSK_1 (and KSK_2 if `num-ds=3`) as
   `created`.
5. KSK_1's DS is pushed to parent on next DS-RRset recomputation.
   After propagation: KSK_1 reaches `standby`.
6. Zone is now under normal management; next scheduled rollover
   will promote KSK_1 → active.

### 8.8 Per-zone rollover sub-phase (ε-sequencing in code)

§3.7 gives the ordering rules that must hold between child-side
and parent-side steps during a rollover. A naive per-key sweep of
`advance_state` cannot enforce those rules — e.g. "remove KSK_old
from the apex, wait for child secondaries, THEN push the new DS
RRset to the parent" is a cross-cutting sequence, not a per-key
transition.

The worker tracks each zone's position in this cross-cutting
sequence via a `rollover_phase` field on `RolloverZoneState`
(§9.3). The field is a small enum:

```
rollover_phase ∈ {
  idle,                    // no sequencing in progress
  pending-child-publish,   // zone re-signed & pushed; waiting for
                           // child secondaries to pick it up
  pending-parent-push,     // child done; DS RRset needs to be
                           // sent to parent
  pending-parent-observe,  // UPDATE sent NOERROR; polling for
                           // DS at parent NS (§7)
  pending-child-withdraw,  // parent confirmed; ready to withdraw
                           // retired DNSKEY from apex
}
```

**Per-tick ordered checklist for zone Z.** The worker processes
each zone on each tick by evaluating phases in this order,
executing at most one phase advance per tick:

```
1. Manual-ASAP re-evaluation (§8.5): if manual_rollover_requested_at
   is set and T_earliest has moved, update it.

2. Pipeline fill (§8.1 step a): if the count of KSKs in non-
   terminal states is less than num-ds, generate new keys in
   `created`. This step is safe to run in any rollover_phase —
   generation only touches the keystore, not DNS.

3. Atomic rollover trigger (§8.5, §3.4 invariant):
   if rollover_phase == idle AND rollover_due(z, now):
      run atomic_rollover(z)
      // atomic_rollover sets rollover_phase = pending-child-publish
      // and rollover_in_progress = TRUE as part of its transaction
      // (§8.1 step 4). Not duplicated here to keep one source of truth.

4. Phase advance, at most one per tick. **Arming a phase counts as
   the single advance** — e.g. `idle → pending-parent-push`
   transitions the phase but does NOT also send the UPDATE on the
   same tick. The send happens on the next tick when
   `pending-parent-push` is evaluated. This keeps each tick's
   observable change small and makes restart-safety trivial; do not
   "optimize" it into same-tick push.

   case rollover_phase:
     idle:
       // Steady-state pipeline maintenance. Even outside a
       // rollover, pipeline-fill (step 2) may have created new
       // KSKs whose DS needs to be pushed to the parent to keep
       // the DS RRset at num-ds entries.
       if push_needed(z):   // §6.1: target != last_ds_submitted
         rollover_phase = pending-parent-push
         // next tick handles the push. Note: idle → pending-
         // parent-push skips pending-child-publish because no
         // child-side change preceded this push — only DS RRset
         // composition changed at the parent.

     pending-child-publish:
       if child_secondaries_caught_up(z):
         rollover_phase = pending-parent-push
         // next tick handles the push

     pending-parent-push:
       if push_needed(z):   // §6.1: target != last_ds_submitted
         send_ds_update(z)
         on NOERROR:
           update last_ds_submitted_*
           rollover_phase = pending-parent-observe
         on error: stay; retry next tick
       else:
         // No push needed. Go back to whatever comes next:
         // if we're mid-rollover, proceed to withdraw; if we're
         // here from idle (steady-state), go back to idle.
         rollover_phase = pending-child-withdraw
                          if rollover_in_progress else idle

     pending-parent-observe:
       observe = poll_parent_ns(z)                 // §7.2
       if observed: update last_ds_confirmed_*
         // key-state advances that depend on confirmation happen here:
         for k in keys with state=created and index in confirmed_range:
           advance k: created → ds-published       // single TX (§9.4)
         // return to pending-child-withdraw only if mid-rollover;
         // otherwise we were steady-state pipeline push → idle.
         rollover_phase = pending-child-withdraw
                          if rollover_in_progress else idle
       if timeout: hard-fail → last_rollover_error

     pending-child-withdraw:
       if any KSK k with state=retired has been retired ≥ margin:
         advance k: retired → removed              // DNSKEY withdrawn
         re-sign zone; publish
         (if no more retired keys, rollover_in_progress = false)
       if all retired keys handled:
         rollover_phase = idle

5. Non-rollover per-key advances for keys not gated on the current
   sub-phase (e.g. `ds-published → standby` time-based advance).

6. Existing ZSK/ZSK-pipeline logic runs unchanged.
```

**Why one phase per tick.** Makes the loop easier to reason about
and easier to test. Each tick is a single observable state
transition. The worker converges to `idle` in O(margin /
tick_interval) ticks for a typical rollover.

**Restart safety.** `rollover_phase` is persisted. After restart
the worker resumes from whatever phase was last committed; each
phase's action is idempotent (re-sending the same DS UPDATE is a
no-op at the parent; re-polling DS is cheap).

**Interlock between phases and `atomic_rollover`.** Only
`atomic_rollover` writes key states that introduce `retired`
keys. It transitions `rollover_phase` from `idle` to
`pending-child-publish` atomically as part of its transaction.
From that point the phase machine runs; no other zone-level work
competes for the keystore until phase returns to `idle`.

## 9. Database Schema Changes

Schema changes split into **minimum intrusion on existing tables**
plus **new tables for rollover-specific data**. Motivation: the
entire rollover subsystem should be extractable to other repos
(tdns-mp, tdns-es) later; splitting bookkeeping into dedicated
tables keeps the extraction boundary clean and avoids bloating
`DnssecKeyStore` with project-specific columns. See §14 for
code-organization guidelines.

### 9.1 Changes to existing tables (minimal)

Only the enum on `DnssecKeyStore.state` is extended — nothing else
on the existing table changes:

```
-- Existing state column accepts one new value (see §3.4):
-- ds-published added to the existing
-- created/published/standby/active/retired/removed set.
-- No column additions.
```

The signing hot path continues to look up the key by `(zone, keyid)`,
read `state` to determine if it's `active`, and use the private key
material. No join required.

### 9.2 New table: `RolloverKeyState`

Per-key rollover bookkeeping. Kept separate from `DnssecKeyStore`
so the rollover subsystem can be extracted without tangling into
core keystore logic.

```
CREATE TABLE IF NOT EXISTS RolloverKeyState (
    zone                 TEXT NOT NULL,
    keyid                INTEGER NOT NULL,    -- RFC 4034 keytag
    rollover_index       INTEGER NOT NULL,    -- per-zone monotonic (§6.1)
    rollover_method      TEXT,                -- multi-ds | double-signature
    rollover_state_at    TIMESTAMP,           -- most recent state transition
    ds_submitted_at      TIMESTAMP,           -- last DS push containing this key
    ds_observed_at       TIMESTAMP,           -- first DS observation at parent
    last_rollover_error  TEXT,
    PRIMARY KEY (zone, keyid)
);
```

Rows are created when the rollover worker first touches a key
(e.g. on generation or import) and deleted when the key reaches
`removed` and is garbage-collected. Absence of a row means "this
key is not under rollover management" (e.g. ZSKs).

### 9.3 New table: `RolloverZoneState`

Per-zone rollover bookkeeping. tdns-v2 has no existing per-zone
bookkeeping table (only `OutgoingSerials`, scoped to SOA serial);
this is a new addition.

```
CREATE TABLE IF NOT EXISTS RolloverZoneState (
    zone                           TEXT PRIMARY KEY,

    -- §6.1: submitted vs confirmed ranges are DISTINCT. Submitted
    -- is updated on NOERROR (drives "push needed?"). Confirmed is
    -- updated on observation at parent (drives key-state advances).
    last_ds_submitted_index_low    INTEGER,
    last_ds_submitted_index_high   INTEGER,
    last_ds_submitted_at           TIMESTAMP,
    last_ds_confirmed_index_low    INTEGER,
    last_ds_confirmed_index_high   INTEGER,
    last_ds_confirmed_at           TIMESTAMP,

    -- §8.8 per-zone rollover sub-phase (the ε-sequencing state).
    rollover_phase                 TEXT NOT NULL DEFAULT 'idle',
      -- idle | pending-child-publish | pending-parent-push
      -- | pending-parent-observe | pending-child-withdraw
    rollover_phase_at              TIMESTAMP,

    -- §15.6: zone is mid-rollover; reject operator key additions.
    rollover_in_progress           BOOLEAN NOT NULL DEFAULT FALSE,

    -- Monotonic counter driving new KSK rollover_index assignment.
    next_rollover_index            INTEGER NOT NULL DEFAULT 0,

    -- §8.5 manual-ASAP rollover support.
    manual_rollover_requested_at   TIMESTAMP,  -- NULL if no pending request
    manual_rollover_earliest       TIMESTAMP   -- T_earliest; re-evaluated on tick
);
```

Both `RolloverKeyState` and `RolloverZoneState` are added to
`DefaultTables` in
`/Users/johani/src/git/tdns-project/tdns/v2/db_schema.go` alongside
the existing tables.

`rollover_method` is set when the key enters a rollover and is
immutable for the remainder of that key's lifecycle (§3.4 open
question).

`rollover_index` is assigned at key generation time and never
changes. The per-zone counter that drives it is persisted in the
zone row (§9's `next_rollover_index` column; increment on each
`GenerateAndStageKey` for a KSK/CSK).

No changes to `MPDnssecKeyStore` in this project.

### 9.4 Two-store transactional consistency

`DnssecKeyStore.state` and `RolloverKeyState.*` are two tables
that together describe one key's position in the rollover
pipeline. They MUST stay in sync — an update to `state` without
the matching update to `rollover_state_at` (or vice versa) would
leave the worker observing inconsistent data on the next tick.

Rule: **every state-advancing operation wraps both table writes
in a single SQL transaction.** Helper functions (in
`ksk_rollover_fsm.go`) encapsulate the pattern:

```go
func AdvanceKeyState(db *DB, zone string, keyid int,
                     newState string, now time.Time) error {
    tx, err := db.Begin(); …
    defer tx.Rollback()
    if err := updateDnssecKeyStoreState(tx, zone, keyid, newState); err != nil { … }
    if err := updateRolloverKeyStateAt(tx, zone, keyid, newState, now); err != nil { … }
    return tx.Commit()
}
```

On partial failure: transaction rolls back, no visible change,
worker retries on next tick. The tick logic is fully idempotent
— replaying a completed action (DS already pushed, etc.) must not
cause a state regression.

The same rule applies to `RolloverZoneState` updates that
accompany key-state changes: DS submission/observation ranges are
updated in the same transaction as the key-state advances that
depend on them.

## 10. CLI and Observability

### 10.1 New CLI commands (under `tdns zone keystore dnssec`)

- `rollover status --zone=Z` — show current KSKs, per-key state,
  rollover_method, rollover_index, timers, last error
- `rollover reset --zone=Z --keyid=N` — clear `last_rollover_error`
  and allow the worker to retry (operator recovery from hard-fail)
- `import --zone=Z --key=... --state=...` — import an externally-
  generated key with an operator-asserted state. See §8.7 for full
  semantics and the typical migration flow.
- `policy validate --file=P.yaml` — dry-run policy parser with
  constraint checks from §5.2

### 10.2 Manual rollover commands (see §8.5)

Two symmetric commands share a common computation
(`ComputeEarliestRollover`):

- **`rollover when --zone=Z`** — query only. No state change.
  Response:
  ```
  Rollover for zone Z is possible at the earliest at
  2026-04-25 14:32:00 UTC (in 4h 12m).
  Rollover NOT yet scheduled.
  Gating factors:
    - max RRSIG expiry drains at 14:17 UTC
    - margin (15m) applied
    - KSK_57 in standby since 2026-04-22
  ```

- **`rollover asap --zone=Z`** — schedule rollover at the earliest
  safe time. Sets `manual_rollover_requested_at` and begins
  immediate TTL/RRSIG clamping. Response:
  ```
  Rollover for zone Z from KSK_56 to KSK_57 scheduled for
  2026-04-25 14:32:00 UTC (in 4h 12m).
  Clamping begun: DNSKEY TTL now 15m; RRSIG validity now 30m.
  Use 'rollover cancel --zone=Z' to abort.
  ```
  Refused if a rollover is already in progress; response shows
  when that in-progress rollover is expected to complete.

- **`rollover cancel --zone=Z`** — cancel a pending manual-ASAP
  request. Clears `manual_rollover_requested_at` /
  `manual_rollover_earliest`. Records already published during
  the override keep their short TTLs (expire naturally). No-op
  if no manual request is pending.

### 10.3 Logging

- All transitions logged via structured `lgSigner` (existing logger)
  with fields: `zone`, `rollover_index`, `keyid`, `flags`,
  `old_state`, `new_state`, `method`, `elapsed`
- UPDATE send outcomes include rcode + EDE
- DS-at-parent poll outcomes include the NS queried, whether the
  expected set was observed, and the attempt number
- Manual-override requests and cancellations log `who`, `when`,
  `t_earliest`, and the gating factors

### 10.4 Metrics (future)

Not in v1. List for later: rollover attempts, failures per zone,
confirm latency, UPDATE rcodes.

## 11. Implementation Phases

Each phase is independently shippable and testable. Phases 2 and
3 have no dependency on each other and can be implemented in
parallel; both are unblocked now that Phase 1 has landed.

Per-phase summary (complexity is qualitative; LOC is order-of-magnitude):

| Phase | Complexity | New LOC | Existing LOC touched | Days | Status |
| ----- | ---------- | ------- | -------------------- | ---- | ------ |
| 1. Policy config + schema       | Low      | ~400    | ~55   | 1–2 | **Done** |
| 2. DS push                      | Medium   | ~350    | 0     | 2–3 | **Done** |
| 3. Parent-agent DS poll         | Low-med  | ~300    | 0     | 2   | Pending |
| 4. Rollover worker + FSM + phase machine + clamp trigger | High | ~1150 | ~5 | 3–4 | Pending |
| 5. Import                       | Medium   | ~250    | 0     | 1–2 | Pending |
| 6. Rapid-rollover validation    | Low (test work) | ~300 (tests) | 0 | 1–2 | Pending |
| 7. Docs & samples               | Low      | 0       | 0     | 1   | Pending |
| CSK signing-path edits          | Medium (scattered) | 0 | ~50 | 1 | Pending |
| **Total**                       |          | **~2800** | **~120** | **12–18** | |

Complexity drivers per phase are called out in the phase
descriptions below.

### Phase 1 — Policy config + schema (1–2 days, **Low** complexity) — **landed**

Complexity: Low. Pure data-shape work. Clamping function is
arithmetic with unit tests; the only conceptual subtlety is
`R`-reset at `T_roll` (§5.2). No concurrency, no I/O.

Files:
- `v2/ksk_rollover_policy.go` — new `RolloverPolicy`,
  `ClampingPolicy` structs + YAML parse + constraint checks
- `v2/ksk_rollover_clamp.go` — clamping function + unit tests
- `v2/db_schema.go` — add `RolloverKeyState` and `RolloverZoneState`
  tables to `DefaultTables`; add `ds-published` to state enum

Work:
- Extend `DnssecPolicy` with `mode` (ksk-zsk|csk), `rollover`
  subtree, `ttls`, and `clamping` subfields (§5.1, §5.2, §3.6)
- Implement clamping with unit tests: steady-state (R large, clamp
  inactive), near-rollover (R small, clamp active), R = 0 (floor
  applies), ramp continuity, R-reset at T_roll
- Schema migration (§9)
- CLI: `policy validate` command (new file
  `v2/cli/ksk_rollover_cli.go`)
- Wiring (not an exhaustive list): `v2/structs.go` (`DnssecPolicy`
  extensions), `v2/parseconfig.go` (`FinishDnssecPolicy`),
  `v2/keystore.go` (`ds-published` allowed in `setstate`),
  `v2/cli/prepargs.go`, `v2/cli/keystore_cmds.go`

### Phase 2 — DS push (2–3 days, **Medium** complexity) [parallel with Phase 3] — **landed**

Complexity: Medium. Reuses `SendUpdate`, DSYNC resolution
(`LookupDSYNCTarget`), and SIG(0) signing (`SignMsg`) from tdns-v2;
UPDATE body construction is new (`BuildChildWholeDSUpdate`). Whole-RRset
semantics (§6.1), DS digest from stored DNSKEYs, and updating
`last_ds_submitted_*` on NOERROR only when every contributing KSK row has
a non-null `rollover_index` (LEFT JOIN to `RolloverKeyState`); otherwise
the submitted range is not written, so uninitialized indices do not
fake a submission checkpoint. **Still open:** worker
integration; integration test against a live test parent; digest
algorithms beyond SHA-256 (§6.3).

Files:
- `v2/ksk_rollover_ds_push.go` — `BuildChildWholeDSUpdate`,
  `ComputeTargetDSSetForZone`, `PushWholeDSRRset` (§6, §6.4)
- `v2/ksk_rollover_ds_push_test.go` — unit test for UPDATE shape
- `v2/cli/ksk_rollover_cli.go` — `keystore dnssec ds-push` (`--dry-run`)
- `v2/cli/keystore_cmds.go` — registers the subcommand

Work (as implemented):
- `PushWholeDSRRset(ctx, zd, kdb, imr)` returning `KSKDSPushResult`
- `ComputeTargetDSSetForZone(kdb, childZone, digest)` (SHA-256 in code
  today)
- `last_ds_submitted_index_*` + `last_ds_submitted_at` on NOERROR when
  index range is known (NOT `last_ds_confirmed_*` — Phase 3)
- **Remaining:** call site from rollover worker; integration test with
  a test parent

### Phase 3 — Parent-agent DS-poll client (2 days, **Low-Medium** complexity) [parallel with Phase 2]

Complexity: Low-medium. Straightforward DNS query code plus
exponential backoff. Subtleties: NS-set discovery, parallel
querying with "any match wins" (§7.1), parent-NS divergence
logging, overall timeout bookkeeping, DS-match algorithm (§7.5)
including foreign-DS tolerance and multiple-digest-per-key. No
state machine. Unit tests with mock resolvers are easy;
integration test with a slow parent needs a test harness.

Files:
- `v2/ksk_rollover_parent_poll.go` — new `QueryParentDS` + backoff
  scheduler
- `v2/cli/ksk_rollover_cli.go` — add `query-parent` CLI subcommand

Work:
- `QueryParentDS(z, expected_index_range) (observed bool, firstAt
  time.Time, err error)` (§7)
- Exponential-backoff scheduler (2s → 60s, cap at
  `confirm-timeout`)
- Parallel NS query; match on expected DS index range

### Phase 4 — Rollover worker + FSM (3–4 days, **High** complexity) [depends on 1, 2, 3]

Complexity: High. This is the centerpiece of the project and
carries most of the conceptual load.

- Two distinct FSMs (multi-DS and double-signature) differing in
  state ordering (§3.4); implementation must switch cleanly on
  `rollover_method` without code duplication
- `atomic_rollover(z)` must preserve the "exactly one active KSK"
  invariant across a multi-step transition; transactional DB work
  plus re-sign triggering plus DS-RRset recomputation in one
  coherent operation
- ε-sequencing rules from §3.7 must be honored; correct ordering
  is "at this tick, first verify child propagation, then touch
  parent" rather than naive state-by-state advance
- `rollover_due()` juggles scheduled + manual-ASAP triggers with
  correct precedence; `ComputeEarliestRollover(z)` takes three
  separate constraints into a single max (§8.5)
- Restart-safety requires every FSM step to be idempotent and
  re-entrant; the worker's tick must be safe to replay
- CLI subcommand set (`when`, `asap`, `cancel`, `status`) shares
  the `ComputeEarliestRollover` kernel

Highest test value is also here: restart mid-rollover, operator
commands during rollover, both methods back-to-back on the same
zone.

Files:
- `v2/ksk_rollover_fsm.go` — per-key state-advance function, one
  table per method (multi-DS, double-signature)
- `v2/ksk_rollover_phase.go` — zone sub-phase machine (§8.8)
- `v2/ksk_rollover_worker.go` — `RolloverTick`; invoked from
  `checkAndTransitionKeys` via one added call
- `v2/ksk_rollover_atomic.go` — `atomic_rollover(z)` transaction
- `v2/ksk_rollover_earliest.go` — `ComputeEarliestRollover(z)`
  (§8.5)
- `v2/ksk_rollover_clamp_trigger.go` — `ComputeNextClampBoundary`
  (§5.3) to push zone to ResignQ when clamped values would change

Work:
- Integrate §3.2 (multi-DS) and §3.3 (double-signature) FSMs
- Per-zone sub-phase machine (§8.8): one phase advance per tick
- `rollover_due()` covering scheduled + manual-ASAP
- Re-sign triggering: reuse existing `triggerResign`; add
  clamp-boundary wake-up via `ComputeNextClampBoundary`
- Two-store transactional consistency (§9.4) for every
  state-advancing call
- Restart-safety test (kill worker mid-rollover, restart, verify
  resume from persisted `rollover_phase`)
- CLI: `rollover when`, `rollover asap`, `rollover cancel`,
  `rollover status` subcommands (§10.2)

### Phase 5 — Import (1–2 days, **Medium** complexity) [depends on 4]

Complexity: Medium. Import semantics themselves are simple
(trust-operator), but the parent-DS probe on first tick and the
foreign-DS handling (§8.7) require careful thought. The
"reject during rollover" gate (§15 resolution 6) is a one-line
check.

Files:
- `v2/ksk_rollover_import.go` — `ImportKey` + first-tick parent-DS
  probe (§8.7)

Work:
- `import` CLI subcommand
- Parent-DS probe logic on first tick after import
- Foreign-DS logging + don't-remove policy

### Phase 6 — Rapid rollover validation (1–2 days, **Low** complexity in code, **High** in diagnostic effort)

Complexity: Low in code (test harness setup and assertions), but
potentially high in diagnostic effort when rapid-rollover test
runs expose race conditions, timing assumptions, or parent-NS
behaviors that the earlier-phase unit tests didn't cover. Budget
slack for "one-off parent misbehavior" debugging.

- End-to-end test with ksk.lifetime = 1h, then 10m, with a pair of
  tdns-auth instances (child + parent)
- Verify clamping behavior (TTLs and RRSIG validity descend toward
  `margin` near rollover; return to operator-configured steady-state
  value after)
- Verify no gaps in DS/DNSKEY coverage at any point — continuous
  validation chain across rollovers
- Verify exactly-one-active invariant across the atomic rollover
- Document failure modes observed

### Phase 7 — Docs & samples (1 day, **Low** complexity)

- Operator guide in `tdns/docs/`
- Sample policies (steady-cadence and rapid-experimental)

## 12. Risk Assessment

Risks are rated **Low / Medium / High** by product of likelihood
and impact. Each risk has an associated mitigation or containment.

### 12.1 Technical risks

**R1. FSM subtlety: validation-chain gap during rollover.** [High]
If the ε-sequencing rules (§3.7) are implemented incorrectly — for
example, removing `DS_old` from the parent before `DNSKEY_old` has
actually been withdrawn from all child secondaries — a validator
could briefly observe a child DNSKEY RRset with no chainable DS at
the parent and return SERVFAIL/BOGUS. Impact: zone goes bogus for
affected resolvers.
Mitigation: unit tests for each ε-sequencing rule; integration
tests that query a validator mid-transition; Phase 6 rapid-rollover
stress test is designed to surface this.

**R2. Restart-safety bug: duplicate or lost state transitions.**
[Medium] Phase 4's requirement that every FSM step be idempotent
and re-entrant is easy to violate in practice — e.g. a worker
crash between "DS UPDATE sent" and "record ds_submitted_at" could
cause a retry to double-count. Impact: stuck rollover requiring
operator reset; in worst case a state inconsistency between
keystore and parent.
Mitigation: transactional state updates (DB row + timestamp in
same TX as the action that caused the transition); Phase 4 explicit
kill-restart-verify test; CLI `rollover reset` as operator
recovery path.

**R3. Atomic rollover not actually atomic.** [Medium] `atomic_rollover(z)`
(§8.5) must transition KSK_n: active→retired and KSK_{n+1}:
standby→published→active in a single observable step, plus trigger
re-sign, plus update DB. If re-sign happens before the DB
transaction commits, a crash could leave the zone signed with a
key the keystore thinks is retired.
Mitigation: strict ordering of commit-before-re-sign; re-sign is
idempotent so partial replay is safe; restart test.

**R4. Clock skew.** [Low-Medium] `R = T_next_roll - T_now`
underlies both clamping (§5.2) and `rollover_due()` (§8.1).
Clock drift on the signer host could cause clamping to fire
at the wrong time or rollover to trigger early/late. Impact: TTLs
not as expected; worst case a premature rollover.
Mitigation: policy constraint `margin ≥ 60s` (§5.2) ensures
sub-minute skew is not catastrophic; operators running rapid
cadence should ensure NTP is healthy.

**R5. Parent-side misbehavior.** [Medium] DS UPDATE returns NOERROR
but parent never publishes; parent publishes inconsistently across
NS; parent uses much longer DS TTL than expected; parent rejects
SIG(0) signatures after a policy change. Impact: stuck rollover,
hard-fail.
Mitigation: §7 explicit handling of timeouts → hard-fail →
operator reset path; §3.5 failure model; observed DS TTL overrides
configured expectation (§5.2).

**R6. Rapid-cadence parameter coupling bugs.** [Medium] The whole
point of clamping is to couple TTLs to rollover timing. Getting
the math wrong (especially the R-reset at T_roll, §5.2) creates
TTLs that don't drain in time, which in turn creates bogus
validation. Impact: silent correctness bug visible only in rapid
cadence.
Mitigation: unit tests covering R boundary conditions (R=0,
R=L, R just after T_roll); Phase 6 end-to-end rapid-rollover test
at L=1h and L=10m.

**R7. Operator-generated keys outside the rollover machinery.**
[Low] A user importing an `active` KSK (§8.7) during a rollover
can create pipeline inconsistencies.
Mitigation: the `rollover_in_progress` flag on
`RolloverZoneState` (§9.3, §15 resolution 6) is a precise gate
that blocks imports and generates across the full in-rollover
window, not just while a `retired` key exists. Error messages
name the blocking zone phase; `rollover status` surfaces it.

**R8. KeyStateWorker concurrency.** [Low] The existing
`KeyStateWorker` and the new `RolloverTick` share access to the
keystore. If both are active they could race on `state`
transitions.
Mitigation: rollover logic runs *inside* `checkAndTransitionKeys`
(§14 integration point), not in a separate goroutine. Single worker
tick = no races.

### 12.2 Non-technical risks

**R9. Scope creep toward tdns-mp.** [Medium] tdns-mp has its own
keystore (`MPDnssecKeyStore`) and its own KeyStateWorker. Pressure
to "just make it work in both" during development would roughly
double the effort and delay Phase 1.
Mitigation: §2 explicitly lists tdns-mp as non-goal; §14 code
organization is designed to make later extraction straightforward
without modifying this project's scope.

**R10. Draft-berra-dnsop-keystate evolves.** [Low] The KeyState
EDNS(0) path is deferred (§16). If the draft changes incompatibly
before we implement it later, the existing §3.4 / §9 state names
may need renaming.
Mitigation: state names in this doc are local (`ds-published`,
not `SIG0_KEY_PUBLISHED`) and not wire-visible; renaming is a code
refactor, not a protocol break.

**R11. RFC 7583 naming drift.** [Low] §3.1.1 commits to a
cross-reference table. If someone updates the spec text without
updating the table, readers get confused.
Mitigation: table is short and in the same section as the
local-name definitions; review checklist item.

## 13. Code Volume Estimate

Total new code: approximately **2800 LOC**, spread across eleven
new files; ~120 LOC of edits to existing files (including CSK
mode-aware signing-path edits in ~5 files). Most of the work is
new files, which supports both the testability and the future
extractability goals (§14).

### 13.1 New files

| File                                 | Est. LOC | Breakdown                                    |
| ------------------------------------ | -------: | -------------------------------------------- |
| `v2/ksk_rollover_policy.go`          |      300 | Structs, YAML parse, constraint validation   |
| `v2/ksk_rollover_clamp.go`           |      100 | Clamping function + helpers                  |
| `v2/ksk_rollover_ds_push.go`         |      350 | `PushDSRRset`, target-set computation, digest |
| `v2/ksk_rollover_parent_poll.go`     |      300 | `QueryParentDS` + DS-match algorithm (§7.5) + backoff |
| `v2/ksk_rollover_fsm.go`             |      400 | Two transition tables + per-key advance      |
| `v2/ksk_rollover_phase.go`           |      200 | Zone sub-phase machine (§8.8)                |
| `v2/ksk_rollover_worker.go`          |      200 | `RolloverTick`, pipeline-fill, `rollover_due` |
| `v2/ksk_rollover_atomic.go`          |      150 | `atomic_rollover(z)` transaction             |
| `v2/ksk_rollover_earliest.go`        |      100 | `ComputeEarliestRollover`                    |
| `v2/ksk_rollover_clamp_trigger.go`   |      100 | `ComputeNextClampBoundary` + ResignQ push    |
| `v2/ksk_rollover_import.go`          |      250 | `ImportKey` + parent-DS probe                |
| `v2/cli/ksk_rollover_cli.go`         |      350 | ~10 subcommands; mostly cobra boilerplate    |
| **Subtotal**                         | **2800** |                                              |

Test files (approximately 1:1 code-to-test ratio for new code, so
another ~2500–2800 LOC of tests, not counted above).

### 13.2 Existing files touched

| File                       | Est. LOC changed | Change                                                    |
| -------------------------- | ---------------: | --------------------------------------------------------- |
| `v2/db_schema.go`          |              30  | Add 2 tables to `DefaultTables`; extend state enum        |
| `v2/structs.go`            |              25  | Add `mode`, `rollover`, `clamping` subtrees to `DnssecPolicy` |
| `v2/key_state_worker.go`   |               5  | One new call: `RolloverTick(conf, kdb)` inside `checkAndTransitionKeys` |
| `v2/parseconfig.go`        |              10  | Call `rollover.ParsePolicy` during policy load            |
| `v2/sign.go` (or equiv)    |              20  | CSK mode-aware signing-key selection                      |
| `v2/zone_sign.go`          |              15  | CSK mode-aware signing-key selection                      |
| `v2/keystore.go`           |              15  | `GetActiveSigningKey(zone, rrtype)` mode-aware helper     |
| **Subtotal**               |         **120** |                                                           |

### 13.3 Interpretation

- **~96% new code, ~4% edits.** The ratio matches the §14 code
  organization goal. The non-trivial edit clusters are (a) the
  one-call integration into `key_state_worker.go` and (b) the
  CSK mode-aware edits in ~3 signing-path files (§14 blast-radius
  table).
- **Estimates are ±30%.** These are order-of-magnitude numbers
  for planning, not contracts. The FSM, phase machine, and worker
  files may shrink if the two rollover methods share more code
  than currently assumed; they may grow if CLI output formatting,
  DS-match canonicalization, or clamp-boundary computation prove
  trickier than expected.
- **CLI is proportionally large.** 350 LOC for ~10 subcommands
  reflects cobra boilerplate + output formatting, not algorithmic
  complexity.

## 14. Code organization and extractability

This project is implemented only for tdns-v2 at this stage. Parts
of the machinery — particularly the rollover FSM, policy parser,
and DS-push/DS-poll helpers — are expected to be ported to
tdns-mp, tdns-es, and other repos at a future time. The code
organization below is chosen to make that extraction a file-level
operation rather than a line-level grep.

**Guidelines:**

- **New files for new logic.** All rollover code lives in
  `v2/ksk_rollover_*.go` files. Do NOT add rollover logic to
  `key_state_worker.go`, `keystore.go`, `childsync_utils.go`, or
  other existing files, except for the minimum integration point
  (§below).
- **New tables for new data.** Key-level rollover bookkeeping
  lives in `RolloverKeyState` (§9.2), zone-level in
  `RolloverZoneState` (§9.3). Only the `state` enum on
  `DnssecKeyStore` is extended; no new columns.
- **Single integration point.** The existing `KeyStateWorker`
  gains one line in `checkAndTransitionKeys` that calls
  `RolloverTick(conf, kdb)` from `ksk_rollover_worker.go`. To
  extract the project to another repo, that one call is the only
  thing to remove; `ksk_rollover_*.go` files move wholesale.
- **Signing hot path untouched.** The signer consults key state
  via `DnssecKeyStore` as today (§9.1). It never joins against
  `RolloverKeyState` for per-signature operations. Rollover
  bookkeeping is worker-tick frequency, not per-signature
  frequency.
- **Config subtree isolation.** All new YAML fields nest under
  the `rollover:`, `ttls:`, and `clamping:` subtrees of
  `DnssecPolicy` (§5.1). Extracting the config means lifting
  those three subtrees into the target repo's policy type.
- **Parser symmetry.** Policy parsing, validation, and constraint
  checking live in `ksk_rollover_policy.go` — not inline in
  `parseconfig.go` or `config.go`. The caller does
  `rollover.ParsePolicy(raw) → RolloverPolicy`.
- **CLI isolation.** All `rollover` subcommands and related CLI
  live in `v2/cli/ksk_rollover_cli.go`, registered through the
  existing `tdns zone keystore dnssec` command tree by a single
  `init()` registration call.

**Files created by this project:**

| File                                         | Phase | Purpose                              |
| -------------------------------------------- | ----- | ------------------------------------ |
| `v2/ksk_rollover_policy.go`                  | 1     | `RolloverPolicy`, `ClampingPolicy`, parse |
| `v2/ksk_rollover_clamp.go`                   | 1     | `ComputeClampedTTL`, `ComputeClampedSigValidity` |
| `v2/ksk_rollover_ds_push.go`                 | 2     | `PushDSRRset`, `ComputeTargetDSSet`  |
| `v2/ksk_rollover_parent_poll.go`             | 3     | `QueryParentDS` + backoff scheduler; DS-match algorithm (§7.5) |
| `v2/ksk_rollover_fsm.go`                     | 4     | Per-method state-transition tables   |
| `v2/ksk_rollover_phase.go`                   | 4     | Zone sub-phase machine (§8.8)        |
| `v2/ksk_rollover_worker.go`                  | 4     | `RolloverTick` + `rollover_due`      |
| `v2/ksk_rollover_atomic.go`                  | 4     | `atomic_rollover(z)`                 |
| `v2/ksk_rollover_earliest.go`                | 4     | `ComputeEarliestRollover`            |
| `v2/ksk_rollover_clamp_trigger.go`           | 4     | `ComputeNextClampBoundary` + ResignQ push |
| `v2/ksk_rollover_import.go`                  | 5     | `ImportKey` + parent-DS probe        |
| `v2/cli/ksk_rollover_cli.go`                 | 1–5   | All CLI subcommands                  |

**Files touched (not rewritten) by this project:**

| File                       | Change                                                    |
| -------------------------- | --------------------------------------------------------- |
| `v2/db_schema.go`          | Add 2 tables to `DefaultTables`; extend state enum        |
| `v2/structs.go`            | Add `mode`, `rollover`, `clamping` subtrees to `DnssecPolicy` |
| `v2/key_state_worker.go`   | One new call: `RolloverTick(conf, kdb)` inside `checkAndTransitionKeys` |
| `v2/parseconfig.go`        | Call `rollover.ParsePolicy` during policy load            |

**CSK mode (§3.6) blast radius.** The CSK/KSK-ZSK choice changes
which key signs which RRset. Every signing path that currently
selects between KSK and ZSK must consult the zone's policy mode.
This is a cross-cutting edit with non-trivial reach:

| File                                  | Likely change for CSK mode                                   |
| ------------------------------------- | ------------------------------------------------------------ |
| `v2/sign.go` (or equivalent)          | `signing_key = active_KSK if mode=csk else active_ZSK` for non-DNSKEY RRsets |
| `v2/zone_sign.go` (zone re-sign path) | Same mode check at RRset iteration                           |
| `v2/keystore.go`                      | `GetActiveSigningKey(zone, rrtype)` helper respecting mode   |
| `v2/key_state_worker.go`              | Maintain-standby-ZSK path skips zones with `mode=csk`        |
| Any ad-hoc caller of `GetActiveZSK`   | Should route through the mode-aware helper                   |

Budget: ~50 additional LOC of edits for CSK. Not a lot, but the
edits are scattered and require careful review. The alternative
— introducing a `SigningKeyFor(rrtype, zone)` abstraction once
and using it everywhere — is cleaner but is a larger refactor
and not strictly required by this project. Recommend the focused
mode-check edit for Phase 1, refactor later if CSK usage grows.

## 15. Resolved Design Decisions

All open questions from earlier drafts are resolved:

1. **`ds-published` is added to the state enum** (§3.4, §9.1). No
   parallel-column alternative.
2. **`rollover_method` is persisted per key** and immutable for
   that key's lifecycle (§3.4, §9.2). Deriving from policy would
   break if policy changes mid-rollover.
3. **`num-ds = 2` is enforced at config parse time** when
   `rollover.method = double-signature` (§5.1.1). Other values
   rejected with an explanatory error.
4. **Clamping applies uniformly to every RRset in the zone** when
   `clamping.enabled: true` (§5.2). No per-type exception list.
   Every RRSIG and every TTL signed/published after
   `clamping.enabled` takes effect is subject to the clamp rule
   `min(configured_ttl, R + margin)`, whether the RRset is DNSKEY,
   NS, A, NSEC, SOA, or anything else.
5. **Emergency "roll now" operator command is `rollover asap`**
   (§8.5, §10.2), which transparently computes the earliest safe
   moment and ramps TTLs/RRSIG validity down toward that moment.
   No separate "emergency accelerate" mechanism.
6. **Operator-generated KSKs during rollover are rejected.** The
   gate is the `rollover_in_progress` flag on `RolloverZoneState`
   (§9.3). The flag is set by `atomic_rollover(z)` (§8.1 step 4)
   and cleared when all retired keys have reached `removed`
   (§8.8 `pending-child-withdraw` → `idle` transition). While the
   flag is TRUE, manual `generate` / `import` commands that would
   add a KSK are rejected with a clear error explaining the
   in-progress rollover. Unlike gating on key states directly (an
   earlier draft), the flag captures the full window from
   `atomic_rollover(z)` through final `retired → removed`
   withdrawal — including the propagation wait between those
   events during which at least one key is in `retired`.
7. **RFC 7583 parameter naming.** This document uses descriptive
   local names for clarity; §3.1.1 provides a cross-reference
   table mapping local names to RFC 7583 parameters.
8. **KeyState EDNS(0) as confirmation channel** is deferred to
   future work (§16). The §7 DS-poll path is the confirmation
   mechanism for this project.

## 16. Future Work (out of scope for this project)

- **KeyState EDNS(0) as confirmation channel.** Once a parent-side
  implementation of draft-berra-dnsop-keystate exists, the §7
  DS-poll path can be short-circuited: the parent actively reports
  publication state rather than the child observing DS records.
  Benefits: precise "DS publication started" timestamp (reducing
  the conservative DS_TTL + margin wait); lower query load on
  parent NS. Integration point: replace `QueryParentDS` in
  `ksk_rollover_parent_poll.go` with `QueryParentKeyState`, keep
  the DS-poll path as a fallback.
- **Algorithm rollover.** Out of scope here. Future work involves
  publishing DNSKEYs under two algorithms concurrently, with two
  DS RRsets at the parent, and sequencing activation/retirement
  across both. Can build on this project's FSM by extending the
  per-key state to include algorithm bookkeeping.
- **Multi-signer / multi-provider coordination.** tdns-mp has its
  own KeyStateWorker and MPDnssecKeyStore; porting this project's
  rollover FSM to that world is non-trivial because key-state
  transitions must be coordinated across providers. Facilitated
  by the code organization in §14 (the rollover-specific files
  should move wholesale).
- **CDS/CDNSKEY signaling (RFC 8078).** An alternative to the DS
  UPDATE push in §6 for parents that prefer to poll. Could be
  added as a second mode alongside the UPDATE-push path.
- **NSEC3 parameter rollover.** Separate state machine, separate
  DS-chain considerations (NSEC3PARAM changes). Out of scope.

## 17. References

- RFC 7583 — DNSSEC Key Rollover Timing Considerations (co-authored
  by Johan Ihren)
- RFC 6781 — DNSSEC Operational Practices, v2
- RFC 8078 — CDS/CDNSKEY (out of scope but adjacent)
- draft-ietf-dnsop-delegation-mgmt-via-ddns-01 — DSYNC + child UPDATE
- draft-berra-dnsop-keystate-02 — KeyState EDNS(0) option
- `tdns/docs/2026-03-07-delegation-sync-refresh-plan.md` — landed
  DSYNC + KeyState refresh
- `tdns/docs/2026-03-14-signal-key-publication.md` — SIG(0) KEY
  publication via combiner (agent-side analogue)
