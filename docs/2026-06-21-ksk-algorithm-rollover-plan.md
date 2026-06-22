# KSK algorithm rollover via the auto-rollover engine

Status: PLANNING. This is the build plan for a **KSK algorithm
rollover** — changing a zone's KSK signing algorithm (e.g. ED25519 →
MAYO5 for a post-quantum transition) with correct parent-DS coordination.

Estimate at a glance (full breakdown in §10.1): ~160–300 source +
~470–700 test LOC, ~17–29 h across 6 steps. Risk concentrates in two
commits — K-2 (HIGH blast radius: the §2 bogus-zone path) and K-3 (the
one engine-counting change); the rest is LOW-to-MED reuse of the ZSK
step-2 scaffolding. Confidence MEDIUM, pending the K-0 re-confirmation
that the engine is algorithm-blind end-to-end.

It is the sibling of the relaxed-mode ZSK algorithm rollover
(`2026-06-17-algorithm-rollover-evaluation.md` §8, DONE — PR #263). The
ZSK plan's §0–§7 design/rationale already covers the KSK case
conceptually (§1 algorithm-blindness, §2 why the reconcile cannot do it,
§3.3 why it is safe, §4.1 one-role-at-a-time, §4.2 mixed-algorithm CDS).
This document does not restate that rationale — read it there. What
follows is the KSK-specific BUILD plan: the engine wiring, the trigger,
the entry-layer changes, the safety gates, the timing concerns the
parent-DS coupling introduces, and the test matrix.

Cross-references below of the form "(eval §N)" point at
`2026-06-17-algorithm-rollover-evaluation.md`. Code references are
`file:line` into `tdns/v2/`.

This work is EXPERIMENTAL, consistent with the alg-split / PQ-transition
goal. The parent is under our control in the testbed (eval §4.2), so a
mixed-algorithm CDS/DS at the parent is a requirement to satisfy, not an
external constraint.


## 0. The one-sentence summary

A KSK algorithm rollover is a same-algorithm KSK rollover in which the
generator mints the **new** algorithm; the existing parent-DS engine —
already algorithm-blind and multi-algorithm-safe at every step — carries
it, with a **trigger** to start it, an **entry gate** so the reconcile
hands off instead of doing the unsafe synchronous swap (eval §2), and a
**both-role / re-entrancy** refusal set.

The headline finding from the engine survey: **almost nothing in the
engine needs to change.** The DS observe/compare, CDS cleanup, key
selection, FIFO promotion, and DS shrink all carry algorithm in their
identity tuples and already handle a mixed old-alg + new-alg DS set. The
work is the trigger, the entry layer, the gates, and a careful look at
timing — not the DS dance itself.


## 1. Why this is mostly already built (the engine survey)

The KSK rollover engine (`ksk_rollover_*.go`) is a 6-phase parent-aware
state machine (eval §1):

```
idle
  → pending-child-publish      (wait propagation_delay; DNSKEY to secondaries)
  → pending-parent-push        (send DS UPDATE and/or publish CDS + NOTIFY)
  → pending-parent-observe     (POLL parent until DS set matches)
  → idle                       (on confirm: advance keys; shrink old DS)
     | parent-push-softfail    (on timeout: long-term probe + observe)
  → pending-child-withdraw     (hold retired keys for the cache margin)
```

Phase constants: `ksk_rollover_automated.go:15-22`. Orchestrator:
`RolloverAutomatedTick` (`ksk_rollover_automated.go:67`).

What the survey confirmed is already algorithm-blind / multi-alg-safe:

- **Generator** mints with `pol.KSKAlgorithm`, passed straight through —
  `GenerateKskRolloverCreated(…, pol.KSKAlgorithm, …)`
  (`ksk_rollover_automated.go:176` → `ksk_rollover_pipeline.go:13`). This
  is the single flip point, exactly as for the ZSK roll. Change the bound
  policy's KSK algorithm and the next minted key carries it.
- **DS/CDS computation** selects all SEP keys by state with NO algorithm
  filter and `ToDS()`-es each: `loadTargetKSKsForRollover`
  (`ksk_rollover_ds_push.go:83`), `ComputeTargetDSSetForZone`
  (`…:205`), `ComputeTargetCDSSetForZone` (`…:625`). A two-algorithm DS
  set is computed identically to a one-algorithm one.
- **DS observe/match** identifies each DS by the full tuple
  `(KeyTag, Algorithm, DigestType, Digest)` and matches set-wise:
  `ObservedDSSetMatchesExpected` (`ksk_rollover_parent_poll.go:42`),
  `dsCanonical` (`…:19`). A mixed old+new DS set at the parent matches
  when BOTH are present — exactly the overlap-window invariant.
- **CDS cleanup** compares on the same algorithm-bearing tuple:
  `cleanupCdsAfterConfirm` (`ksk_rollover_cds_cleanup.go:45`). Multi-alg
  CDS unpublishes correctly.
- **FIFO promotion** is already ordered oldest-first:
  `listRolloverStandbyKeysTx` orders `published_at ASC, keyid ASC`
  (`ksk_rollover_zone_state.go:~488`); `AtomicRollover` picks the first
  (`ksk_rollover_atomic.go:60`). (Contrast the ZSK path, where the
  unordered query was a real bug we had to fix; the KSK path was already
  correct — do NOT touch it.)
- **DS shrink** falls out of the state machine: once an old-alg key
  reaches `removed`, `loadTargetKSKsForRollover` stops selecting it
  (its state filter excludes `removed`), so the next DS push omits its
  DS; the whole-RRset UPDATE (`BuildChildWholeDSUpdate`,
  `ksk_rollover_ds_push.go:40`) atomically replaces the set.
- **Standby gate** is the safety property the ZSK roll lacked entirely: a
  KSK reaches `standby` (promotable) only after its DS is CONFIRMED at the
  parent (`last_ds_confirmed_*` vs `last_ds_submitted_*`,
  `confirmDSAndAdvanceCreatedKeysTx`,
  `ksk_rollover_automated.go:~631`). This is precisely what makes a KSK
  alg roll safe where the synchronous swap is not (eval §2, §3.3).

Conclusion: the DS dance needs NO algorithm-awareness added. The plan is
trigger + entry-layer + gates + timing audit + tests.


## 2. The four things that must change

Mirroring the ZSK plan's structure, exactly four kinds of change:

1. **A trigger** — an operator command that binds the new KSK algorithm
   to the zone (so future-minted KSKs carry it) and starts the roll. The
   engine already has the manual-trigger plumbing (`asap`); a KSK alg
   roll IS a manual on-demand KSK roll with a changed generator algorithm.
2. **An entry gate (the reconcile hand-off)** — today
   `reconcileActiveKeyAlgorithms` REFUSES any KSK alg mismatch (the
   step-2 safety gate, `sign.go:~310`). The KSK plan replaces that refusal
   with a hand-off: do not retire the old-alg active KSK; let the engine
   carry it (the standby gate guarantees safety). This is the KSK analog
   of D3 in the ZSK plan.
3. **Pipeline counting / DS-target reconciliation across the alg
   transition** — the engine's pipeline-fill is sized to `NumDS + 1` and
   counts by SEP-flag + state, NOT by algorithm
   (`ksk_rollover_automated.go:140-182`). Verify the mixed-alg window does
   not over- or under-fill (see §6).
4. **Safety refusals** — both-role change refused at entry (eval §4.1);
   re-entrancy (a KSK alg roll already in flight) refused; CSK still
   refused (eval §4.5); strict vs relaxed completeness is a NON-issue for
   the KSK (see §3).

Everything else is reuse.


## 3. Completeness mode is (almost) a non-issue for the KSK

The ZSK roll's central tension was completeness (eval §3.2): a ZSK signs
the whole zone, so strict mode demands a maintained whole-zone
double-signature through the drain, which is why relaxed mode exists.

The KSK signs ONLY the apex DNSKEY RRset (eval §3.2.1, §4.1). So even in
STRICT completeness, a KSK alg roll adds at most ONE maintained RRSIG on
ONE RRset — the apex DNSKEY RRset — which is TCP-transported regardless.
The two modes are effectively identical for a KSK roll.

DECISION K1 — **the KSK alg roll runs the same way in both completeness
modes.** Unlike the ZSK roll, it is NOT gated behind `relaxed`. There is
no whole-zone double-signature, no completeness escape hatch needed. The
only KSK-side overlap cost is the extra apex-DNSKEY RRSIG during the
window, which strict completeness wants anyway.

Consequence: the `dnssec.completeness` knob does NOT gate the KSK roll.
The KSK roll proceeds in strict mode (the default), which is the right
default for a KSK alg roll. (If a later refinement wants relaxed-only
behavior for some KSK sub-case, it can branch then; none is known now.)

What DOES differ from the ZSK roll, and is the entire reason the KSK case
is harder, is the **parent-DS coupling**: the new-alg key cannot be
promoted until its DS is confirmed at the parent, and the old-alg DS
cannot be withdrawn until after promotion + the cache margin. That
coupling is already implemented by the standby gate and the
withdraw/margin machinery — the plan's job is to route the alg change
THROUGH it, not around it (the §2 mistake).


## 4. The overlap window, concretely (KSK)

A KSK alg roll walks this sequence (all but the trigger already
implemented):

1. **Bind** the new KSK algorithm (trigger; §5). Future-minted KSKs are
   new-alg.
2. **Mint** a new-alg KSK into `created` (pipeline-fill, when the engine
   would naturally generate the next pipeline key — see §6 on counting).
3. **Publish** its DNSKEY; wait `propagation_delay`
   (pending-child-publish).
4. **Push** the DS — now a MIXED set: old-alg DS (from the active
   old-alg KSK) + new-alg DS (from the created/ds-published new-alg KSK)
   — via UPDATE and/or CDS+NOTIFY (pending-parent-push). The CDS RRset at
   the apex spans both algorithms (eval §4.2).
5. **Observe** the parent until the mixed DS set is confirmed
   (pending-parent-observe). The match is set-wise on
   `(keytag, alg, digesttype, digest)`, so it confirms only when BOTH
   DSes are present.
6. **Promote** the new-alg KSK standby → active; retire the old-alg KSK
   (`AtomicRollover`). Both DNSKEYs stay published; both RRSIGs over the
   apex DNSKEY RRset stay served (additive signer). The parent still
   advertises both DSes → both chains validate.
7. **Withdraw** the old-alg DS: after the retired old-alg key passes the
   cache margin (`effectiveMarginForZone`,
   `ksk_rollover_automated.go:~1637` = `max(clamping.margin,
   max_observed_ttl)`), it goes retired → removed; the next DS push omits
   its DS; the parent now advertises only the new-alg DS
   (pending-child-withdraw → idle).

At no instant is there zero working DS→DNSKEY chain (eval §3.3): before
promotion the old chain is live and the new one is confirmed-and-waiting;
after promotion both are live; after withdrawal only the new one — which
has been live since step 6. A parent DS with no matching active key is
harmless (RFC 6840 §5.9), and a retired key's DNSKEY + RRSIGs outlive
their cached signatures (drain).

This is the multi-DS (double-DS) rollover of RFC 7583, which is exactly
what the engine already implements for the same-algorithm case. The only
difference is that the two DSes differ in algorithm rather than just
keytag.


## 5. The trigger and the bound algorithm

### 5.1 What the trigger does

Modelled on the ZSK roll's `change-policy` (eval §8.3) and the KSK
`asap`:

`auto-rollover policy-change -z <zone> -p <policy>` (the SAME command we
built for ZSK) must learn to handle a KSK-algorithm target. It:

- writes the `ZonePolicyOverride` target + rebinds `zd.DnssecPolicy`
  in-memory (reuse `setZonePolicy`/`SetZonePolicyOverride`,
  `apihandler_zone.go`), so future-minted KSKs carry the new algorithm
  and a restart resumes toward the target;
- does NOT itself retire, mint, or push anything synchronously — it binds
  the future algorithm and lets the engine's normal cadence (or an
  operator `asap`) drive the roll;
- prints the two-command workflow in its output (bind, then
  `auto-rollover asap -z <zone>` — the KSK asap, no `--zsk` — to
  accelerate), the same discoverability requirement we applied to ZSK.

DECISION K2 — **reuse the existing `change-policy` command and add a KSK
branch**, rather than a new command. The command already binds a target
policy and refuses both-role / CSK / re-entrancy for ZSK; the KSK branch
adds KSK-target handling and removes the current KSK refusal.

### 5.2 The throttle

The KSK `asap` (`auto-rollover asap -z <zone>`, no `--zsk`) is the
throttle, identical in spirit to the ZSK case but **bounded by the
parent-DS clock**: each `asap` brings the roll forward, but the new-alg
key still cannot promote until its DS is CONFIRMED at the parent. So
unlike the ZSK roll — where successive `asap`s run back-to-back because
standbys are already propagated — KSK `asap` cannot outrun the parent
confirmation + cache margin. `asap` removes the lifetime wait; it does NOT
remove the DS-at-parent wait (and must not — that wait is the safety
gate). This is correct and intended; document it for operators.

### 5.3 "Roll in progress" predicate (KSK)

The ZSK roll derived "in progress" from key state (D4) and used a fuller
drain-window predicate for the re-entrancy guard (eval §8.3). The KSK has
a stronger, already-persisted signal: `RolloverZoneState.
rollover_in_progress` (set by `AtomicRollover`,
`ksk_rollover_atomic.go:~129`) plus `rollover_phase != idle`. Combine
that with the key-state predicate (an active KSK whose algorithm ≠ the
bound policy KSK algorithm, OR any KSK of a non-target algorithm in
ds-published/standby/active/retired) for the fuller drain-window notion.

DECISION K3 — the KSK re-entrancy guard uses
`rollover_in_progress == true` OR `rollover_phase != idle` OR the
key-state drain predicate. Any of those true ⇒ refuse a second
`change-policy`. This is stricter than the ZSK case (which had no
engine-phase signal) and catches a roll mid-DS-dance, not just
mid-drain.


## 6. Pipeline counting across the algorithm transition (the one real risk)

This is the KSK analog of the ZSK roll's role-only-counting concern (D5),
and the only place the engine's existing counting could misbehave.

Today (`ksk_rollover_automated.go:140-182`):

- `maxPipeline = pol.Rollover.NumDS + 1`.
- `CountKskInPipeline(zone)` counts all non-terminal SEP keys
  (created/ds-published/published/standby/active/retired) — NOT by
  algorithm.
- `CountKskWithDSAtParent(zone)` counts SEP keys whose DS is expected at
  the parent — NOT by algorithm.
- The loop mints (with `pol.KSKAlgorithm`) while below both targets.

Because the counts are already algorithm-blind, the inversion that bit
the ZSK roll (per-alg counting → eager over-generation) does NOT happen
here: N old-alg pipeline KSKs already satisfy the count, so binding a new
algorithm does NOT trigger eager minting. Good — that is the behavior we
want, and it is already the behavior.

BUT there are two things to verify and likely handle:

- **K6a — the alg roll needs the new-alg key to actually get minted.**
  With `NumDS = 1` (the common case) and one active old-alg KSK, the
  pipeline is "full" (1 of 1 with DS at parent), so the loop mints
  nothing — and the roll never starts. The ZSK roll solved the analog by
  letting a manual `asap` promote through the FIFO; but the KSK has no
  spare standby to promote, because nothing was minted. RESOLUTION: the
  trigger (or the `asap` for a bound-but-different-algorithm zone) must
  force one new-alg key into the pipeline ABOVE the steady-state count —
  i.e. allow a transient `NumDS + 1`-with-DS overlap during an alg roll.
  Concretely: when an alg roll is in progress (the K3 predicate),
  `CountKskWithDSAtParent`'s target becomes `NumDS + 1` (room for the
  new-alg key alongside the draining old-alg one) until the old-alg key is
  removed. Audit the exact counting site and add the alg-roll-aware bump;
  it must be ONE shared definition (mint target and pipeline cap agree, or
  they oscillate — the ZSK lesson).

- **K6b — the bound algorithm must be the one minted.** Confirm the
  pipeline-fill reads `zd.DnssecPolicy.KSKAlgorithm` from the rebound
  policy (it does — `pol.KSKAlgorithm` at the mint site), so after
  `change-policy` rebinds, the minted key is new-alg. No change expected;
  verify with a test.

This §6 work is the riskiest commit and needs a testbed checkpoint, the
same way E1.b did in the transport redesign. It is the KSK plan's
equivalent of the ZSK role-only-count + cap.


## 7. The entry gate: reconcile hand-off (replacing the step-2 refusal)

Today `reconcileActiveKeyAlgorithms` (`sign.go:~310`) REFUSES any active
KSK whose algorithm ≠ policy with "KSK algorithm rollover not implemented
… route via the auto-rollover engine — not yet built." That refusal was
the step-2 safety gate. The KSK plan turns it into a hand-off.

DECISION K4 — in `reconcileActiveKeyAlgorithms`, a KSK algorithm mismatch
no longer refuses and no longer retires; it returns WITHOUT acting on the
KSK (a no-op for that key), exactly like the relaxed-ZSK branch — because
the engine owns KSK state transitions (eval §3.5) and the standby gate
makes the gradual roll safe. The synchronous retire (the §2 bogus-zone
path) stays gated off forever; the engine is the only actor that moves a
KSK from active → retired during an alg change.

Critically, this hand-off MUST be paired with the trigger + override
write landing together (eval §3.4): writing the override without gating
the synchronous reconcile gives the unsafe swap; gating the reconcile
without writing the override gives a roll that reverts on restart. These
three land in one commit.

Note the asymmetry with ZSK: the ZSK reconcile hand-off was the WHOLE
mechanism (the FIFO + standby maintainer did the rest). For the KSK, the
hand-off just gets the reconcile out of the way; the ENGINE (already
built) does the parent-DS work. So K4 is a small change — delete the
refusal, return no-op on KSK mismatch — but it is a SAFETY-critical one:
get the branch wrong and the §2 path runs.


## 8. Safety refusals (gates, not scope notes)

As with the ZSK roll, these are correctness gates — a wrong branch
reintroduces the bogus-zone path.

- **Both-role target** (KSK alg AND ZSK alg both differ) → REFUSE at the
  entry layer, BEFORE any override write (eval §4.1, ZSK §8.3 already
  implements this guard; the KSK branch reuses it). One role per roll.
- **CSK alg change** → REFUSE at the entry layer (eval §4.5). The
  reconcile early-returns on CSK, so the guard lives in
  `change-policy`/`set-policy`. (Already implemented for the ZSK step;
  unchanged.)
- **Re-entrancy** (a KSK alg roll already in flight, K3 predicate) →
  REFUSE a second `change-policy` with "a KSK algorithm rollover is
  already in progress … wait or cancel." Operator uses KSK `cancel` then
  re-issues to change course.
- **ZSK-mode interactions** — a `change-policy` whose target changes ONLY
  the KSK algorithm proceeds as a KSK roll; one that changes ONLY the ZSK
  algorithm proceeds as the existing relaxed-ZSK roll; both ⇒ refused
  (above). The entry layer dispatches on which role's algorithm differs.
- **No-DSYNC parent** — if the parent advertises no usable DSYNC scheme,
  the engine already enters `child-config:waiting-for-parent` softfail
  (indefinite, never hardfails, `ksk_rollover_schemes.go`). A KSK alg roll
  triggered against such a parent will correctly stall in that state
  rather than bogus the zone. This is existing behavior; document it as
  the KSK alg roll's "blocked, safely" mode. Consider whether
  `change-policy` should WARN at bind time if the parent advertises no
  scheme (cheap, optional — the roll would otherwise silently sit in
  softfail).


## 9. Timing audit (the parent-DS coupling)

The agents flagged several timing/assumption points. Most are already
correct; this section is the audit checklist, not a list of known bugs.

- **K9a — DS digest is hardcoded SHA-256** (`ToDS(uint8(dns.SHA256))` at
  `ksk_rollover_ds_push.go:165,189,220,640`, cleanup `…:150-151`). For
  the algorithms in scope (ED25519, MAYO5, etc.), SHA-256 is the correct
  and sufficient DS digest. The alg roll changes the DNSKEY ALGORITHM, not
  the DS DIGEST type, so a single SHA-256 digest per key is fine for both
  old and new alg. NO change needed; note it explicitly so a future
  reviewer does not "fix" a non-bug. (A separate future concern is
  multiple digest types per DS, unrelated to this roll.)

- **K9b — `pending-child-publish` propagation_delay** is a single
  zone-wide `kasp.propagation_delay` (`ksk_rollover_automated.go:~265`).
  Both old and new alg DNSKEYs propagate as one RRset (the apex DNSKEY
  RRset), so a single delay is correct. NO change.

- **K9c — `ds-published → published` timing** uses
  `min(pol.TTLS.DNSKEY, pol.TTLS.MaxServed)` or observed max TTL
  (`TransitionRolloverKskDsPublishedToPublished`,
  `ksk_rollover_automated.go:~960`). The DNSKEY RRset TTL is shared by
  both algorithms' DNSKEYs (same RRset), so the single value is correct.
  NO change.

- **K9d — retired→removed margin** is `max(clamping.margin,
  max_observed_ttl)` (`effectiveMarginForZone`,
  `ksk_rollover_automated.go:~1637`). `max_observed_ttl` is the longest
  RRSIG TTL the zone served; during the overlap the old-alg apex-DNSKEY
  RRSIG is part of that, so the margin already covers the old-alg
  signature's cache lifetime. VERIFY that `max_observed_ttl` is recorded
  for the apex DNSKEY RRSIG specifically (it should be — it is a normal
  served RRSIG). Likely no change; add a test asserting the old-alg key is
  not removed before the margin.

- **K9e — large new-alg KSK (PQ).** A MAYO5/SNOVA KSK DNSKEY is large;
  the apex DNSKEY RRset during the overlap holds old-alg + new-alg
  DNSKEYs + their RRSIGs and the CDS spans both. This RRset goes over TCP
  regardless (eval §3.2.1), and `dnssec.large_algorithms` already drives
  the IMR transport decision (`large_ksk.go`). VERIFY the overlap-window
  apex DNSKEY/CDS RRset transports correctly when one algorithm is large
  (it should — this is the alg-split steady state the large-alg work
  targets). This is a testbed-observation item, not a code change.

- **K9f — `ComputeEarliestRollover` for the KSK asap** already accounts
  for the parent-DS gates (the asap path refuses Case-1/PolicyBlocked,
  `apihandler_rollover.go:140`). Confirm it does not assume single
  algorithm anywhere; the survey found no such assumption.


## 10. Build order

Each step builds + `go test -race` green before the next; show diff +
update this doc's status before committing each (project rule). Testbed
validation is operator-gated, but §6 (K6a) and the §7 hand-off MUST get
a testbed checkpoint — they are the bogus-zone-adjacent commits.

- **Step K-0 — pre-flight (no code).** Re-read this plan against current
  code; the engine may have shifted line numbers. Re-confirm the survey
  claims (algorithm-blind DS dance, FIFO already ordered,
  `rollover_in_progress` semantics). Write down any drift.
  → **Risk LOW · ~0 src / ~0 test LOC · ~1 h.** Pure reading; the value is
  catching engine drift before the risky commits.

- **Step K-1 — entry-layer dispatch + KSK refusals.** Extend
  `change-policy` to detect a KSK-only algorithm target and (for now)
  still refuse with "not yet implemented," BUT add the both-role and KSK
  re-entrancy (K3) guards and the dispatch skeleton. This lands the
  guards without yet enabling the roll — a safe intermediate, testable in
  isolation. Verify: KT2c (both-role), KT2d (re-entrancy), KT2b (CSK
  still refused).
  → **Risk LOW–MED · ~50–90 src / ~80–120 test LOC · ~3–5 h.** Mostly
  reuse of the ZSK `change-policy` guard scaffolding; the new piece is the
  K3 KSK re-entrancy predicate (read `rollover_in_progress` /
  `rollover_phase` + key-state) and the role-dispatch. MED only because
  the dispatch must correctly separate KSK-only / ZSK-only / both-role.

- **Step K-2 — the reconcile hand-off (K4) + override write, together.**
  Replace the KSK refusal in `reconcileActiveKeyAlgorithms` with a no-op
  on KSK mismatch; wire `change-policy`'s KSK branch to write the override
  + rebind (reusing the ZSK path). After this step a `change-policy` to a
  new KSK algorithm binds the future algorithm and does NOT synchronously
  retire — but the roll only advances on cadence/asap (next step makes it
  actually mint). RISKIEST commit (§2 path is one branch away). Testbed
  checkpoint. Verify: KT1 (reconcile no-op on KSK mismatch), KT9 (reload
  mid-roll does not retire).
  → **Risk HIGH · ~30–60 src / ~80–120 test LOC · ~3–5 h.** Small code
  (delete the refusal, return no-op on KSK mismatch; wire the override
  write — both reuse the ZSK pattern), but SAFETY-CRITICAL: a wrong branch
  reinstates the §2 bogus-zone synchronous swap. HIGH is about blast
  radius, not line count. Disproportionate test + review effort; mandatory
  testbed checkpoint before proceeding.

- **Step K-3 — pipeline-fill alg-roll bump (K6a).** Make the pipeline
  mint the new-alg key during an alg roll (transient `NumDS + 1`
  DS-at-parent overlap), sharing one count between mint-target and cap.
  Testbed checkpoint. Verify: KT3 (new-alg key minted on bind), KT3b
  (minted key is new-alg), KT4 (no over-mint; old-alg pipeline keys
  untouched).
  → **Risk MED–HIGH · ~40–80 src / ~120–180 test LOC · ~4–7 h.** The one
  genuine engine change (the rest of the plan routes AROUND the engine;
  this reaches INTO the pipeline-fill counting). Must touch
  `CountKskWithDSAtParent` / the mint loop so mint-target and cap share
  ONE alg-roll-aware count (the ZSK oscillation lesson). Heaviest test
  burden after K-5 — counting edge cases (NumDS=1 vs >1, mid-drain
  overlap). Testbed checkpoint mandatory.

- **Step K-4 — trigger UX + status.** `change-policy` KSK branch prints
  the two-command workflow; `auto-rollover status` shows the KSK
  alg-transition in the zone-global header (reuse the ZSK
  `AlgTransition` field + the shared in-flight predicate, generalized to
  KSK). The KSK `when`/`asap`/`cancel` already exist (they are the
  same-alg KSK commands); confirm they read sensibly mid-alg-roll.
  Verify: KT5 (status shows transition), KT-when (when reflects the
  pending KSK roll).
  → **Risk LOW · ~40–70 src / ~40–60 test LOC · ~2–4 h.** Cosmetic /
  operator-facing; reuses the ZSK `AlgTransition` field and the
  zone-global status header verbatim, generalized to KSK. `when`/`asap`/
  `cancel` already exist, so this is mostly the status line + help text +
  generalizing the in-flight predicate to either role.

- **Step K-5 — full-sequence + timing tests.** The end-to-end overlap
  sequence (§4) under fake time / driven engine, plus the K9d margin
  assertion and the K6a no-zero-chain invariant. Verify: KT6 (full
  sequence), KT7 (margin hold), KT8 (mixed-alg DS confirm).
  → **Risk LOW (test-only) · ~0 src / ~150–220 test LOC · ~4–7 h.** No
  production code (any code change discovered here loops back to the
  relevant step). The full-sequence test (KT6) is the most involved — it
  needs the parent-DS observe seam the same-alg KSK tests already use
  (injected observed DS set). Time goes into driving the engine through
  all six phases with a mixed-alg DS set, not into writing logic.


### 10.1 Effort summary

| Step | What | Risk | Src LOC | Test LOC | Time |
|------|------|------|---------|----------|------|
| K-0 | Pre-flight re-read | LOW | 0 | 0 | ~1 h |
| K-1 | Entry dispatch + KSK refusals | LOW–MED | 50–90 | 80–120 | 3–5 h |
| K-2 | Reconcile hand-off + override | **HIGH** | 30–60 | 80–120 | 3–5 h |
| K-3 | Pipeline-fill alg-roll bump | MED–HIGH | 40–80 | 120–180 | 4–7 h |
| K-4 | Trigger UX + status | LOW | 40–70 | 40–60 | 2–4 h |
| K-5 | Full-sequence + timing tests | LOW (test) | 0 | 150–220 | 4–7 h |
| **Total** | | | **~160–300** | **~470–700** | **~17–29 h** |

Calibration: the ZSK step 2 (PR #263), which built the scaffolding this
plan reuses, landed at ~310 source + ~470 test LOC. The KSK work is
SMALLER in production code (it routes through an already-built engine
rather than building one) but LARGER in tests (the parent-DS full-sequence
case KT6 is heavier than any ZSK test). Net source LOC is lower because
K-2's hand-off is a deletion-plus-no-op, not new mechanism.

**Where the risk concentrates:** two commits, K-2 and K-3, carry nearly
all of it. K-2 is HIGH on blast radius (the §2 bogus-zone path is one
wrong branch away) despite being small; K-3 is the only commit that
reaches into the engine's counting. Everything else (K-0, K-1, K-4, K-5)
is LOW-to-MED and largely reuse. Budget the review/testbed effort
accordingly: most of the human attention belongs on K-2 and K-3, not
spread evenly.

**Sequencing risk:** K-2 and K-3 must NOT be combined into one commit —
K-2 (hand-off, no minting) is independently testable and gives a clean
testbed checkpoint where the zone binds-but-does-not-roll; folding K-3's
minting in would make a bisect of a bogus-zone regression ambiguous
between "hand-off wrong" and "counting wrong."

**Confidence:** MEDIUM. The estimates assume the survey's central claim
holds — that the engine is genuinely algorithm-blind end-to-end and needs
no DS-dance changes. K-0 exists to confirm that before the risky commits.
If K-0 surfaces an algorithm assumption in the DS push/observe path that
the survey missed, K-3 (and possibly a new step) grows materially; treat
the upper bounds as the planning figure, not the lower.


## 11. Test matrix

Model on `zsk_alg_rollover_test.go` + `sign_reconcile_test.go` and the
existing KSK engine tests. Drive the engine / fake time where a sequence
is needed; for the parent-DS observe step, use the existing test seam the
same-alg KSK tests use (a fake parent DS response / injected observed
set).

- **KT1** — reconcile with active KSK alg ≠ policy: does NOT retire the
  active KSK and does NOT refuse (the §2 path stays gated off, the engine
  carries it). Both completeness modes (K1: identical).
- **KT2b** — a CSK algorithm change is refused at the entry layer
  ("not implemented"); no key churn.
- **KT2c** — a both-role target (KSK alg AND ZSK alg differ) is rejected
  at entry BEFORE any override write (eval §4.1).
- **KT2d** — RE-ENTRANCY: a second `change-policy` while a KSK alg roll is
  in flight is refused; cover (i) mid-DS-dance (`rollover_in_progress` /
  `rollover_phase != idle`) and (ii) drain window (old-alg KSK still
  retired). Uses the K3 predicate.
- **KT3** — on `change-policy` to a new KSK algorithm, the pipeline mints
  exactly ONE new-alg KSK (the alg-roll bump, K6a) and the old-alg active
  KSK is untouched (no synchronous retire).
- **KT3b** — the minted key carries the NEW algorithm (K6b).
- **KT4** — no over-mint: with the new-alg key minted, the pipeline does
  not mint further old- or new-alg keys; the steady-state `NumDS + 1`
  overlap cap holds. Mint-target and cap agree (no oscillation).
- **KT5** — `auto-rollover status` shows the KSK alg transition in the
  zone-global header (from/to alg + progress), derived from the shared
  in-flight predicate.
- **KT6** — FULL SEQUENCE (§4): bind → mint new-alg → DNSKEY publish →
  mixed DS push → parent confirms BOTH DSes → promote new-alg / retire
  old-alg → old-alg passes margin → removed → DS shrinks to new-alg only.
  Assert: at no step zero working DS→DNSKEY chains; FIFO promotion; the
  parent DS set is mixed during the window and single-alg after.
- **KT7** — MARGIN HOLD (K9d): the retired old-alg KSK is NOT removed
  (and its DS not withdrawn) before `max(clamping.margin,
  max_observed_ttl)` elapses from its `retired_at`.
- **KT8** — MIXED-ALG DS CONFIRM: `ObservedDSSetMatchesExpected` confirms
  only when BOTH old-alg and new-alg DSes are present at the parent;
  old-alg-only or new-alg-only does NOT confirm. (Likely a direct unit
  test of the matcher with a two-algorithm expected set.)
- **KT9** — RELOAD MID-ROLL: a `zone reload` (re-parse + resign) while
  the old-alg KSK is still active does NOT retire it (the K4 hand-off
  holds through reload; the §2 path stays off).
- **KT-when** — `auto-rollover when` (KSK) reflects the pending alg roll
  sensibly; `asap` (KSK) brings it forward but cannot outrun the
  parent-DS confirm + margin (K2 throttle bound).


## 12. Explicitly out of scope for this plan

- **ZSK algorithm rollover** — DONE (eval §8 / PR #263). Untouched here
  except the shared `change-policy` dispatch and status header.
- **CSK algorithm rollover** — still refused (eval §4.5). A CSK is a
  parent-coupled roll like the KSK; supporting it is later work that can
  reuse most of this plan.
- **Both-role (KSK+ZSK) in one window** — refused (eval §4.1). The
  operator runs two rolls in sequence.
- **New DS digest types per key** (K9a) — the roll changes the DNSKEY
  algorithm, not the DS digest; multiple digest types is a separate
  concern.
- **Large-zone secondary-propagation observation** for the ZSK switch
  (eval §6 item 5) — not a KSK concern (the KSK touches only the apex
  DNSKEY RRset).


## 13. Open questions for the operator

These are genuine decisions the operator should weigh before Step K-2/K-3
(flagged here rather than guessed):

1. **K6a overlap target.** During an alg roll, is a transient
   `NumDS + 1`-with-DS-at-parent overlap acceptable (old-alg DS + new-alg
   DS both present, briefly `NumDS + 1` of them), or should the steady
   `NumDS` cap be held by withdrawing the old-alg DS BEFORE the new-alg
   key is fully promoted? The plan assumes the former (the safe,
   standard multi-DS overlap — both chains live through the window). The
   latter would shrink the window but risks a moment with a single chain.
   Recommendation: the former (overlap), consistent with RFC 7583
   multi-DS and the same-alg engine behavior.

2. **`change-policy` warn on no-DSYNC parent (§8).** Should
   `change-policy` to a new KSK algorithm WARN (or refuse) at bind time
   if the parent currently advertises no usable DSYNC scheme, since the
   roll would otherwise sit silently in `child-config:waiting-for-parent`
   softfail? Recommendation: WARN, do not refuse (the parent may start
   advertising; refusing is too strict).

3. **KSK alg roll under `set-policy` (not just `change-policy`).** For the
   ZSK, D3 made `set-policy` on an alg change ALSO gradual (the relaxed
   reconcile no-ops the swap). For the KSK, the K4 hand-off has the same
   consequence: `set-policy` to a new KSK algorithm would also become a
   gradual engine-driven roll rather than the synchronous swap. This is
   correct (the synchronous swap is the §2 bug), but confirm the operator
   wants `set-policy` and `change-policy` to behave identically for a KSK
   alg change (the ZSK precedent says yes).


## 14. Summary

- The parent-DS KSK rollover engine is ALREADY algorithm-blind and
  multi-algorithm-safe at every step that matters: DS/CDS computation,
  parent observe/match, CDS cleanup, FIFO promotion, DS shrink, and the
  standby gate. A KSK alg roll is a same-alg roll with a new generator
  algorithm.
- Completeness mode is a non-issue for the KSK (K1): the KSK signs only
  the apex DNSKEY RRset, so strict and relaxed are effectively identical;
  the roll runs in both, not gated behind `relaxed`.
- The work is four things: a TRIGGER (reuse `change-policy` + KSK
  `asap`), an ENTRY GATE (turn the step-2 KSK refusal into a hand-off,
  K4 — the riskiest, §2-adjacent commit), PIPELINE COUNTING across the
  transition (K6a, mint the new-alg key into a transient overlap), and
  SAFETY REFUSALS (both-role, re-entrancy via the engine's
  `rollover_in_progress` signal, CSK).
- The throttle (`asap`) is bounded by the parent-DS clock — it cannot
  outrun confirmation + cache margin, and must not (that wait is the
  safety gate).
- Timing is mostly already correct (§9); the audit items (digest,
  margins, large-alg transport) are verifications, not known bugs.
- Build incrementally (§10) with testbed checkpoints on K-2 and K-3; the
  test matrix (§11) mirrors the ZSK matrix plus the KSK-specific
  mixed-DS-confirm, margin-hold, and full-sequence cases.
