# Transactional DNSSEC policy-reload — decisions & motivations

Companion to `2026-07-15-transactional-policy-reload-plan.md`. The plan records
the *what*; this file records the *why* for the design decisions taken while
implementing **PR-1** and the review + testbed round on top of it, so the
motivation survives independently of the plan. PR references are to
[johanix/tdns#288](https://github.com/johanix/tdns/pull/288).

Each entry is **Decision** + **Motivation** (+ where it lives). This is a log,
not a spec — when a decision changes, add a dated entry rather than rewriting.

---

## Foundational — Phase-0 design locks

These gate the whole design and are stated in the plan (§5.1/§6.2); repeated
here because everything below depends on them.

- **① Classification is always applied (from DB) vs intent — never the current
  in-memory binding.**
  *Motivation:* on restart the binding is freshly loaded from config and equals
  intent, so comparing the binding to intent returns "no change" and silently
  misses a YAML edit. Comparing the *last-applied* record (persisted) to intent
  detects it. `classifyPolicyChange` is therefore structurally unable to take
  `zd.DnssecPolicy` as the "old" side.

- **② Applied-missing → backfill `applied = intent` WITHOUT a forced re-sign**
  when the zone is already signed under intent.
  *Motivation:* the first reload after upgrade must not re-sign every
  already-correct config-only zone (thundering herd). The backfill branch is
  reachable independently of `intent == applied`.

---

## PR-1 decisions

### D1 — No `BenignInternals` classifier class (plan Finding A)
**Decision:** the classifier has three classes — `None`, `CompatibleName`,
`IncompatibleAlg`. Same name + same effective algorithms → `None` (this includes
internals-only edits: lifetimes/sigvalidity/ttls/rollover). Persist the policy
**name only**, no fingerprint.
**Motivation:** `resolvePolicyPair` resolves BOTH the applied and intent structs
from the *same* `ConfLive()` snapshot *by name*, so a "same name, changed
internals" delta is unreachable at classify time — both sides are the identical
struct. Internals edits converge via the resigner on the normal cadence, so a
separate class would be dead weight. (Removed the earlier `BenignInternals`
value + its `suppressLoadWarnings`-normalized struct compare.)

### D2 — Per-zone apply serialization via a dedicated `policyApplyMu`
**Decision:** add `ZoneData.policyApplyMu` (distinct from `zd.mu`). The apply
core acquires it as the OUTERMOST lock across rebind → re-sign → persist →
revert. `applyZonePolicyTransactional` locks it and delegates to
`applyZonePolicyTransactionalLocked`; `policy-reset` holds the mutex itself
across its clear + re-sign and calls the `…Locked` variant.
**Motivation:** two concurrent applies on one zone could interleave, and a
failed revert could clobber a newer successful binding. The apply cannot hold
`zd.mu` across the sign because `SignZone` takes `zd.mu` internally — and a lock
held *across* `SignZone` is the shape that previously self-deadlocked here
(`zd.mu` released before `SignZone`, so `policyApplyMu` as an outer lock has no
ordering inversion). Chose **core-locks + locked-variant** over caller-held so
the common CLI callers can't forget to lock, while `policy-reset` (which must
serialize clear+apply as one unit) avoids a double-lock.

### D3 — policy-reset clears persisted records only AFTER a successful re-sign
**Decision:** order is rebind config → drop+regen keys (`clear`) → refresh key
cache → `applyZonePolicyTransactionalLocked(source=config)` (writes
`applied=config`) → clear the CLI override **last**. `applied` is never
pre-cleared. On a `clear` failure, the in-memory rebind is reverted (its tx
rolled back, original keys intact). Failure messages: post-key-regen → "run
`resign`" (keys already correct); pre-regen → "re-run `policy-reset`".
**Motivation:** the original order cleared the override + applied records and
dropped keys *before* the fallible re-sign, so a re-sign failure left the zone
unsigned (SERVFAIL) with its records already gone. Pre-clearing `applied` is
specifically avoided because, on a failed re-sign, a restart would then see
"applied missing" and the ② backfill would record `applied=config` on an
*unsigned* zone — reopening the same SERVFAIL window. Letting the successful
apply write `applied=config` keeps the record honest.

### D4 — policy-reset stale active-key-cache fix
**Decision:** `resetZonePolicy` calls `zd.refreshActiveDnssecKeys` after `clear`
and before the re-sign; additionally `DnssecKeyMgmt` re-invalidates the zone's
`KeystoreDnskeyCache` entries POST-COMMIT for the `clear` subcommand.
**Motivation:** the keystore `clear` runs DELETE + regen in one transaction and
invalidates the cache mid-tx (before commit). A `GetDnssecKeys` during that
uncommitted window (separate DB connection) re-caches the OLD key set, so the
in-line re-sign then read stale keys and refused on an algorithm mismatch
(ED25519 → MAYO5), leaving the zone SERVFAIL until a manual `resign` — the
testbed failure that triggered this round. The post-commit invalidation closes
the latent bug for the plain `keystore dnssec clear` path too.

### D5 — `ClearZonePolicyOverride` clears the override only (UPDATE, not DELETE)
**Decision:** `UPDATE ZonePolicyOverride SET policy='', set_at=NULL WHERE
zone=?` instead of deleting the row.
**Motivation:** the override (`policy`/`set_at`, intent) and the last-applied
record (`applied_*`) share one row but are independent (a config-only zone can
carry `applied_*` with no override). A full-row DELETE wiped `applied_*` too,
contradicting that independence. An empty `policy` already reads as "no
override".

### D6 — `ctx` threaded at the signature, inert at the leaf
**Decision:** `applyZonePolicyTransactional` and its callers take
`context.Context` as the first parameter (fed `r.Context()` from the API
handler), but it is currently unused past the signature.
**Motivation:** house convention + consistency with `resetZonePolicy` (which
threads `ctx` into `DnssecKeyMgmt`). The leaf `SignZone(kdb, force)` and the
applied-policy DB writes are not ctx-aware anywhere in the tree, so full
threading is a separate `SignZone`-ctx change; the parameter is carried now so
that change is drop-in later.

### D7 — policy-reset is surgical (per-role key handling)
**Decision:** policy-reset forces the zone's active key set to match the config
policy's algorithms **per role** — keep any key whose algorithm is already
correct, drop+regenerate only the role(s) whose algorithm changed
(`zoneActiveKeyRoleChanges` → `forceZoneKeysToPolicyRoles`). A ZSK-only change
keeps the KSK, so the parent DS stays intact; the DS-break warning fires only
when the KSK algorithm changed. A role is "changed" if it lacks a right-alg
active key or carries a wrong-alg one (missing role or mid-rollover mix →
changed, drop all of that role's keys across every state + regen one). A
split↔CSK **mode change** is handled conservatively as a full reset with the DS
warning (chosen over trying to keep a former-CSK key as a KSK, whose mixed
signer semantics aren't worth the risk in a break-glass tool). The no-op case
(both roles already correct) still re-signs additively + records applied=config.
The force op strips not only the dropped keys' orphaned RRSIGs but **every
DNSKEY-covering RRSIG** — on a ZSK-only flip the DNSKEY RRset changed, so the
kept KSK's DNSKEY RRSIG covers a stale key set (not an orphan; additive re-sign
won't remove it) — letting the re-sign regenerate exactly one fresh RRSIG per
active KSK.
**Motivation:** the original unconditional drop+regenerate-all rolled the KSK
even for a ZSK-only change → new KSK keytag → the parent DS went stale and the
chain of trust broke for nothing (confirmed on hardware: MAYO5+MAYO2 →
MAYO5+MAYO1 dropped the MAYO5 KSK). Surgical per-role handling is the correct
abrupt hard-flip counterpart to change-policy's gradual roll, and because it
pre-aligns keys before re-signing it works in strict completeness mode
(reconcile has nothing to refuse). **Side effect:** removed the clear-only
post-commit cache invalidation from `f81defa` — it was dead for the plain
`keystore dnssec clear` CLI path (external tx, so the localtx-gated invalidation
never fired) and is now unused by policy-reset, which uses
`forceZoneKeysToPolicyRoles` with its own complete post-commit invalidation. The
general keystore-cache-invalidation hardening (all subcommands / external txs)
remains a separate follow-up (G3).

---

## Deferred to PR-2 (gates)

### G1 — Backfill "actually signed" predicate (plan §5.5) — MUST close before backfill goes live
**Decision:** PR-1 ships `backfillAppliedIfEligible` with a **keystore-only**
predicate (active keys match intent's algorithms). Strengthening it to also
require the zone to actually SERVE a signature by an active intent-algorithm key
is deferred to PR-2. The exact recipe and the constraint are captured in the
function's `⚠ PR-2 GATE` doc-comment.
**Motivation:** algorithm-matched keys are necessary but not sufficient — a zone
can hold the right active keys yet be unsigned (fresh keygen with no sign; a
secondary whose stored RRSIGs are absent/stale). But the served-RRSIG check
reads zone data (`zd.GetRRset` → needs `zd.Ready` + a populated snapshot), which
couples it to the (PR-2) refresh-engine call site: that call MUST run *after* the
zone snapshot is Ready, NOT the pre-`initialLoadZone` placement §5.5 line 516
floats for a keystore-only predicate. Landing the stricter predicate now, in
isolation, would be either untestable (needs a signed-snapshot fixture) or a
trap — it fails closed when the snapshot isn't ready, forcing a re-sign of every
config-only zone and defeating blocking-②. Safe to defer because backfill has no
production caller in PR-1 (unit tests only).

### G2 — Refresh-engine wiring (the rest of the plan)
**Decision:** the three refresh-engine sites (reload / restart-first-bind /
dynamic) are wired through `resolvePolicyPair → backfill → classify →
apply/refuse` in PR-2, which also removes `applyReloadedPolicyLocked`, adds the
in-flight-ZSK-roll and §5.6 deleted-policy fallback branches, and retargets
`reload_policy_alg_guard_test.go` to applied-vs-intent.
**Motivation:** PR-1 is the foundation (persistence + transactional core + CLI
routing + escape hatch); wiring it into the live reload/restart paths is the
behavioural change and carries the §9 live-matrix merge gate — kept separate so
each PR is reviewable and independently testable.

### G3 — Generic keystore cache-invalidation hardening (CodeRabbit) — follow-up
**Decision:** the keystore's `DnssecKeyMgmt` cache invalidations are per-subcommand
and mid-transaction; several are unlocked map mutations, and the pattern is
vulnerable to the same uncommitted-window re-cache race across `add` / `generate`
/ `setstate` / `delete`, and skips post-commit invalidation entirely for
caller-supplied (external) transactions. Generalizing this — a single locked,
post-commit invalidation hook that also works with external txs — is a deliberate
refactor of shared DNSSEC-keystore code, deferred to its own pass.
**Motivation:** these are pre-existing issues (PR-1 only touched the policy-reset
path); a broad keystore-cache refactor doesn't belong in a policy-reload PR and
carries real regression risk on the key store. D4/D7 fixed the one observed
(policy-reset) path completely via the explicit `refreshActiveDnssecKeys` + the
force op's own complete post-commit invalidation.
