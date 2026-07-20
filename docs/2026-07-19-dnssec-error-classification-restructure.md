# DNSSEC error classification restructure — the need (document-only)

- **Status:** need captured, NOT a design or plan. Prompted by PR-2 live testing
  (`docs/2026-07-19-transactional-policy-reload-pr2-live-results.md`, D thread) and
  the config-reload guardrail (`docs/2026-07-17-config-reload-policy-guardrail-plan.md` §8).
- **Not scheduled.** This blocks one deferred fix and would sharpen another; it is
  recorded so the dependency is visible, not to commit to a design yet.

## The problem

A zone's error state is a set of slots keyed by **`ErrorType`** (an enum:
`RefreshError`, `DnssecError`, `DnssecPolicyWarning`, `config`, `agent`, …). Set
with `zd.SetError(type, msg)`, cleared with `zd.ClearError(type)` — **one slot per
type, cleared wholesale**.

`DnssecError` in particular is **overloaded**: a single type slot covers distinct,
unrelated causes, each with its own dynamic message. Today's set-sites:

| Site | Cause |
|------|-------|
| `parseconfig.go:794` | zone's `dnssecpolicy` ref is unresolvable at (re)parse |
| `zone_policy_apply.go:355` | intent policy missing/broken → sync-time quarantine |

…plus signing/key-generation failures that will land here as the code grows.

## Why it bites

Because `ClearError` is keyed by **type, not cause**, you cannot clear "the one
`DnssecError` that a particular condition set" without risking clearing a
**different, still-valid** `DnssecError`. Concretely (the D-thread finding):

- A zone quarantined because its policy definition was removed
  (`DnssecError` = "policy X does not exist") does NOT recover when the policy is
  re-added and the config reloaded — the stale error persists (the re-resolve
  success path can't safely clear it), and the refresh engine then skips the zone
  (`refreshengine.go:334`, `HasServiceImpactingError`). Recovery needs a restart.
- The obvious one-liner — `ClearError(DnssecError)` on a successful re-resolve —
  is **unsafe**: a zone could hold a `DnssecError` from the sync-time quarantine
  (or a signing failure) while its ref independently re-resolves, and the blanket
  clear would wipe that unrelated error.

So the reload-recovery fix is **blocked** on being able to clear errors by cause,
not by coarse type.

## What a fix would need to provide (requirements, not a design)

- **Clear by cause, not just by type.** Either split `DnssecError` into
  cause-specific types (e.g. `DnssecPolicyResolutionError`, `DnssecSigningError`,
  `DnssecQuarantineError`), or move to cause-keyed errors
  (`SetError(type, key, msg)` / `ClearError(type, key)`), so a condition can
  set/clear exactly its own error.
- **Preserve the service-impacting classification** (`ErrorTypeIsServiceImpacting`
  / the `refreshengine.go:334` skip) across whatever split is chosen.
- **Keep it presentable** — `zone list -v` / `zone desc` render error state;
  finer types must not fragment the operator view unhelpfully.

## Consumers unblocked / improved

1. **Reload recovery** (the deferred `ClearError` fix) — the blocking dependency.
2. **Reload guardrail diagnostics** (guardrail §3.2) — a per-cause error model
   lets the gate explain precisely what would break.
3. General zone-error hygiene as more DNSSEC failure modes are added.
