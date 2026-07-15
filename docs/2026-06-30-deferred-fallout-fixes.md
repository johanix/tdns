# Deferred fallout fixes — replication / TSIG stack (started 2026-06-30)

Tracking list of fixes identified during the pre-merge **features-off regression review**
(see [breaking-changes & migration](./2026-06-30-breaking-changes-and-migration.md) and
[full-project eval](./2026-06-29-first-class-tsig-keystore-plan-eval.md)) that are
**deliberately deferred** rather than fixed now. Each entry is written to be actionable
cold. Add to this list whenever a fix is deferred; check items off (or move to a "Done"
section) as they land.

---

## Deferred

### D1 — Hostname-primary resolution: make it runtime + retried (medium scope; only affects hostname primaries)

**Problem.** A primary specified by **hostname** (not an IP) is resolved **once, at
config-parse time**, via the internal resolver (IMR):
- (a) A transient lookup failure (IMR not yet primed, DNS blip, network not up at boot)
  → `len(res.Resolved)==0` → `ConfigError` → the zone is **permanently quarantined**
  until the next reload/restart. A transient failure should not permanently brick a zone.
- (b) Resolved addresses are **cached forever**, so a primary whose address later changes
  is no longer followed. (Regression vs `main`, which resolved the hostname **at dial time
  on every refresh**.)
- (c) Coupled boot-time symptom: to make parse-time resolution possible, the IMR is primed
  **synchronously before `ParseZones`** via a live, **no-deadline** root-NS fetch
  (`main_initfuncs.go:208-212`), so startup can **stall** on root-server reachability —
  for every default Auth/Agent server, even IP-only-primary configs.

**Agreed fix (full version).** Move primary resolution to **refresh time, retried each
cycle** — restoring `main`'s resolve-at-use behavior:
- An unresolved hostname primary keeps the zone **valid** and marks it **pending /
  retryable** (treated like an *unreachable* primary — keeps retrying on the refresh
  cadence), **not** `ConfigError`.
- Re-resolve on the refresh cadence (start simple: re-resolve each refresh cycle; TTL-aware
  caching is a later refinement). This also fixes (b).
- Once resolution is runtime, **remove the synchronous early `InitImrEngine`** prime →
  fixes (c) (boot no longer blocks on the root fetch); the IMR reverts to async start.

**Files.** `v2/resolve_primaries.go` (don't fail-hard; return "pending"),
`v2/parseconfig.go:694` (don't quarantine on unresolved), `v2/refreshengine.go` (resolve +
retry on the refresh cadence), `v2/main_initfuncs.go:208-212` (remove the synchronous
early prime once resolution is runtime).

**Only affects:** configs with **hostname** primaries. **IP-literal primaries are
unaffected** (they skip the IMR entirely).

**Status:** ✅ **DONE** (2026-06-30, commit `5093ccd`). Primary resolution moved to refresh
time — `zone_utils.go` re-resolves `PrimariesConf` on each `Secondary` refresh via
`resolvePrimaries`; an unresolved hostname primary keeps the zone valid and retries on the
refresh cadence instead of quarantining (`parseconfig.go` now emits `ConfigWarning`, not
`ConfigError`); and the synchronous early IMR prime was removed (`main_initfuncs.go`), so
boot no longer stalls on a root-NS fetch. A debug log of successful resolution was added in
`051d492`.

### D2 — Soften legacy bare-string `downstreams:` parsing (decided; ready to implement)

**Problem.** `downstreams:` changed `[]string → []AclEntry`; a legacy bare-string list now
**aborts the entire config load** (vs `notify:`, which quarantines just the one zone).

**Decided fix (B = graceful per-zone, no auto-migrate).** Add a `Legacy` marker to
`AclEntry` + a decode hook (parallel to the existing `PeerConf`/`stringToPeerConfHook`
path) so a bare-string `downstreams:`/`allow-notify:` **quarantines just that zone** with a
clear "migrate to `{prefix, key}`" error — instead of failing the whole load. **Not**
auto-migrated, because `downstreams` *changed meaning* (notify-list → AXFR ACL); silently
reinterpreting old entries as an allow-transfer ACL would be a security-relevant guess.

**Files.** `v2/acl.go` (`AclEntry` + marker), `v2/parseconfig.go` (decode hook + per-zone
validation, mirroring the `notify` legacy path ~`:718-733`).

**Status:** ✅ **DONE** (2026-07-01). Added a `Legacy` marker to `AclEntry` and a
`stringToAclEntryHook` (mirroring `stringToPeerConfHook`), composed into both decode-hook
sites (`parseconfig.go`, `config_validate.go`); `ValidateACL` rejects a `Legacy`-marked
entry, so a bare-string `downstreams:`/`allow-notify:` now quarantines just that zone via the
existing per-zone ACL validation instead of aborting the whole load. Not auto-migrated.
Test: `v2/acl_legacy_test.go`.

### D3 — `ExpandTemplate` silently drops new `ZoneConf` fields (maintainability footgun)

**Problem.** `ExpandTemplate` (`parseconfig.go:1110`) propagates template → zone via a
**hardcoded list** of per-field copies (`if len(tmpl.X) > 0 { zconf.X = tmpl.X }`). When a
new `ZoneConf` field is added, it is easy to forget the copy, so **templated zones silently
get the zero value**. This already bit us during live testing: `Downstreams` and
`AllowNotify` were dropped (fixed 2026-06-30 by adding the two copies), which made every
AXFR from a templated zone get REFUSED (empty downstreams ACL ⇒ deny).

**Fix direction.** Make an omission impossible to miss:
- **Preferred:** add a regression test that builds a template with *every* mergeable field
  set to a non-zero value, expands it onto an empty zone, and asserts each propagated (or
  is on an explicit skip-list). Adding a `ZoneConf` field without handling it in
  `ExpandTemplate` then fails the test.
- **Optional refactor:** drive the copy generically (e.g. reflect over `ZoneConf`, copy
  non-zero template fields except an explicit skip-set), so new fields are handled by
  default. Weigh against the fields that need special handling — `Name` (never copied),
  `Zonefile` (format-expanded), `OptionsStrs` (append, not replace), `DnssecPolicy`
  (zone-wins).

**Files.** `v2/parseconfig.go` (`ExpandTemplate`), new `v2/*_test.go` for the propagation test.

**Status:** ✅ **DONE** (2026-06-30, commit `4e4bc0b`). `ExpandTemplate` rewritten as a
reflection-based gap-fill (every template-set field propagates to a zone that didn't set it,
zone wins) with bespoke handling kept for `Zonefile` (%-expansion), `OptionsStrs` (union),
and `DnssecPolicy` (agent-gate); `Name`/`Template` never copied; runtime/display fields
skipped. Regression tests added in `v2/template_test.go`
(`TestExpandTemplatePropagatesAllFields` fails if a settable, template-set field is dropped).

### D4 — Zonefile template traversal guard false-positives on FQDN zone names (small, low-risk)

**Problem.** `ExpandTemplate`'s zonefile `%`-expansion rejects any expanded path containing
the substring `".."` as directory traversal (`strings.Contains(expanded, "..")`). For a zone
whose **name ends in a dot** (a fully-qualified `name: child.example.` in config) and a
template `zonefile: ".../%s.zone"`, expansion yields `.../child.example..zone` — the `..`
comes from the FQDN trailing dot meeting the `.zone` extension, **not** a real `../`
traversal — so the zone is falsely rejected and quarantined. Pre-existing (the guard predates
the D3 refactor); surfaced by the D3 propagation test, which originally used a trailing-dot
name.

**Fix direction.** Replace the blanket `strings.Contains(expanded, "..")` with a real
traversal check: reject only a `..` **path segment** (split on the separator, or verify the
cleaned path stays within the intended zonefile base dir), so a literal `..` inside a
filename is allowed.

**Files.** `v2/parseconfig.go` (`ExpandTemplate`, the zonefile-expansion guard).

**Only affects:** templated zones whose **config name carries a trailing dot** AND whose
template supplies a `zonefile` pattern. Current configs write zone names without the trailing
dot, so this is latent, not biting today.

**Status:** noted, not fixed (out of scope for D3, which was about field propagation).
Small, low-risk.

---

## Decisions made (context — not deferred fixes)

- **AXFR-out empty-`downstreams` = DENY** (close the legacy open-AXFR default): **keep** it
  (deliberate security hardening). Documented as a breaking change + migration step
  (breaking-changes §1). No backward-compat "empty = open" opt-in planned unless requested.

## See also

- [TSIG keystore punch-list](./2026-06-29-first-class-tsig-keystore-punch-list.md) — its own
  intentionally-deferred item: **minimum-secret-length validation** (should *warn*, not
  reject, to preserve interop with short BIND/NSD keys).
