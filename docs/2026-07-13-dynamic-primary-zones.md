# Dynamic primary zones — API-provisioned, template-constrained

**Date:** 2026-07-13
**Status:** DESIGN — agreed in discussion. **Sequenced after
`feature/zone-snapshot-correctness` merges** (see §8); implementation must build
on the post-snapshot world.
**Companion:** `2026-07-13-tdns-debug-test-tool.md` — whose provisioning stage
(§6.3 there) is the immediate consumer; this feature turns its
"operator installs zone + config" step into a fully automated
provision→run→cleanup round-trip.

---

## 1. Motivation

The dynamic-zone API provisions **secondaries only** — a deliberate v1
restriction, not an accident: `ProvisionDynamicZone` rejects
`fromAPI && Type != Secondary` with the comment *"API/CLI v1 is secondary-only
(primary + notify peers are static/catalog config until a later extension)"*
(`v2/dynamic_zones.go`). This document is that extension.

Immediate driver: test automation. tdns-debug needs disposable, updatable
primary zones created and destroyed per test identity. General value: any
service that wants to mint zones at runtime (self-service provisioning à la
the labstuff secondary service, but for authoritative data).

## 2. What already exists (code-verified, main @ `ae2d295`)

The striking finding is how little is missing:

- **Extension point designed in:** `DynamicZoneInput.Type` exists; the
  secondary-only check is one clause in the add path. Persistence with
  rollback, the `ApiManaged` marker, delete/modify guards, and the B5a/B5b
  resurrection interlocks are all zone-type-agnostic.
- **Templates already express everything a primary needs.** Post-D3,
  `ExpandTemplate` (`v2/parseconfig.go`) gap-fills *every* `ZoneConf` field:
  `UpdatePolicy` copied whole, `Downstreams`, `Notify`, `DnssecPolicy`,
  options unioned, and `Zonefile` as a `%s`-pattern substituted with the zone
  name (traversal-guarded) — built for stamping out many zones from one
  declaration.
- **Restart already works.** The dynamic config file is pulled in via
  `include:` and parsed by the normal `ParseZones` at boot — the same path
  that performs template expansion and update-policy activation (including
  `OptAllowUpdates`) for static zones. Persist `type: primary` +
  `template: <name>` in the dynamic entry and a restarted server rebuilds the
  zone with full policy through existing code. (Today `zoneDataToZoneConf`
  does not serialize `Template` — a one-field addition, §5.)
- **Dirty-primary machinery exists.** `OptDirty` blocks reload of a modified
  primary; the refresh engine's zone-file write-back covers persistable
  (API-managed, B5a) zones with the B5b `zoneStillLive` guards.

What is genuinely new is only the **add path** (§4) and the **gates** (§3).

## 3. Gating (two gates, both required)

1. **`dynamiczones.dynamic.allowed` changes from bool to `[]string`**, with
   allowed values `primary` and `secondary`:

   ```yaml
   dynamiczones:
     dynamic:
       allowed: [ secondary, primary ]
   ```

   **No legacy support:** a bool value is a hard config error with a message
   naming the new syntax (`allowed: [secondary]`). Absent/empty → deny all.
   Unknown list values are a config error.

2. **Per-template opt-in**: a template must carry `dynamiczones: true` to be
   instantiable via the API:

   ```yaml
   templates:
     churn-test:
       dynamiczones: true
       zonefile: /var/tdns/dynamic/%s.zone
       update-policy:
         zone:
           type: selfsub   # signer key _churn.<id>.<zone> owns names under itself
           rrtypes: [ TXT ]
       downstreams:
         - { prefix: 127.0.0.1/32, key: NOKEY }
   ```

   (Named `dynamiczones:`, not `dynamic:` — it is the *zones using* the
   template that are dynamic, not the template.) A template without the flag
   is refused with a clear error. This is the security envelope: an API
   client cannot express an update policy at all; it can only pick among
   operator-blessed configurations. Combined with the truststore API (which
   governs *which keys* the policy trusts), privileges split cleanly:
   operator curates the policy space, API caller picks a point in it.

## 4. The add path

`zone add` gains `zonetype: primary` + `template: <name>` (template
**required** for primaries in v1 — a primary without a template is refused;
"inline everything" can be revisited later if a need appears). Flow:

1. Check both gates (§3).
2. Expand the template over `ZoneConf{Name, Type: primary}` — existing
   `ExpandTemplate`, unchanged.
3. Activate the update policy — the validation/activation logic currently
   inlined in `ParseZones` (policy-type switches, RRtype maps,
   `OptAllowUpdates`) is factored into a helper both callers share, so
   API-added and boot-parsed zones cannot drift.
4. **Bootstrap the zone file** if absent (§4.1), at the template's expanded
   zonefile path.
5. Register + persist (as today, with rollback; the persisted entry now
   carries `template:`), enqueue a refresh that loads **from file**
   (`FetchFromFile`) instead of AXFR.
6. Zone goes ready and is mutable via RFC 2136 according to the template's
   update policy — that is the intended modification channel from then on.

**Inline TSIG keys are accepted, symmetrically with secondaries, but
reinterpreted for the primary role:** the same staging/commit/rollback
machinery upserts the key, and it is applied to every keyless (`""`/`NOKEY`)
`downstreams` entry in the expanded config — gating *outbound transfers* by
that key, the mirror image of the secondary case (where it authenticates
*inbound* transfers). Rewiring `NOKEY` → named key only ever tightens access,
and it lets many tests share one template while each supplies its own
per-test key. The rewired `downstreams` are persisted with the zone (as
`Downstreams` already is), and at boot re-expansion the zone's materialized
entries win over the template's by gap-fill semantics — consistent, no
special case. Other key references in the template (`notify`, explicit
`downstreams` keys) must pre-exist in the keystore as before.

### 4.1 Bootstrap apex synthesis

The server knows the zone name and its own listen addresses
(`dnsengine.addresses`, `v2/config.go`). Synthesize:

```
<zone>     SOA   ns.<zone> hostmaster.<zone> 1 <refresh retry expire minimum>
<zone>     NS    ns.<zone>
ns.<zone>  A     <each IPv4 listen address>
ns.<zone>  AAAA  <each IPv6 listen address>
```

- Addresses: `dnsengine.addresses` with ports stripped, deduplicated,
  classified v4/v6. **Wildcard listeners (`0.0.0.0`/`::`) are skipped with a
  WARN** — predictable beats clever; operators who want addresses in
  synthesized apexes list them concretely. If nothing remains, the zone is
  still created (NS without address records) with a WARN.
- Proposed constants (implementation-review detail): RNAME
  `hostmaster.<zone>`, serial `1`, timers `3600 600 604800 300`.
- Everything above is ordinary zone content — once the zone is live it can
  be reshaped via DNS UPDATE as the policy allows.

## 5. Persistence and lifecycle

- `zoneDataToZoneConf` additionally serializes `Template` (and the
  `type: primary`). Update policy is **not** persisted — it re-derives from
  the template at boot, one source of truth. Zone *content* persists via the
  zone file (dirty write-back, B5a/B5b).
- Template changed/removed under a persisted dynamic primary: the normal
  boot behavior applies (missing template ⇒ zone in ERROR state; changed
  template ⇒ new expansion wins). Documented, not special-cased.
- **`delete`**: as for dynamic secondaries (map + config entry), plus the
  zone file — an API-managed primary is disposable by construction. Static
  and catalog zones stay refused.
- **`modify`**: not supported for primaries in v1 (decided; symmetry noted
  but no strong need). The rationale beyond need: modify-for-primary has
  murky semantics — "change the template" of a live, since-updated zone
  means either re-expansion (clobbering drift the policy legitimately
  allowed) or partial application (a new merge concept). Every concrete use
  has a cleaner home: content via DNS UPDATE, key rotation via the keystore
  API, config changes via delete + re-add. Revisit when an actual use case
  can't be served by those.

## 6. Interaction with tdns-debug

- Capability probing is clean in both worlds: today the add-primary attempt
  returns a classifiable structured error; post-feature it succeeds. The
  tool's capability matrix gains `zone add (primary)`.
- With the capability present, `--generate-config` stops emitting operator
  artifacts for tdns targets: template existence is checked (its *creation*
  stays an operator/config concern — deliberately, that is the envelope),
  keys go in via keystore/truststore API, the zone via `zone add`, and
  `cleanup --test <id>` really deletes everything. The emit-artifacts path
  remains for non-tdns targets and templates the operator has not blessed.
- tdns-debug's churn/ddns runs against an API-provisioned primary double as
  this feature's acceptance tests.

## 7. Migration / compatibility notes

- `dynamiczones.dynamic.allowed` bool → `[]string` (§3) — the only breaking
  config change; hard cutover, no legacy bool decode.
- No wire, API-response, or zone-file format changes. The `zone add` request
  gains fields; existing secondary adds are untouched.

## 8. Sequencing (agreed)

After `feature/zone-snapshot-correctness` merges — this feature creates a new
zone-mutation path, and building it pre-merge means immediately reworking it
to route through `publish()` (initial-snapshot install, staged bootstrap
content). Order: snapshot campaign (tdns-debug M1–M3, manual zone install) →
snapshot merge → this feature → tdns-debug provisioning upgrade (§6).

## 9. Acceptance criteria (sketch)

- add → serve → UPDATE-per-policy (SIG(0) accepted, unsigned/wrong-key
  refused) → restart → policy + content survive → delete → nothing resurrects
  (mid-flight guards, B5b analogue) and the zone file is gone.
- Gate matrix: allowed-list × template-flag × zone-type combinations refuse
  or admit correctly; a legacy bool `allowed:` is a config error naming the
  new syntax.
- Inline TSIG on a primary add: keyless `downstreams` entries become gated
  by the inline key (transfer refused without it), key persisted, boot
  re-expansion preserves the rewiring.
- Wildcard-listener and zero-address bootstrap edge cases WARN as specified.
- tdns-debug churn run green against an API-provisioned primary.

---

## 10. Implementation scoping (2026-07-19, code-verified)

A second pass, tracing every claim in §2 against the tree (verified on
`feature/transactional-policy-reload-pr2 @ 6da9344`, i.e. main + the PR-2
merge; the code paths for this feature are main-equivalent — file:line
anchors below may drift by a few lines on main but the structures match).
**Conclusion: §2's "how little is missing" holds for the *plumbing*, but the
residual work is a *medium* feature (~1,000–1,500 LOC across ~12–15 files,
roughly half tests), not a small one. The risk is not spread thin — it
concentrates in exactly two spots (§10.3).** Not scheduled for implementation
at the time of writing; recorded here so the scope is known before it is.

### 10.1 Confirmed genuinely free (reused unchanged)

- **Delete** — `RemoveDynamicZone` (`v2/dynamic_zones.go:852`) already removes
  map + config + zone file and guards on `OptApiManagedZone`; zone-type
  agnostic, works for primaries as-is.
- **Restart / boot re-expansion** — `ParseZones` already expands any
  `zconf.Template` (`v2/parseconfig.go:632`) and enqueues a file-load refresh
  for primaries carrying a `Zonefile` (`v2/refreshengine.go:376`). Persist
  `template:` + `type: primary` and boot rebuilds the zone through existing
  code.
- **Template expansion** — `ExpandTemplate` (`v2/parseconfig.go:1157`)
  gap-fills `UpdatePolicy`/`Downstreams`/`DnssecPolicy`, unions options, and
  `%s`-substitutes the zonefile with a traversal guard — exactly a primary's
  needs.
- **Persist/rollback + `ApiManaged` marker** — reused as-is;
  `ZoneConf.Template` (`v2/structs.go:261`) already exists as a field.

### 10.2 The actual work

| # | Item | Where | ~LOC | Risk |
|---|------|-------|------|------|
| A | Gate 1: `dynamiczones.dynamic.allowed` **bool → `[]string`** + custom "legacy bool" config error | `v2/config.go:429`, `dynamic_zones.go:713,144` | 80–120 | **Med** — breaking config change; `DynamicZoneTypeConf` is *shared* with the catalog structs, so `dynamic` needs its own type; a generic decode won't produce the required named-syntax error |
| B | Gate 2: per-template `dynamiczones: true` opt-in | `v2/structs.go:261` (new field), `ExpandTemplate` skip map | ~40 | Low |
| C | **Primary branch** in `ProvisionDynamicZone` | `v2/dynamic_zones.go:708` | 120–180 | **Med** — genuinely new control flow, not a deleted check (§10.3) |
| D | Bootstrap apex synthesis (SOA/NS/A/AAAA from `dnsengine.addresses`) | new helper (`dnsengine.addresses` at `v2/config.go:184`) | 100–140 | Low-Med — isolated; edge cases (wildcard/zero-address) are the test surface |
| E | **Factor policy-activation out of `ParseZones`** into a shared helper | `v2/parseconfig.go:811–894` | 120–160 | **Med-High** — hottest boot path (§10.3) |
| F | Inline-TSIG **reinterpreted for `downstreams`** | `stageInlineTsigKey` (`v2/dynamic_zones.go:629`) | 60–100 | Low-Med — downstreams are `AclEntry`, not `PeerConf` → a parallel impl, not a reuse |
| G | Persist `Template` | `ZoneData` (**no such field today**) + `zoneDataToZoneConf` (`v2/dynamic_zones.go:362`) | ~15 | Low |
| H | Reject `modify` on a primary (v1) | handler / `ModifyDynamicZone` | ~15 | Low |
| I | API + CLI wiring (`--type`, `--template`; relax `MarkFlagRequired("primaries")`) | `v2/api_structs.go:211`, `apihandler_zone.go:217`, `cli/zone_cmds.go:211` | 80–120 | Low — mechanical, but public surface |
| J | Docs + sample YAMLs + `allowed:` migration note | `cmdv2/auth/*.sample.yaml`, config guide | 60–100 | Low |
| K | Acceptance tests (§9 gate matrix, round-trip, inline-TSIG, edge cases) — note `dynamic_zones_cores_test.go:50` currently asserts the **opposite** and must be inverted | test files | 300–500 | — |

### 10.3 Where the risk concentrates

Two items make this not-an-afternoon; the rest is as light as §2 claims.

1. **`ParseZones` policy-activation extraction (item E).** Lines 811–894 are
   not a self-contained block — they are entangled with the `broken_zones`
   accumulator, `zd.SetError`, and `continue` control flow, and they mutate
   `options` (`OptAllowUpdates`/`OptAllowChildUpdates`) with a
   delegation-backend cross-check. Extracting a helper both callers share is
   a refactor of the path **every zone boots through**; it needs
   behaviour-preservation proof against the existing tests, not just a clean
   compile.

2. **Snapshot-integration of the primary branch (item C).** Per §8 (now
   satisfied — `feature/zone-snapshot-correctness` merged, `965df6f`), the
   freshly-bootstrapped apex must land through the post-snapshot
   `publish()` / initial-snapshot-install path, or it trips the
   "Ready ⇒ valid snapshot" apex guard added on the snapshot branch. The
   secondary add path already routes through this, so the primary path
   inherits it — but the *bootstrap content* is new, and that is exactly the
   class of thing that passes a unit test and SERVFAILs live.

Plus one smaller sharp edge: the **breaking `allowed:` bool→list cutover**
(item A) touches every deployed config (nox, foffe testbeds), and an existing
test asserts the pre-feature behaviour and must be inverted.

### 10.4 Suggested PR sequence

The work splits cleanly so the two risky items land in isolation, each
independently testable:

- **PR1** — gates (A + B) + persistence (G); pure config plumbing, no primary
  path yet.
- **PR2** — the `ParseZones` factoring (E) **alone**, behaviour-preserving,
  guarded by the existing tests.
- **PR3** — primary add branch (C) + apex synthesis (D) + inline-TSIG (F) +
  API/CLI wiring (I), stacked on PR2.
- **PR4** — docs/samples + the acceptance matrix (J + K).

### 10.5 Verdict

The original description's instinct about the *shape* is right: the design
front-loaded the hard architectural decisions into this document, so what
remains reads mechanical, and most of §10.2 genuinely is. But three items
carry real regression risk (E, the snapshot-integration of C, the gate
cutover), and the acceptance surface (§9) is broad. Net: **a medium feature,
~3–5 focused sessions — not an afternoon, and not a large project either.**
