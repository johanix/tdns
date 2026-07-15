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
