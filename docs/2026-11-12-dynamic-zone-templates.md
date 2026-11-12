# Templates for API zones: who owns the outbound settings

**Written 2026-11-12.** For #1040. Line references are to main at `405f40b6`.

**Status:** implemented on `feat/api-secondary-template` (draft PR, refs #1040).
Catalog zones (the last section) are not covered by the PR.

## The problem

A server that receives zones through the zone API and passes them on (a
distribution point: it transfers each zone in, and other servers transfer it
from it) needs two things on every API zone:

- **downstreams**, with the TSIG key the downstream servers use, or their
  transfers are refused (`downstream_auth.go`: no entry matched, refused);
- **NOTIFY targets**, or they see a change only at their SOA refresh.

`zone add` for a secondary gave the zone neither. `ProvisionDynamicZone`
(`v2/dynamic_zones.go:814`) built the zone with primaries, options and
transfer-src only, and `ZonePost` had no field for the outbound side.
Templates already carried it, and `zone add --type primary --template` used
them (`prepareDynamicPrimary`, `v2/dynamic_primary.go:77`), but a secondary's
template was documented as unused and ignored.

Templated primaries had a problem of their own. Their outbound lists were
persisted as expanded on the day of the add, and at boot the persisted lists
won over the template by gap-fill (`2026-07-13-dynamic-primary-zones.md`
§11.1). No reload re-expanded a dynamic zone either: `config reload` and
`config reload-zones` both rebuild the template map, but only static zones
are re-parsed (`v2/config.go:1283`). So a downstream added to a template
never reached a zone stamped from it, not even on a restart.

## The decisions

Taken with the maintainer on 2026-11-12:

1. An operator default template per zone type, used when an add names none.
2. A template change reaches existing zones on `config reload`, not only on
   a restart. If reload cannot do it today, that is in scope.
3. For catalog zones, first test a catalog zone defined in the config, and
   build anything new only if that fails (the last section).

## The design

**A template for an API secondary gives it its outbound settings, and
nothing else.** `zone add` (and `zone modify`, below) for a secondary takes a
template. The template must exist, be blessed (`dynamiczones: true`), and
say `type: secondary`. A primary's template may leave the type unset, but
most of a template means nothing to an API secondary, so the type is how the
operator says a template is meant for one. From the template the zone takes
exactly:

- `downstreams` and `downstream-auth`
- `notify` and `allow-notify`
- `notify-retries` and `notify-retry-interval`

Its primaries, inline TSIG key, options and transfer-src stay the caller's.
A template that sets primaries does not change where the zone comes from;
the primaries are simply not read. The expanded lists go through the same
checks as a static zone's (`validateTemplateOutbound`, shared with the
primary path): downstream-auth mechanisms, NOTIFY targets as `{addr, key}`
with no TLS fields, both ACLs through `ValidateACL`, every key known.
`peers:` references are expanded first. The zone's own inline key is not
acceptable on this side: it authenticates the zone's primaries, and a
template is shared by every zone stamped from it.

**The template owns those settings.** For a template-driven API zone, of
either type, they are never persisted. The dynamic config entry carries the
template's name, and the lists are expanded from the template:

- when the zone is added;
- at every boot (`LoadDynamicZoneFiles`);
- on every `config reload` and `config reload-zones`
  (`ReapplyDynamicZoneTemplates`, run after the reload has rebuilt the
  template map and released `confMu`).

So editing the template and reloading is how a new downstream gets every
zone. The reload replies with a count: zones re-expanded, how many changed,
how many failed.

**A template that no longer expands.** On a reload, the zone keeps the
outbound settings it had and gets a `TemplateWarning`, a new
visibility-only error category. A typo in a template must not cut live
zones off from their downstreams. The warning clears on the next expansion
that succeeds. It is its own category so that clearing it cannot remove an
unrelated `ConfigWarning`, or the other way round. At boot there is nothing
to keep: a secondary loads without the outbound settings, so it allows no
transfers out and sends no NOTIFYs, and carries the warning. A primary keeps
its earlier rule and becomes an error-state zone.

**The operator default.** `dynamiczones.dynamic.default-template` maps a
zone type to a template:

```yaml
dynamiczones:
   dynamic:
      allowed:  [ secondary ]
      storage:  persistent
      default-template:
         secondary:  hub-secondary
```

An API add that names no template gets the default for its zone type. The
resolved name is persisted with the zone, so changing the default later does
not move zones added under the old one. To move them, run `zone modify`.
Catalog-provisioned zones never take the default. Each entry is checked at
load and by `config check` against the same gates as an add: the template
exists, is blessed and has the right type (a type inherited from a parent
template counts). A primary added without a template is still refused when
no primary default is set.

**`zone modify`** (secondaries) keeps the zone's template unless told
otherwise. `--template X` sets or replaces it. `--clear-template`
(`ZonePost.ClearTemplate`) removes it, and with it the outbound settings it
gave the zone, since they were the template's. Both together are refused.
A template named in a modify is gated like an add's. When the zone's own
template has stopped expanding, an unrelated modify (a key, a primary) still
goes through: the zone keeps its outbound settings and gets a
`TemplateWarning`. A zone without a template keeps today's behaviour: its
persisted lists are carried forward.

**Templated primaries follow the same rule.** Their outbound lists are now
the template's at boot and on reload too. One thing was persisted for a
reason: a primary added with an inline TSIG key has the keyless (`""`/`NOKEY`)
entries of its template's downstreams bound to that key. The bound key now
has its own field in the dynamic config entry, `inline-tsig-key:`, and is
re-applied after every expansion, including to keyless entries added to the
template later. The daemon writes the field. It is never copied from a
template, and means nothing in the static config.

**Entries persisted before this change.** A templated primary written by
an older version carries its outbound lists as they were expanded, and no
`inline-tsig-key`. At boot the lists give way to the template's, and the
inline key is recovered from them: it is the key the persisted entries use
on the prefixes that the template leaves keyless (`legacyInlineTsigKey`).
The entry is then rewritten once in the current form. Recovery errs towards
binding, never away from it, because a binding the recovery missed would
open the zone to keyless transfers. So when the entries show more than one
such key, the recovery refuses to guess. The zone becomes an error-state
zone that keeps its persisted lists, and later rewrites of the file keep
them too, until the operator sets `inline-tsig-key` or re-adds the zone.

**Visibility.** `zone list-dynamic` shows each zone's template and live
NOTIFY targets. The live lists are filled in from the zone, since the
persisted form no longer has them.

## Not changed

- A reload does not NOTIFY a newly added target about changes it missed. It
  catches up at its next refresh or the zone's next change. A downstream
  that loads a zone for the first time transfers it anyway.
- A templated primary's other template fields (options, update policy,
  DNSSEC policy, publish cadence) follow the template only at boot, as
  before. Making them follow on reload means re-running the primary's whole
  activation on a live zone, which is its own change.
- The NOTIFY a server sends after each transfer in, to `zd.Notify`, is the
  existing refresh-engine behaviour; the loopback run below confirms it for
  API zones.

## Tests

Unit tests in `v2/dynamic_template_test.go`:

- an API secondary with a blessed template gets the template's outbound
  settings and nothing else (primaries, options, transfer-src stay its own);
- a missing, unblessed, primary-typed or untyped template is refused, as are
  outbound lists that do not validate, and the zone's own inbound inline key
  in a template's downstreams;
- the default template applies when an add names none, a named template
  wins, and catalog-path adds never take it; the config check of the
  default (missing, unblessed, wrong type, inherited type, unknown zone type);
- persistence keeps the template name, drops the outbound lists, and keeps a
  primary's inline key;
- boot re-expansion replaces stale persisted lists and rewrites the entry; a
  missing template loads the zone with a warning and no outbound settings;
- reload re-expansion reaches secondaries and primaries (keeping the inline
  key binding), reports changes, keeps settings and warns on a broken
  template, and clears the warning once fixed;
- modify keeps, sets and clears the template, and refuses what it should;
- legacy primary entries: key recovery, the ambiguous case, and the
  one-shot rewrite at boot.

A loopback run (all on 127.0.0.1): a BIND 9.20 primary with three zones,
transfers authorised by a customer TSIG key; a tdns-auth distribution
server adding them through the API with that key as inline key; one
tdns-auth and one NSD 4.13 downstream using an operator key. The template
gives downstreams `127.0.0.1/32` with the operator key, and NOTIFY targets.
SOA refresh was 3600 s, so a change within seconds came by NOTIFY.

| Step | Result |
|---|---|
| `zone add` without a template; with `--template` | Both zones get the template (the first from `default-template`). The persisted entry has `template:` and empty outbound lists. |
| Downstream transfers | tdns-auth and NSD transfer with the operator key. AXFR with no key, or with the customer key: REFUSED ("no entry matched address+TSIG"). |
| Change on the BIND primary, template NOTIFYs the tdns-auth downstream only | That downstream has the new serial within 6 s; NSD stays on the old one (not notified). |
| Add NSD to the template's `notify`, `config reload` | "2 re-expanded (2 changed, 0 failed)"; `list-dynamic` shows both targets on both zones. |
| Next change on the primary | Both downstreams have it within 1 s, by NOTIFY. |
| Restart the distribution server | Zones re-expanded at boot with both targets; the next change reaches the tdns-auth downstream by NOTIFY. |
| `zone modify --clear-template`, then `--template` | Keyed AXFR refused after the clear, served again after the set. Both flags together, and an unknown template, refused. |
| A third zone added, on both downstreams | Transferred by both; NSD picked it up through the catalog. |
| Template renamed away, `config reload-zones` | "3 re-expanded (0 changed, 3 failed)"; every zone keeps its targets and shows the warning; a change still reaches the tdns-auth downstream. Template restored, `config reload`: warnings gone. |
| `default-template` naming a missing template | The daemon refuses to start; `config check` reports it as a FAIL. |

## Catalog zones

Decision 3 asked for a test of a catalog zone defined in the config (a
primary with `options: [catalog-zone]`, plus downstreams and NOTIFY in the
config). It works with `catalog zone add`: NSD is notified with the key,
transfers the catalog and the member zones. It does not survive a restart,
nor `config reload-zones`:

- The member list (`catalogMemberships`, `v2/catalog.go:546`) is kept only
  in memory and never rebuilt from the catalog's records. A catalog created
  with `catalog create` has the same flaw: its content survives a restart,
  but the next `catalog zone add` rewrites it with the new member only.
- A configured catalog's changes are written to a copy under
  `dynamiczones.zonedirectory`, not to its own zone file. A restart or
  `config reload-zones` serves it from its file again, without members, and
  a consumer that takes that empty catalog drops every member zone.
- A configured catalog the server produces must also have
  `catalog.config-groups` present (it may be empty), or it goes to
  ConfigError (`v2/parseoptions.go:384`). Only a consumer needs config groups.

These are open questions for the maintainer, and not part of this PR.
