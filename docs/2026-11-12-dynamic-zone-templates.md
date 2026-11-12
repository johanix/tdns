# Templates for API zones: who owns the outbound settings

**Written 2026-11-12.** For #1040. Line references are to main at `405f40b6`.

**Status:** implemented on `feat/api-secondary-template`, draft PR #1041,
including the catalog fixes (the last section). Revised the same day for the
review rounds (CodeRabbit, and an external review); the changes are in place
below.

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
   build anything new only if that fails. It failed; the maintainer then
   ruled to keep the configured catalog, with no new catalog API, and fix
   what the test found (the last section).

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
`peers:` references are expanded first.

The template may not name **the zone's own inbound keys**: the keys its
primaries use, and the inline key of the add or modify. Such a key
authenticates where the zone comes from, typically the zone owner's key, and
a template is shared by every zone stamped from it, so in its downstreams
it would let that key's holder transfer every such zone. The check compares
key names, so it also holds when an earlier add has already put the key in
the keystore. A key the operator declares in `keys.tsig` is exempt: one
operator key may serve both directions, for instance between two
distribution servers.

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
how many failed. Both reload paths now read templates (and zones) the way
the startup parse does: transfer-list aliases such as `provide-xfr:` are
normalized, and bare-string peer and ACL entries decode, so an alias does not
lose its list on a reload.

The installs are ordered. A reload's re-expansion holds one lock for its
whole run, an add holds it from its expansion until the zone is in the zone
map, and a modify from reading the zone until its replacement is in the map.
Otherwise an expansion made before a reload rebuilt the template map could
be installed after the reload's own, and the zone would keep a downstream
the operator had just removed; and two modifies of one zone could both start
from the same old zone, the second undoing the first.

**A template that no longer expands.** On a reload, the zone keeps the
outbound settings it had and gets a `TemplateWarning`, a new
visibility-only error category. A typo in a template must not cut live
zones off from their downstreams. The warning clears on the next expansion
that succeeds. It is its own category so that clearing it cannot remove an
unrelated `ConfigWarning`, or the other way round, and it does not block a
serial bump the way other errors do. At boot there is nothing to keep: a
secondary loads without the outbound settings, so it allows no transfers out
and sends no NOTIFYs, and carries the warning. A primary keeps its earlier
rule and becomes an error-state zone.

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
template counts), and its parent chain has no missing parent and no cycle
(a template naming itself included), since the template map drops such a
template at load. Two keys for one zone type (`primary` and `Primary`) are
refused. On a full reload the check runs before the template map is
rebuilt, so a refused reload leaves the running templates as they were.
More generally, the template map is built on the side and installed only
once complete, and a `config reload` that fails at any later point puts the
previous map back; `config reload-zones` keeps the templates in use when the
template part of its re-read fails. A
primary added without a template is still refused when no primary default
is set.

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
open the zone to keyless transfers. So the recovery refuses to guess when
the entries show more than one such key, and when they show none but a keyed
prefix the template has since dropped sits beside a keyless template prefix
the entry has no entry for (the key may have been on the dropped prefix).
Entries that leave a keyless template prefix keyless prove there was no
inline key. A refused zone becomes an error-state zone that keeps its
persisted lists. Later rewrites of the file keep them too, and a reload
does not re-expand it, until the operator sets `inline-tsig-key` or re-adds
the zone.

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
- legacy primary entries: key recovery, the ambiguous cases, the one-shot
  rewrite at boot, and a reload leaving an error-state shell alone;
- the zone's own inbound key refused in a template on add (also when it is
  already in the keystore), on modify and on reload, and an operator key
  from `keys.tsig` accepted in both directions;
- a template's `provide-xfr:` decodes as its downstreams on a reload;
  a `TemplateWarning` alone does not block a serial bump;
- the default template's parent chain: a missing parent, a cycle, a
  template naming itself; two keys for one zone type.

Unit tests in `v2/catalog_membership_test.go` cover the catalog fixes (the
last section), including a rebuild that keeps a member whose publish has not
landed, auto-configuration leaving a produced catalog alone, and empty group
prefixes.

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
config). It worked with `catalog zone add`: NSD was notified with the key,
and transferred the catalog and the member zones. It did not survive a
restart, nor `config reload-zones`:

- The member list (`catalogMemberships`, `v2/catalog.go:546`) was kept only
  in memory and never rebuilt from the catalog's records. A catalog created
  with `catalog create` had the same flaw: its content survived a restart,
  but the next `catalog zone add` rewrote it with the new member only.
- A configured catalog's changes were written to a copy under
  `dynamiczones.zonedirectory`, not to its own zone file. A restart or
  `config reload-zones` served it from its file again, without members, and
  a consumer that took that empty catalog dropped every member zone.
- A configured catalog the server produces had to have
  `catalog.config-groups` present, even empty, or it went to ConfigError
  (`v2/parseoptions.go:384`). Only a consumer needs config groups.

The maintainer ruled (2026-11-12): keep the configured catalog, managed
through the existing `catalog zone add` and `delete`, with no new catalog
API, and fix all three.

**The member list comes from the catalog's records.** When a catalog this
server originates is loaded, the member list is rebuilt from its own PTR
records under `zones.<catalog>`, with the groups of each member's
`group.<id>.zones.<catalog>` TXT (`rebuildCatalogMembership`). The `<id>`
labels are kept, so a later rewrite does not move a member. This holds for
API-created catalogs too. It runs at the first load, again once the
journal has been replayed (a member added since the file was last written is
only in the journal), and after a refresh that changed the zone (an edited
zone file reloaded). It steps aside while the list is ahead of the zone: the
list counts the member changes made through the API and the ones the
published content reflects, the latter advanced when the publish carrying a
regeneration lands, and a rebuild that finds them different, before or
after reading the zone, keeps the list as it is. A secondary's
catalog mirrors its upstream and gets no member list. A group that is
defined but on no member is not in the zone, so it does not survive a
restart.

**A configured catalog writes its own zone file.** Zones the config file
defines are now marked as such when ParseZones creates them, or takes over
one that was dynamic. For such a
catalog, a change is written to its own `zonefile` once the publish that
carries it is done, as `zone write` would (`WriteZone`, which also records
the file's identity, so the next refresh does not take the write for an
outside edit). Such a zone is also no longer copied into the dynamic config
file, where it would have outlived its removal from the config; a copy an
older version wrote there drops out at the next rewrite.

**Only a catalog that auto-creates needs config groups.** The
`catalog.config-groups` check now applies to a catalog with
`catalog-member-auto-create`. A catalog the server produces, or only reads,
needs no `catalog:` block at all: without one, or with no
`group-prefixes` in it, every group is an ordinary group. And member
auto-configuration checks a member's config group against the local config
groups only for a catalog that auto-creates: a catalog that only reads no
longer goes to ConfigError, and stops being served, over a member group not
defined locally, and a produced catalog's groups are labels for its
consumers. A ConfigError such a check left earlier (with auto-create on) is
cleared at the next pass.

The ruling as given covered a catalog the server produces. The maintainer
widened it to every catalog that does not auto-create, consumers included,
in the second review round ("Fix both", 2026-11-12).

The loopback rerun, with the hub's config holding no `catalog:` block:

| Step | Result |
|---|---|
| Hub start | The configured catalog loads (no ConfigError), and is not listed among the dynamic zones. |
| `catalog zone add` of three zones | The hub serves 3 PTRs; the catalog's own zone file holds them; NSD transfers all three member zones. |
| Hub restart | The catalog still has its 3 members ("member list rebuilt ... members=3"); `catalog zone list` shows them; NSD keeps every member. |
| `catalog zone delete` of one member, then add it back | NSD drops that member only, then takes it back; the other two stay. |
| `config reload-zones` | The catalog keeps its 3 members; NSD keeps every member. |
| An API catalog: add a member, restart, add another, restart, add a third | All three are in the catalog after the last add. |
| The dynamic config | The copy of the configured catalog an older version wrote there is gone after the next rewrite. |
