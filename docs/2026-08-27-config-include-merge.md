# Merging `include:`d config instead of replacing it

2026-08-27

Revised after external review
([`2026-08-27-config-include-merge-review.md`](2026-08-27-config-include-merge-review.md)).
The central change from the first draft: the merge is **opt-in per include**
rather than a default-on behaviour change. What that fixed, and what in the
review did not survive checking, is recorded at the end.

## The problem

`include:` cannot be used to contribute *more* of something the main config
already has. A file that carries `zones:` does not add zones; it replaces them.

The concrete case: `tdns-zonegen` generates a tree of test zones and writes the
tdns-auth blocks they need. That output has to be merged into the server config
by hand, extracting the contents of each block and pasting them into the
existing one. The tool prints a warning telling the operator *not* to
`include:` the file it just wrote, which is a poor thing for a generator to
have to say.

The same shape appears whenever config comes from more than one source: a
per-host file plus a shared one, generated plus hand-written.

## What happens today

[`processConfigFile`](../v2/parseconfig.go) unmarshals each file into a raw
`map[string]interface{}` and merges the included file into the including one:

```go
for k, v := range included {
    if existing, exists := config[k]; exists {
        if existingMap, ok1 := existing.(map[string]interface{}); ok1 {
            if newMap, ok2 := v.(map[string]interface{}); ok2 {
                for k2, v2 := range newMap {
                    existingMap[k2] = v2        // ONE level
                }
                continue
            }
        }
    }
    config[k] = v                                // everything else: replace
}
```

- **`zones:` and `templates:` are lists** — replaced outright.
- **`dnssec:` is a map, so it merges — one level only.** Each *sub-key* is
  copied wholesale, so an included `dnssec.policies` replaces the main
  config's, while `dnssec.completeness` beside it survives.
- **Top-level maps already combine.** `peers:` merges today. Nested maps do
  not. That inconsistency is the surprising part.
- The **included** file wins over the including one.

This is not mapstructure. The merge is over raw YAML maps; mapstructure only
decodes the already-merged result.

## Prerequisite: `config check` and the daemon already disagree

Found while costing this, and true today with no changes to anything:

`config check` does not use the daemon's loader. `loadConfigViper` resolves
`include:` with **viper's `MergeInConfig`**, a different algorithm that
deep-merges maps. Its comment claims it merges "exactly as the daemon/CLI
loaders do". Measured, same two files:

```
dnssec.policies    daemon = [beta]          (n=1)
                   config check = [alpha beta] (n=2)
```

So a zone referencing policy `alpha` **passes `config check` and then fails at
the daemon**, because the daemon never had `alpha`. That is a live bug
independent of this work, and it must be fixed first: any plan that reports
collisions from `config check` would otherwise report a different world than
the one being enforced.

The fix is small. `viper.MergeConfigMap` takes a raw map, so
`loadConfigViper` can hand it the daemon's own merged result and every
downstream check — which all take a `*viper.Viper` — stays untouched:

```go
raw, _, err := tdns.LoadRawConfigMap(path)
v := viper.New()
v.MergeConfigMap(raw)
```

## The design: opt-in merge

An include either replaces (today's behaviour, and the default) or merges:

```yaml
include:
  - auth-templates.yaml          # replace, exactly as now
  - file: zonegen-auth.yaml
    merge: true                  # allowlisted merge
```

A bare string stays a bare string, so every existing config keeps its exact
current behaviour. Zonegen stops printing "do not include this file" and starts
printing "include it with `merge: true`".

### The allowlist

Merging applies only to these paths. Everything else replaces, opted in or not.

| Path | Kind | Strategy |
|---|---|---|
| `zones` | list of named maps | concatenate; duplicate `name` is an error |
| `templates` | list of named maps | concatenate; duplicate `name` is an error |
| `dnssec.policies` | map of named maps | merge by policy name; duplicate name is an error |
| `dnssec.large_algorithms` | list of strings | union |
| `dnssec.split_algorithms` | map of string lists | merge by KSK name, union the ZSK lists |

Three strategies, because these are three kinds of thing:

- **Collections of named objects** (`zones`, `templates`, `dnssec.policies`).
  Two definitions of one name is a conflict, not something to merge — deep
  merging two zone definitions produces a zone neither file describes.
- **Sets** (`large_algorithms`). The same algorithm in two files is the same
  fact stated twice. Union.
- **Maps of sets** (`split_algorithms`). Merge at the KSK level, union the
  leaf lists.

`split_algorithms` deserves a caveat the first draft did not give it: unioning
it **widens which KSK/ZSK pairings the server will accept**. That is the right
direction for the motivating case and it only gates policy parse, but it is a
widening, not a restatement. Documented as such.

**Not on the allowlist, and deliberately:** `dnsengine.addresses`,
`apiserver.addresses`, `dnsengine.transports`. Concatenating those would
silently make a server listen on more addresses than the file in front of you
says — the same class of failure as widening an ACL, and worse than the clobber
being fixed, because a clobber is at least visible in what the server runs.
The allowlist holds even for an include that opted in.

**Known gaps, not blockers:** `dnssec.templates` (policy templates, same shape
as `dnssec.policies`) and `keys.tsig` (list of named objects) still replace.
Neither is emitted by zonegen. Add them when something needs them.

### Warn when a replace actually clobbers

Opt-in has one weakness: the default stays silently surprising. Someone who
writes a second `zones:` file *without* `merge: true` still loses their zones
and is told nothing.

So: **when a non-merge include replaces a non-empty allowlisted key, log a
WARN** naming the key, both files, and `merge: true`.

Behaviour is unchanged — the replace still happens — but the silent clobber
that started this whole conversation becomes loud for everybody, including
operators who never opt in. This is the part that makes opt-in a complete
answer rather than a narrow one.

## Duplicates

### What YAML already catches

`gopkg.in/yaml.v3` **rejects duplicate map keys** — verified, not assumed. So
two policies named `alpha` in one file is already a parse error today. The same
holds for any map-shaped collection.

The gap is only **list-shaped** collections. Two `zones:` entries with the same
`name:` are distinct YAML items; the parser has no opinion, and neither does
tdns:

`ParseZones` has no duplicate-name check at all. Two entries named
`example.com.` in a single `zones:` block is silently last-wins today.

### The rule

| Object | On duplicate |
|---|---|
| zone | `zd.SetError(ConfigError, ...)`. Neither definition is served; every other zone is untouched. |
| template | Unchanged: `buildTemplateMap` returns an error and the config is refused. See below. |
| DNSSEC policy | Within a file: already a YAML parse error. Across merged files: marked rejected via the existing `DnssecPolicy.Error` path. |

Neither definition wins when a name collides. Picking one arbitrarily is how a
zone ends up signed by a policy nobody wrote down.

Detection runs on the **merged result**, not inside the merge — one code path,
and it catches the single-file case too.

Per review S4, the zone check must be a **pre-pass over `conf.Zones` before the
`ParseZones` body runs**. That loop get-or-creates `ZoneData`, mutates it and
enqueues a refresh, so checking inline would leave the first definition already
live and possibly queued twice.

### Templates keep the hard error

The first draft softened duplicate templates to per-zone quarantine. On review,
that was the wrong call and it is reverted.

The motivating argument — a host serving 100 000 zones should not refuse to
start because one trivial zone names a broken template — is sound, but it is
about **a zone referencing a bad template**, which is already handled that way
(`zd.SetError` on template expansion failure). A **template defined twice** is a
different thing: an ambiguity in a definition every referencing zone depends
on, detectable before anything is served. Fail-closed is right, it is what the
code does today, and changing it is a separate decision with its own
justification rather than something include-merge needs.

## Provenance

The merge discards which file a key came from. Fine while the rule is "last one
wins"; not fine once collisions are reportable, because every error this design
produces is *"X is defined twice"* and the useful half is **where**.

The merge must therefore carry, per allowlisted item, its originating file —
for those paths only, not the whole config. Concat order is: including file
first, then each include in list order, nested leaves first. Provenance is the
leaf path.

Per review S6: if two files disagree about a key's **type** (`zones:` a list in
one, a map in another) that is a hard error, never a silent fallback to
replace.

## Why opt-in rather than default-on

The first draft made merging the default. The review's objection, which holds:

The failure being fixed is *"I included a file that contributes zones and lost
the ones I had."* The failure default-on would introduce is the inverse — *"I
included a file that was clobbering, deliberately or accidentally, and after an
upgrade I started serving both."* Extra zones, extra signing, extra notify
targets.

And that second failure lands on paths nobody is watching.
`processConfigFile` has six call sites; four are runtime reloads:

```
ParseConfig(reload bool)      reloadTemplatesFromFile()
reloadDnssecFromFile()        reloadZonesFromFile()
reloadTsigKeysFromFile()      checkReloadPolicyGuardrail()
```

`ReloadZoneConfig` runs from the SIGHUP watcher. A default-on change to merge
semantics would take effect there, unattended, on a running server.

There is even a documented instance of the accident it would revive:
`CheckDynamicConfigFileIncluded` exists because operators `include:` the
dynamic-zones file. Under default-on, such a config would start serving the
static zones it had been silently dropping — while `ParseZones` also degraded
the dynamic ones.

Opt-in removes that entire class. Existing includes keep the semantics they
were written against; new behaviour requires asking for it.

## What does not change

- Any config that does not use `merge: true`. Behaviour is identical, with one
  addition: a WARN when a replace clobbers an allowlisted key.
- Any path not on the allowlist, opted in or not.

The first draft claimed single-file configs were untouched. **That was wrong**,
and the review was right to catch it: duplicate-zone detection changes
single-file behaviour, with no `include:` anywhere. A config with an accidental
duplicate zone name today serves one of them; afterwards it serves neither.
That is a deliberate change, listed as a risk below, not a side effect to hide
in a compatibility section.

## Risk

| ID | Risk | Severity |
|---|---|---|
| R1 | A config with an accidental duplicate zone name loses that zone. Today: last-wins, served. After: quarantined, not served. An upgrade can take a zone off the air. | **High** — the one real hazard left. Mitigated by shipping reporting first. |
| R2 | The merge runs on four reload paths including SIGHUP, so a bug lands on a running server, not at a start where it is obvious. | High. Drives tests-first. |
| R3 | Configs relying on last-wins across includes start serving both. | **Eliminated by opt-in.** Was the dominant risk in the first draft. |
| R4 | Template hard error softened. | **Eliminated** — no longer part of this work. |
| R5 | `dnssec.policies` stops being replaceable wholesale. | Low, and only for an include that opted in. |
| R6 | `LoadRawConfigMap` signature changes for provenance. In-tree: `config check` plus six call sites. Out of tree: breaks at next repin, loudly. | Low. |
| R7 | List order becomes include-order dependent for merged includes. Should not matter; wants checking anywhere a lookup takes first-match. | Low. |
| R8 | The legacy `tdns/` tree keeps its own `processConfigFile` and old semantics, so `reporter` and `scanner` in tdns-apps diverge. | Low, consistent with delete-don't-patch. |
| R9 | `split_algorithms` union widens accepted KSK/ZSK pairings. | Low; documented, opt-in only. |
| R10 | The `config check` fix changes what check reports for configs that are *already* inconsistent — some will start failing a check they used to pass. That is the bug being fixed, and it will look like a regression. | Medium. Needs saying in the release note. |

### Sequencing

1. **Fix the `config check` / daemon divergence.** Standalone bug, needed
   before any reporting can be trusted.
2. **Duplicate reporting in `config check`.** Read-only. Lets operators find
   accidental duplicates before anything enforces them.
3. **Enforcement and opt-in merge.** After operators have had a release to
   clean up.

## Extent

| Work | LOC | Notes |
|---|---|---|
| `config check` uses the daemon loader (prerequisite) | ~20 | `LoadRawConfigMap` + `viper.MergeConfigMap`; downstream checks unchanged. |
| Opt-in include syntax | ~40 | Include entries become string-or-map. |
| Merge strategies + allowlist | 90–120 | New file: path table, three strategies, dispatcher. |
| Warn on clobbering replace | ~25 | Needs the allowlist and provenance already present. |
| Provenance threading | 40–60 | Plus ~15 lines of mechanical signature updates across six call sites. |
| Duplicate detection: zones | ~40 | Pre-pass before `ParseZones` mutates or enqueues (S4), not the ~20 first estimated. |
| Duplicate detection: policies (cross-file) | ~15 | Existing rejected-policy path. |
| Duplicate detection: templates | 0 | Already a hard error. |
| `CheckDynamicConfigFileIncluded` rewrite | ~10 | Comment and message; the check stays. |
| **Production subtotal** | **270–330** | |
| Tests | 400–550 | Below. Includes the first tests this path has ever had. |
| **Total** | **~670–880** | |

Roughly the first draft's estimate, differently distributed: opt-in and the
prerequisite fix add work, dropping the template change and having yaml handle
single-file policy duplicates removes some.

## Testing

There are **no tests for the include merge today**, on the config path of every
tdns app, four of whose call sites are live reloads. That ordering is the
point: tests first.

1. Each allowlisted key merging across two files — one per strategy.
2. Non-allowlisted keys still replacing even when opted in — specifically
   `dnsengine.addresses`, the case the allowlist exists for.
3. A bare-string include still replacing, and emitting the clobber WARN.
4. Duplicate detection per object kind, including the single-file case with no
   `include:` at all.
5. Provenance: the error names both files; nested includes name the leaf.
6. YAML type mismatch across files is a hard error.
7. **`config check` and the daemon agree** — the same config through both, same
   resulting zones and policies. This is the regression test for the
   prerequisite bug, and it should have existed already.
8. SIGHUP reload of a two-file merged `zones:`.
9. The dynamic-zones file still in `include:`, still warned about.
10. Real `tdns-zonegen` output included with `merge: true` into a config that
    already has `zones:` and `dnssec:` — the case that motivated all of this.

## Not in scope

- Letting an included file *remove* something.
- Reversing "included file wins" for non-allowlisted keys. Surprising, but
  changing it alters behaviour for configs that work today, with no forcing
  reason.
- User-widenable allowlists. It is a property of the schema; the listen-address
  argument applies to whoever writes the config too.
- Softening the duplicate-template hard error. Separate decision, own
  justification.

## Review outcomes

From [the review](2026-08-27-config-include-merge-review.md), with what
checking each claim produced:

| Finding | Outcome |
|---|---|
| S1 — "single-file configs unaffected" is false | **Accepted.** The draft contradicted itself. Now stated as a deliberate change with a risk entry. |
| S2 — R3 is the production hazard, live on SIGHUP | **Accepted**, and it drove the move to opt-in, which removes R3 entirely. |
| S3 — `config check` decodes through viper | **Accepted and stronger than stated.** They already disagree today: measured `[beta]` vs `[alpha beta]`. Promoted to a prerequisite bug fix with its own regression test. |
| S4 — zone duplicate handling is not ~20 lines | **Accepted.** Now a documented pre-pass, re-costed to ~40. |
| S5 — yaml.v3 last-wins on duplicate map keys | **Refuted.** yaml.v3 *rejects* them, verified. Single-file policy duplicates are already a parse error; the gap is only list-shaped collections. |
| S6 — type mismatch unspecified | **Accepted.** Hard error, specified. |
| S7 — `split_algorithms` union is a widening | **Accepted.** Documented as a widening rather than "the same fact twice". |
| Recommendation: opt-in | **Accepted**, plus the clobber WARN, so operators who never opt in still stop losing zones silently. |
| Recommendation: do not bundle the template change | **Accepted.** Reverted to the hard error. |
