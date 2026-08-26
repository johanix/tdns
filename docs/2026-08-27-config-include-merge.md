# Merging `include:`d config instead of replacing it

2026-08-27

## The problem

`include:` cannot be used to contribute *more* of something the main config
already has. A generator that emits `zones:` and `dnssec:` blocks produces a
file that is correct, complete, and unusable as an include — pulling it in
silently removes every zone the server had.

The concrete case: `tdns-zonegen` generates a tree of test zones and writes the
tdns-auth blocks they need. That output has to be merged into the server config
by hand, extracting the contents of each block and pasting them into the
existing one. The tool even prints a warning telling the operator *not* to
`include:` the file it just wrote, which is a poor thing for a generator to have
to say.

The same shape appears whenever config is assembled from more than one source:
a per-host file plus a shared one, a generated file plus a hand-written one.

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

Two consequences, and they differ by key:

- **`zones:` and `templates:` are lists.** They fall through to the last line
  and are replaced outright.
- **`dnssec:` is a map, so it merges — but one level only.** Each *sub-key* is
  copied wholesale, so an included `dnssec.policies` replaces the main config's
  `dnssec.policies` entirely, while `dnssec.completeness` next to it survives.

Worth noting because it surprises people: the **included** file wins over the
including one. Most config systems are the other way round.

This is not mapstructure. The merge is over raw YAML maps; mapstructure only
decodes the already-merged result into structs, and cannot see that two files
were involved.

## What changes

An **allowlist** of config paths that merge instead of replace. Everything not
listed keeps today's behaviour exactly.

| Path | Kind | Strategy |
|---|---|---|
| `zones` | list of named maps | concatenate; duplicate `name` is an error |
| `templates` | list of named maps | concatenate; duplicate `name` is an error |
| `dnssec.policies` | map of named maps | merge by policy name; duplicate name is an error |
| `dnssec.large_algorithms` | list of strings | union (set semantics) |
| `dnssec.split_algorithms` | map of string lists | merge by KSK name, union the ZSK lists |

Three different strategies for five keys, because they are three different
kinds of thing:

- **Collections of named objects** (`zones`, `templates`, `dnssec.policies`).
  Two definitions of the same name is a conflict, not something to merge — deep
  merging two zone definitions would produce a zone neither file describes.
- **Sets** (`large_algorithms`). Two files listing the same algorithm is not a
  conflict; it is the same fact stated twice. Union, deduplicate, done.
- **Maps of sets** (`split_algorithms`). Merge at the KSK level, union at the
  leaf. Two files both allowing `MLDSA87` to pair with different ZSKs should
  end up allowing both.

### Why an allowlist and not "merge everything"

Because these are lists too:

```
dnsengine.addresses      apiserver.addresses      dnsengine.transports
```

Concatenating those would silently make the server listen on more addresses
than the file in front of you says. That is the same class of failure as
silently widening an ACL, and worse than the clobber being fixed here: a
clobber is at least visible in what the server ends up running.

The allowlist is also what keeps this change strictly additive. No existing
deployment changes behaviour unless it uses one of the five keys in more than
one file — which today it cannot do usefully anyway.

## Provenance

The merge currently discards which file a key came from. That is fine while the
rule is "last one wins", and not fine once the rule is "these combine", because
every error this design can produce is of the form *"X is defined twice"* — and
the useful half of that sentence is **where**.

So the merge needs to carry, for each allowlisted item, the file it came from.
Not for the whole config — only for the paths that can now collide.

This matters most for `config check`, which is the one place that can report a
collision *before* a restart. It already calls `LoadRawConfigMap`, the same
function that does the merge, so it sits in exactly the right place. By the
time `ParseZones` runs, the maps are merged and provenance is gone.

## Duplicates

The rule: **nothing at config level is fatal. The affected zones are
quarantined; everything else keeps serving.**

That is already how tdns treats a zone whose template expansion fails, and how
it treats a zone bound to an unusable policy. Extending it here means a
duplicate definition never takes down a server — which matters exactly in
proportion to how much the server is carrying. A host serving 100 000 zones
should not stop because a trivial zone's template was defined twice.

| Object | On duplicate |
|---|---|
| zone | `zd.SetError(ConfigError, ...)` on that zone. It stops being served; every other zone is untouched. |
| template | The template is marked unusable. Every zone referencing it gets `zd.SetError(ConfigError, "references duplicated template %q")`. A duplicated template nobody uses is a WARN and nothing more. |
| DNSSEC policy | The policy is marked rejected, reusing the existing `DnssecPolicy.Error` path. Zones bound to it fail through the existing unusable-policy route. |

Neither definition wins when a name collides. Picking one arbitrarily is how
you get a zone signed by a policy nobody wrote down.

### This is a behaviour change for templates

Today a duplicate template name is a hard error that refuses the whole config:

```go
if _, exists := Templates[tmpl.Name]; exists {
    return fmt.Errorf("duplicate template name: %s", tmpl.Name)
}
```

That becomes a per-template rejection with per-zone quarantine. Strictly more
available, and `config check` reports it before a restart either way.

### And it closes a hole that exists today

`ParseZones` does not check for duplicate zone names at all. Two entries named
`example.com.` in a single `zones:` block is currently last-wins, silently.

So duplicate detection belongs on the **merged result**, not inside the merge:
one code path, and it catches the single-file case that is already broken.
Concatenation would otherwise make that hole easier to fall into.

## What does not change

- Any config path not in the allowlist. Same replace-or-shallow-merge as today.
- Single-file configs. Nothing here can affect a config with no `include:`.
- The order dependence for non-allowlisted keys (included file still wins).

## Compatibility

`CheckDynamicConfigFileIncluded` warns an operator who has `include:`d the
dynamic-zones file, and its message asserts the current semantics:

> the include merge OVERRIDES list-valued keys, so a dynamic file carrying
> `zones:` clobbers the `zones:` of any other config file

Once `zones:` concatenates, that sentence is wrong — but the *warning* is still
right, for its other reason: including that file routes dynamic zones through
`ParseZones`, which loses their ApiManaged/SourceCatalog markers and degrades
them to looking static. The check stays; the justification needs rewriting.

## Testing

There are **no tests for the include merge today**. Given this is the config
path for every tdns app, that is the part of this work with the worst
effort-to-risk ratio, and it comes first:

1. Each allowlisted key merging across two files, one test per strategy.
2. Non-allowlisted keys still replacing — specifically `dnsengine.addresses`,
   as the case the allowlist exists to protect.
3. Duplicate detection for each of the three object kinds, including the
   single-file case that has no include at all.
4. Provenance: the error names both files.
5. Nested includes, since `processConfigFile` recurses to depth 10.
6. A round trip of real `tdns-zonegen` output `include:`d into a config that
   already has `zones:` and `dnssec:` — the case that motivated this.

## Not in scope

- Letting an included file *remove* something. There is no need yet, and the
  syntax for it in YAML is uniformly ugly.
- Reversing the "included file wins" order for non-allowlisted keys. It is
  surprising, but changing it now would alter behaviour for configs that
  currently work, with no forcing reason.
- Merging arbitrary user-chosen paths via config. The allowlist is a property
  of the schema, not something a deployment should be able to widen — the
  listen-address argument applies to whoever writes the config too.
