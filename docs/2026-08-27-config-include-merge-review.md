# Review: merging `include:`d config instead of replacing it

2026-08-27

**Plan under review:** [`2026-08-27-config-include-merge.md`](2026-08-27-config-include-merge.md)

Checked against `processConfigFile`, `ParseZones`, `ReloadZoneConfig`,
`config check`, and `tdns-zonegen` emit.

## Verdict

The allowlist, the three merge strategies, tests-first, and provenance for
collisions are the right shape. **It is not safe to ship as one default-on
behaviour change.**

The plan bundles a single-file semantics change while claiming single-file
configs are untouched, and default concatenation of `zones:` revives
accidentally-clobbered zones — including the documented dynamic-zones include
footgun — on a SIGHUP path nobody is watching.

| | |
|---|---|
| Safe to ship as written | Conditional |
| Better alternative | Opt-in merge, same allowlist |
| Risks that dominate | R3 (revived zones) and R1 (duplicate quarantine) |

## What the plan gets right

Today `include:` cannot contribute *more* of something the main file already
has. Lists replace; maps merge one level, so `dnssec.policies` is replaced
wholesale while `dnssec.completeness` beside it survives. The included file
wins. That matches `processConfigFile` in `v2/parseconfig.go`. Zonegen emits a
complete `dnssec:` plus `zones:` block and has to warn the operator not to
include it.

| Claim | Code |
|---|---|
| Lists replace; maps shallow-merge one level | Confirmed. The 15-line merge loop does exactly this. |
| `dnssec.policies` is a nested map, so it replaces | Confirmed. `dnssec` is the map; `policies` is a sub-key copied wholesale. |
| `peers:` already merges (top-level map) | True, and unstated. Top-level maps already combine; nested maps do not. |
| `ParseZones` has no duplicate zone-name check | Confirmed. Two entries with the same name are last-wins on the same `ZoneData`. |
| Duplicate template name is a hard `ParseConfig` error | Confirmed. `buildTemplateMap` error is returned; startup refuses the config. |
| Allowlist excludes listen addresses | Correct. Concatenating `dnsengine.addresses` / `apiserver.addresses` would silently widen listeners. |
| Zonegen emits exactly four of the five keys | `large-algorithms`, `split-algorithms`, `policies`, `zones`. `templates` is the generalization. |
| Reload uses the same merge | Confirmed. Four runtime re-reads call `processConfigFile`, including SIGHUP `ReloadZoneConfig`. |

## Safety findings

The plan’s R1–R8 are real. The rows below are either stronger than the plan
states, or missing from it.

| ID | Finding | Why it matters |
|---|---|---|
| S1 | “Single-file configs are unaffected” is false | Duplicate-zone quarantine and template hard→soft fire with no `include:` at all. That is a different change, packaged as include-merge. |
| S2 | R3 is the production hazard, and it is live on SIGHUP | Two `zones:` files in `include:` currently keep only the last. Afterwards both are served. `CheckDynamicConfigFileIncluded` exists because people include the dynamic-zones file; that config would start serving the static zones it was silently dropping, and `ParseZones` would also degrade the dynamic ones. `ReloadZoneConfig` will apply this without anyone watching. |
| S3 | `config check` still decodes collections through viper | `LoadRawConfigMap` is used only for alias/case scans. Zones and policies are unmarshalled from `viper.MergeInConfig`, which still replaces lists and is single-level. After daemon concat, `checkZones` / `checkDnssecPolicies` would see a different set than the process. The “40–60 LOC presentation” estimate does not cover switching the typed decode. |
| S4 | `ParseZones` duplicate handling is not ~20 lines if “neither wins” | The loop get-or-creates `ZoneData`, mutates it, and queues refresh. A second same-name entry overwrites the first and may queue twice. Rejecting both needs a pre-pass before any enqueue, or the first definition is already live. |
| S5 | Policy duplicates in one file are undetectable after `yaml.Unmarshal` | `policies` is a YAML map. `gopkg.in/yaml.v3` last-wins on duplicate keys before merge runs. “Single-file duplicate detection for all three kinds” only works for list-shaped objects (`zones`, `templates`). |
| S6 | Type mismatch is unspecified | If one file has `zones:` as a list and another as a map, today’s code replaces. After concat, a type-assert failure must be a hard error, not a silent fallback to replace. |
| S7 | `split-algorithms` union is a silent widening of crypto policy | Same class as concatenating listen addresses, lower blast radius: it only gates policy parse. For zonegen it is the right direction. Treat it as a documented widening, not as “the same fact stated twice”. |

### The two decisions in the plan

**Reporting before enforcement — do this.** Given R1, landing `config check`
duplicate reporting first is the correct sequence — but only if check decodes
through the daemon loader. Reporting from viper would miss the collisions the
daemon will enforce.

**R3 migration note — required.** Anyone with two `zones:`-bearing includes is
currently losing zones silently. They will gain them back on the next start or
SIGHUP. That is “correct” and still a surprise outage in the other direction:
extra zones, extra signing, extra notify targets.

## What not to bundle

The write-up treats three independent changes as one “additive” include-merge:

| Change | Needed for include-merge? | Recommendation |
|---|---|---|
| A. Allowlisted concat/union/merge-by-name | Yes — this is the feature. | Ship, preferably opt-in (see alternatives). |
| B. Duplicate zone-name detection + quarantine | Yes if concatenating. Otherwise last-wins gets worse (two entries processed). | Ship with A, but report in `config check` first. This does change single-file configs; say so. |
| C. Template duplicate: hard error → quarantine | No. After concat, `buildTemplateMap` already refuses the whole config. That is fail-closed and fine for v1. | Do not bundle. Softening loses the “it will not start if I got this wrong” gate (R4) for no include-merge reason. |

**Allowlist gap, not a blocker.** `dnssec.templates` is a map of named objects
nested under `dnssec:`, same shape as `dnssec.policies`, and is not on the
allowlist. Zonegen does not emit it, so the motivating case is fine. If a later
file carries policy templates, they still replace. `keys.tsig` is a list of
named objects and would still replace; also not needed for zonegen.

## Alternatives

Ranked. The plan’s “merge everything” rejection is correct; that row is here
only to keep it off the table.

| Rank | Approach | Safety | Fits zonegen? | Cost |
|---|---|---|---|---|
| 1 | Opt-in merge include, same allowlist | Strictly additive. No R3. Existing includes keep replace. | Yes: one documented include line. | Small parser change: include entries stay strings (replace) or become `{file, merge: true}`. Allowlist still refuses merging addresses even when opted in. |
| 2 | Plan as specified, split C out, report-first | Safe enough if R3 is documented and check uses the daemon loader. | Yes, and `include:` becomes the obvious thing. | Default-on concat still revives clobbered zones. Requires a migration note and a check that actually sees the merged set. |
| 3 | `tdns-zonegen merge --into <file>` | Safest runtime: daemon unchanged. Operator sees the spliced YAML. | Solves only the generator. Not the general “two sources” case. | A file-rewrite tool, plus a well-defined splice region so regeneration does not eat hand-written zones. |
| 4 | New keys: `include_zones` / `include_dnssec` | Additive, explicit. | Yes, but a second include mechanism to teach. | Schema growth for a problem `include:` already exists to solve. |
| — | Deep-merge every key | Unsafe. Listen addresses, ACLs, transports. | Would work, for the wrong reason. | Correctly rejected by the plan. |

### Why opt-in is the better default

The motivating failure is “I included a file that contributes zones and lost
the ones I already had.” The production failure the plan would introduce is
the inverse: “I included a file that was clobbering on purpose (or by accident)
and on upgrade I started serving both.” There is already a warning for one
instance of that accident — `CheckDynamicConfigFileIncluded`. Making concat
the default turns that warning’s remaining reason (degrading dynamic zones
through `ParseZones`) into a quieter problem next to a louder one: extra zones
appearing on SIGHUP.

Opt-in keeps today’s replace semantics as the default, which is what every
existing include was written against. Zonegen stops saying “do not include this
file” and starts saying “include it with `merge: true`.” The allowlist still
applies, so an operator cannot opt into concatenating `dnsengine.addresses`.

Sketch, not a commitment to syntax:

```yaml
include:
  - auth-templates.yaml          # replace (today)
  - file: zonegen-auth.yaml
    merge: true                  # allowlisted concat
```

## If you keep default-on merge

Then the plan is close. These are the deltas to make before any code:

1. Drop the sentence that single-file configs are unaffected. Duplicate-zone
   quarantine is a single-file behaviour change. Say it in Compatibility.
2. Do not soften template duplicates in this work. Keep the `ParseConfig` hard
   error.
3. Ship `config check` duplicate reporting first, decoding via
   `decodeConfigFile` / `LoadRawConfigMap` — not viper — for zones, templates,
   and dnssec collections.
4. Write the R3 migration note, naming the dynamic-zones include case
   explicitly. Keep the warning; rewrite the justification as the plan says.
5. Specify type-mismatch as a hard error. Specify concat order: including file,
   then each include in list order, nested leaf files first. Provenance is the
   leaf path.
6. Duplicate zone detection is a pre-pass over `conf.Zones` before the
   `ParseZones` body mutates `ZoneData` or enqueues refresh. Neither entry is
   served; both names appear in `brokenZones`.
7. Tests as specified, plus: viper/check vs daemon agreement; SIGHUP reload of
   a two-file zones concat; dynamic-zones file still in `include:`; YAML type
   mismatch; nested include provenance names the leaf.

Checked against: `v2/parseconfig.go`, `v2/config.go` (`ReloadZoneConfig`),
`v2/cli/config_check_cmds.go`, `v2/dynamic_zones.go`,
`tdns-apps.zonegen/cmd/zonegen/emit.go`.
