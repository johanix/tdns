# Re-review: merging `include:`d config (opt-in revision)

2026-08-27

**Plan:** [`2026-08-27-config-include-merge.md`](2026-08-27-config-include-merge.md)
(revised after [`2026-08-27-config-include-merge-review.md`](2026-08-27-config-include-merge-review.md))

Same code as the first review, plus a live check of yaml.v3 duplicate-key
behaviour.

## Verdict

**Safe to implement.** The revision took the recommendations that mattered:
opt-in per include (R3 gone), template duplicates stay a hard error (R4 gone),
the “single-file unaffected” claim is now an honest R1, and the `config check`
/ daemon split is promoted to a prerequisite bug rather than a costing footnote.

The leftover items are spec nits and one implementation pitfall. None of them
re-open the “default-on concat on SIGHUP” problem.

| | |
|---|---|
| Safe to ship as written | Yes, after the nits below are written into the plan |
| Dominant remaining risk | R1 (single-file duplicate zone quarantine), mitigated by reporting-first |
| First review S5 | Retracted — yaml.v3 does reject duplicate map keys; the plan was right |

## What the revision got right

Every accepted finding from the first review is actually in the text, not just
ticked in the outcomes table.

- **Opt-in** is the default-preserving form: a bare string include is still
  replace. Zonegen documents `merge: true` instead of “do not include this”.
- **Clobber WARN** on a non-merge replace of a non-empty allowlisted key is
  new, and it is the right companion to opt-in. Operators who never opt in
  still stop losing zones silently. The warn names the remedy.
- **Allowlist still binds opted-in includes**, so `dnsengine.addresses` cannot
  be concatenated by asking. The known gaps (`dnssec.templates`, `keys.tsig`)
  are listed as add-when-needed, not forgotten.
- **`split_algorithms` union is called a widening**, not “the same fact twice”.
- **Templates stay fail-closed.** The 100k-zone argument is correctly scoped to
  a zone *referencing* a bad template (already quarantined), not to a template
  *defined twice*.
- **Zone duplicate check is a pre-pass** before `ParseZones` mutates `ZoneData`
  or enqueues refresh.
- **Sequencing** (fix check/daemon, then report duplicates, then enforce +
  opt-in) is the right order for R1.
- **S5 refutation holds.** `yaml.Unmarshal` into `map[string]interface{}` with
  yaml.v3 (uniqueKeys default true) errors `mapping key "alpha" already defined`.
  The first review was wrong about last-wins on map keys. Single-file policy
  duplicates are already a parse error; the remaining gap is list-shaped
  collections only.

The measured check/daemon disagreement (`dnssec.policies` = `[beta]` in the
daemon, `[alpha beta]` in check) is real: viper deep-merges maps, the daemon
replaces nested maps at one level. `ValidateConfig` already uses
`decodeConfigFile`; `checkDnssecPolicies` / `checkZones` still use the viper
view. That is why check can green-light a policy the daemon never loaded.

## First-review findings, this pass

| ID | First-review claim | This pass |
|---|---|---|
| S1 | “Single-file unaffected” is false | **Closed.** Stated as a deliberate change; R1. |
| S2 | R3 live on SIGHUP | **Closed.** Opt-in removes it. Dynamic-zones include stays a warn, not a behaviour change. |
| S3 | check decodes collections through viper | **Closed as a finding, opened as a prerequisite.** Stronger than stated, correctly sequenced first. |
| S4 | Duplicate handling is not ~20 lines | **Closed.** Pre-pass, re-costed ~40. |
| S5 | yaml.v3 last-wins on duplicate map keys | **Retracted.** Plan was right; first review was not. |
| S6 | Type mismatch unspecified | **Closed.** Hard error. |
| S7 | `split_algorithms` is a widening | **Closed.** Documented, opt-in only, R9. |
| Opt-in | Preferred alternative | **Adopted**, plus the clobber WARN. |
| Do not soften templates | Keep the hard error | **Adopted.** |

## Remaining nits

None of these are reasons to go back to default-on merge. They are things the
plan should say before the code is written, because they are cheap to specify
and expensive to discover in a reload test.

### N1. Step 2 only sees single-file duplicates

Cross-file collisions do not exist until `merge: true` concatenates. Today a
replace include *removes* the earlier list, so check cannot report
“defined in A and B”. Step 2 is the R1 mitigator (accidental duplicate in one
`zones:` block). Merge-time collisions are caught in step 3 by running
`config check` after writing `merge: true` and before SIGHUP.

Say that in Sequencing, so step 2 is not mistaken for coverage of the zonegen
case.

### N2. Duplicate pre-pass must use `dns.Fqdn`

`ParseZones` does `zname := dns.Fqdn(zconf.Name)` before anything else. Two
entries `example.com` and `example.com.` are the same zone today (last-wins on
one `ZoneData`). The pre-pass has to compare FQDNs or it will miss the case
the body would treat as one zone. `config check` reporting in step 2 needs the
same rule; decoded `Config.Zones` has not been FQDN’d yet.

### N3. Allowlisted paths are dotted; the hook is the inner assignment

`dnssec.policies` is not a top-level key. Today the outer loop sees `dnssec`
as two maps and the *inner* loop does `existingMap["policies"] = v2`. If
`merge: true` only special-cases top-level keys, policies still replace and
the zonegen case does not work.

The dispatcher has to intercept **every** allowlisted path as it is assigned,
including nested ones under the existing one-level map merge. Other `dnssec:`
subkeys (`completeness`, `kasp`, `templates`, `dnskey_query_transport`) keep
included-wins.

### N4. Replace after merge wipes the concat

```yaml
include:
  - file: zonegen-auth.yaml
    merge: true
  - other-zones.yaml          # replace
```

Result is only `other-zones.yaml`. That is consistent with “bare string =
replace”, and the clobber WARN should fire because a non-empty allowlisted key
is being replaced. Add this as a test; it is the mixed-list footgun.

Also specify the trivial map form: `file: x.yaml` with no `merge` (or
`merge: false`) is replace, same as a bare string. Unknown keys in the map,
or `merge: true` without `file:`, are hard errors.

### N5. Other include parsers will not understand the map form

`processConfigFile` is the daemon. These still do `GetStringSlice("include")`
and expect strings:

- `cmdv2/cli/root.go` (CLI initConfig)
- `cmdv2/debug/root.go`
- `v2/cli/cert_init_cmds.go`

A map entry will not come out as a path. Most of those loops treat a
non-existent path as skip, so they will **silently ignore** `merge: true`
includes. That is acceptable for CLI overlay (algorithms.yaml, API settings)
provided `ValidateConfig` / `decodeConfigFile` is what answers “would the
daemon start”. It is not acceptable for `config check` — and the prerequisite
fix addresses that one.

Do not teach the CLI shim to stringify the map; that would `stat` a garbage
path. Either leave it skipping, or point those loaders at `LoadRawConfigMap`
too. Worth a sentence under What does not change.

Today, non-string include entries are already silently skipped by
`processConfigFile` (`inc.(string)` fails). After this work they become
meaningful. Unlikely anyone has a map-shaped include already; still a
behaviour change for that shape.

### N6. Prerequisite fix is slightly more than the snippet

`viper.MergeConfigMap` of an empty viper with the daemon’s already-merged map
is the right idea for `checkZones` / `checkDnssecPolicies`. Two extra
consequences, both alignments with the daemon, both worth a line in R10:

- **Nested includes** start being visible to those checks (viper was
  single-level; `processConfigFile` recurses to 10).
- **Missing includes** fail at load rather than WARN-and-continue. They
  already fail later via `ValidateConfig` → `decodeConfigFile`; the WARN from
  `loadConfigViper` is the misleading extra.

`processConfigFile` deletes `include:` from the result map. After the switch,
`v.GetStringSlice("include")` is empty. That is fine if load no longer
iterates it.

### N7. Provenance is born at the leaf

Concat order (including file, then includes in list order, nested leaves
first) is specified. Implementation constraint: provenance has to be attached
when an allowlisted item is *read from a file*, and carried through recursive
`processConfigFile`, not stamped when the parent merges the child’s already-
flattened map. Otherwise a nested include is blamed on the intermediate file.

## What I would not change

- Opt-in over default-on. Still the correct call.
- Keeping template duplicates fatal.
- Shipping the check/daemon fix first, as its own change, with the
  `[alpha]/[beta]` regression test.
- Clobber WARN as part of step 3 (so the message can name `merge: true` as a
  real remedy, not a future one).
- Not widening the allowlist to `dnssec.templates` / `keys.tsig` until
  something needs them.

## Suggested deltas to the plan (short)

1. Sequencing: step 2 is single-file duplicates only; merge collisions are
   step 3 + `config check` before reload.
2. Pre-pass and check reporting compare `dns.Fqdn` names.
3. Allowlist dispatcher hooks nested assignments (`dnssec.policies`), not
   only top-level keys.
4. Test: merge include followed by a bare-string include; result is replace;
   clobber WARN fires.
5. Map-form include: missing `merge` = replace; unknown keys / missing
   `file` = hard error.
6. One sentence: CLI/debug/cert-init include shims keep expecting strings and
   will skip map entries.
7. Provenance threaded from the leaf file through recursive process.

After those, implement in the sequenced order. Tests still first on the merge
path itself.

Checked against: revised plan, yaml.v3 `uniqueKeys` default, `v2/parseconfig.go`,
`v2/config_validate.go` (`ValidateConfig` already uses `decodeConfigFile`),
`v2/cli/config_check_cmds.go`, `cmdv2/cli/root.go`.
