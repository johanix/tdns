# ZONEMD gate rig — tdns vs Knot

RFC 8976 as a **gate in the transfer chain**: does a server refuse a zone
whose ZONEMD does not describe it? Offline checking of a zone file says
nothing about that, and the gate is the only thing that makes ZONEMD
depended-upon rather than decorative.

tdns and Knot are the two references. NSD has no ZONEMD (its generic
`verifier:` hook could be pointed at an external checker, but that is a
different mechanism); BIND 9.20 has none at all.

## Running

```
./setup.sh
./run.sh start
./run.sh verify     # 11 assertions; non-zero exit on failure
./run.sh stop
```

No TLS is involved — ZONEMD is orthogonal to transport, so everything is
Do53. Requires `tdns-auth`, `tdns-agent`, `tdns-cli` from `cmdv2/` and a Knot
build tree.

| Daemon | Port | Role |
|---|---|---|
| tdns-auth | 5311 | primary; publishes a real digest for one zone and serves deliberately broken ones for the rest |
| tdns-agent | 5312 | secondary with `verify-zonemd` on every zone |
| knotd | 5315 | secondary with `zonemd-verify: on`; also primary for the zone whose digest **Knot** generates |

## The zones

| Zone | What it carries | Purpose |
|---|---|---|
| `good` | digest tdns computed (`publish-zonemd`, SHA-384 + SHA-512) | both gates must accept |
| `bad` | a hand-written wrong digest, `publish-zonemd` **off** so tdns serves it untouched | both gates must refuse — this is the gate itself |
| `warn` | the same wrong digest | consumer runs `on-verify-failure: warn`: adopt and complain |
| `knotgen` | digest **Knot** generated (`zonemd-generate: zonemd-sha384`) | cross-implementation: tdns verifying Knot's arithmetic |
| `none` | no ZONEMD at all | a gate that passes this is bypassed by stripping the record |
| `unsup` | a ZONEMD using private-use algorithm 240 | present but uncheckable: looks verified, is not |
| `tmpl` | wrong digest; consumer inherits its whole `zonemd:` block from a template | the block templates at all |
| `tmplpart` | wrong digest; consumer sets `zonemd.algorithms` itself | the block templates **per field**, so naming one field does not drop the rest |

## Templating

`zonemd:` is a per-zone block; there is no server-level ZONEMD setting in
tdns. Fleet-wide policy is expressed through a template, which zones name with
`template:` (tdns has no implicit `default` template, unlike Knot, where a
template of that name applies to every zone that names no other).

The `tmpl` / `tmplpart` pair pins the merge rule. Templating the block worked
already; what did not was a zone setting **one** field of it — under the
whole-block copy `ExpandTemplate` applies to every other nested config field,
that dropped the template's remaining fields silently. Fixed in
`v2/parseconfig.go` by merging `Zonemd` field by field, with
`TestZonemdBlockMergesFieldByFieldWithItsTemplate` in `v2/zonemd_config_test.go`
as the regression test.

It matters more the moment per-verdict policy exists: `on-verify-failure`
defaults to `refuse`, so losing it fails safe, but an `on-absent:` whose
default is `adopt` would have failed **open** — a fleet-wide "refuse zones
with no ZONEMD" quietly undone by a zone that mentioned `algorithms`.

## What it found (2026-08-25)

The two implementations agree wherever a digest exists and can be checked,
and **diverge on both cases where nothing can be checked**:

| | tdns `verify-zonemd` | Knot `zonemd-verify: on` |
|---|---|---|
| valid digest | accept | accept |
| wrong digest | refuse | refuse |
| **no ZONEMD** | **accept** | refuse (`verification failed (not exists)`) |
| **uncheckable algorithm** | **accept** (logs WARN) | refuse |

tdns's position is deliberate and argued in `v2/zonemd_verify.go`: the option
says "check the digest if there is one", and making it also mean "and require
one" would be a policy about the upstream's configuration rather than about
this zone's integrity. That is coherent — but it means `verify-zonemd` alone
cannot be depended on in the transfer chain, because an upstream that stops
publishing ZONEMD, or publishes one in an algorithm this build does not
implement, is adopted. Of the two, only the uncheckable-algorithm case logs at
`Warn` (`zonemd_verify.go:397`); the absent case logs at `Debug` (`:389`), so
at ordinary log levels it is silent.

The `verify` assertions encode this behaviour as it stands rather than as it
arguably should be, so that changing it shows up as a failing assertion and a
deliberate edit here.

Discussed remedy (not implemented): per-verdict policy in the existing
`zonemd:` block — `on-absent:` and `on-unsupported:` alongside today's
`on-verify-failure:`, all taking `warn`/`refuse`, with an `enforce-zonemd`
shorthand setting all three to `refuse`. The code already distinguishes the
four verdicts (`ZonemdAbsent`, `ZonemdValid`, `ZonemdInvalid`,
`ZonemdUnsupported`), so the policy surface would follow a split that exists.
