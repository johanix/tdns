# Review: fold DNS names at the index boundary (#417)

**Date:** 2026-08-28
**PR:** [#417](https://github.com/johanix/tdns/pull/417)
**Branch:** `feature/case-insensitive-names` @ `938f8558`
**Base:** `feature/equalnames-util` ([#416](https://github.com/johanix/tdns/pull/416), `core.EqualNames`) — **not** `main`. Merge #416 first.
**Plan:** [`2026-08-28-case-insensitive-names-scope.md`](2026-08-28-case-insensitive-names-scope.md) (in the PR), stage 1 of 7. Closes [#415](https://github.com/johanix/tdns/issues/415).
**Size:** 37 files, +1028 / −119
**Lens:** map the implementation against stage 1 of the plan. Correctness, completeness, omissions, mistakes, and errors this PR introduces. Later stages are out of scope for the diff and in scope only as the landing context.

This PR is **not intended to merge alone.** It is stage 1 of a series:

| Stage | PR | Area |
|---|---|---|
| 1 | [#417](https://github.com/johanix/tdns/pull/417) (this) | Index boundary |
| 2 | [#419](https://github.com/johanix/tdns/pull/419) | Auth query + update |
| 3 | [#421](https://github.com/johanix/tdns/pull/421) | IMR + cache |
| 4–7 | upcoming | Delegation / keystore / CLI / enforcement |

Findings below are scoped against that landing, not against a hypothetical solo merge onto `main`.

Commits:

1. `8db2a6c3` — docs: scope the case-insensitive name comparison work
2. `938f8558` — Fold DNS names at the index boundary

---

## Verdict

**Approve as stage 1 of the series.** The four named defects are fixed, the index change is structural, and `CanonicalizeName` / `NameMap` are the right primitives. The query-path fallout of dropping the old `FindZone` qname-rewrite is real, and it is **#419's job**, not a change request against this PR.

Do not cherry-pick or deploy #417 onto a running auth server without #419. The series merge does not have that problem.

| | |
|---|---|
| Stage 1 completeness | The four defects, the four indexes, construction-time `zd.ZoneName` fold, `FindZoneNG`, lab-domain debug line, `fold-case` documented inert |
| Index correctness | Sound |
| Introduced query-path error | Real; already scheduled for #419 |
| Action on #417 itself | None required |

| # | Finding | Fix in #417? | Where it belongs |
|---|---------|--------------|------------------|
| 1 | Dropping the qname-rewrite makes `findDelegationFrom` refer mixed-case sub-apex queries to the apex NS | **No** | #419 (auth query + update) |
| 2 | `Conf.Zones[i].Name == zd.ZoneName` misses a mixed-case config name after `ZoneName` is folded | **No** | A later comparison-stage PR (API) |
| 3 | `FindZone` godoc landed on `normalizeZoneName`; `EqualNames` still names `dns.CanonicalName` as the map key | **No** | Optional nit, any PR that touches those comments |

---

## Stage 1 map

The plan asked for: `CanonicalizeName` + a key type; canonical keys for `Zones`, `zd.Data`, the snapshot and the working set; `GetOwner` / `FindZone` / `SortFunc`; `zd.ZoneName` folded at construction; the four confirmed defects.

| Planned item | In #417? |
|---|---|
| `core.CanonicalizeName` (byte-wise, not `dns.CanonicalName`) | Yes. Zero-alloc already-canonical path, non-UTF-8 preserved, agrees with `EqualNames` on 1,119,364 pairs |
| `NameKey` alias | **Replaced by `NameMap`**, which is the better shape: the fold cannot be forgotten at a call site |
| `Zones` → `NameMap` | Yes |
| `zd.Data` → `NameMap` | Yes, every production constructor |
| Snapshot lookups fold | Yes, `getOwnerFrom` / `nameExistsFrom` |
| Working set keyed canonically | Yes at the mutation helpers; still a plain `map[string]*OwnerData` |
| `GetOwner` / `FindZone` / `SortFunc` | Yes. `FindZone` lost the `folded` flag; `SortFunc` uses `dns.IsSubDomain` and no longer folds the stored owner |
| `zd.ZoneName` folded at construction | Yes at ParseZones, refresh, dynamic/catalog/auto-zone paths, plus `normalizeZoneName` on parse and refresh |
| Defects 1–4 | Covered by `v2/name_case_test.go` |
| `FindZoneNG` deleted, `p.axfr.net.` debug gone, `fold-case` documented inert | Yes in v2 (v1 excluded by the written scope boundary) |

`NameMap` only wraps the ConcurrentMap methods `Zones` / `zd.Data` actually use. That is complete, not a missing-API hole.

v1 (`tdns/`, `cmd/`) still has `FindZoneNG` and the lab-domain debug line. That matches the plan's scope boundary, not an oversight.

---

## What is correct

**CanonicalizeName is the right primitive.** ASCII A–Z only, octet-preserving, idempotent. `dns.CanonicalName` really does turn `0xff` into U+FFFD; the differential test against `EqualNames` is the right invariant.

**The index change is structural.** `NameMap` is the right answer to “61 `Zones.Get` sites, most of which forgot to fold.” Keys are canonical; `OwnerData.Name` and RR headers keep the zone-file spelling. AXFR-out and zone-file write iterate snapshot keys (canonical) but emit RR headers (original case), so on-the-wire case is preserved.

**Defect 1 is fixed, and `IsSubDomain` is a bigger win than case.** `strings.HasSuffix("notexample.com.", "example.com.")` is true; `dns.IsSubDomain` is not. The old gate was wrong on label boundary as well as case. Apex is still in-bailiwick (`IsSubDomain` is true for the name itself).

**Defects 2–4 are fixed at the store.** `GetOwner("UPPER.EXAMPLE.COM.")` finds `Upper.example.com.`. Two spellings of one owner merge. A zone declared `Example.COM.` has `zd.ZoneName == "example.com."` and is reachable via `FindZone`.

**`fold-case` as a no-op** is the honest leftover. Keeping the option so existing YAML parses is right.

The addendum in the scope doc is also right about the comparison count: 149 → 148 is the expected result. This PR fixed indexes, not comparisons. Owner-map keys and `zd.ZoneName` being canonical converts a slice of the “latent” class to genuinely safe (operands that came out of an index). What remains is wire- and API-sourced names compared without going through an index — which is the series’ remaining work.

---

## FINDING 1 — Mixed-case queries that used to work now self-refer

**Fix in #417: no. Belongs in #419.**

`DefaultQueryHandler` used to lowercase the qname when `FindZone`’s second pass won. That pass ran whenever the *zone-name part* of the qname did not byte-match the stored key, which is almost every 0x20 query. #417 correctly stopped rewriting, because lookups fold themselves. The raw spelling now reaches `findDelegationFrom`:

```go
if child == zd.ZoneName {
    break // no point in checking above current zone name
}
```

`nameExistsFrom` folds, so the walk sees the apex. The apex has NS. The stop condition does not recognise `EXAMPLE.com.` as `example.com.`, so the apex NS is returned as a child delegation and the server refers the query to itself.

| QNAME vs zone `example.com.` | Before #417 | After #417 alone |
|---|---|---|
| `WWW.example.com.` (the #415 shape) | Zone found, owner missed → NXDOMAIN | Owner found, walk stops at exact apex → **fixed** |
| `WWW.EXAMPLE.com.` / 0x20 | Fold rewrite → lowercase → answer | Walk treats apex NS as a child → **referral to self** |
| Apex `EXAMPLE.com.` A/NS/SOA | Fold rewrite → answer | Same length as `zd.ZoneName`, so the below-apex walk is skipped → still answers |
| Apex AXFR `EXAMPLE.com.` | Fold rewrite → transfer | `qname == zd.ZoneName` fails → **NOTAUTH** |

This is not a leftover comparison that “was always wrong for mixed case” in a way operators would have hit. The old rewrite made the common mixed-case path work. Removing it without converting the walk is a behaviour change on the query path, and 0x20 is how resolvers talk to an auth server.

The same hole sits in `IsChildDelegation` (`qname == zd.ZoneName`), so a mixed-case apex can be classified as a child (it has NS). DS queries for an in-zone name with a mixed zone suffix take `handleDSQuery`’s “grandparent referral” arm for the same reason (`cdd.ChildName == qname` fails, `cdd` is the fake apex delegation).

Stage 1 tests never send a query, so none of this goes red. Index tests cannot fail for a self-referral. That is why “revert the index fix and watch the test fail” did not catch it, and why #419’s method note — drive the path, don’t only read the 149-site list — is the right follow-up.

**Extent of the fix:** convert the apex-recognition comparisons on the auth query/update path (`findDelegationFrom`’s stop, `IsChildDelegation`, AXFR/IXFR apex test, and the other wire-qname `== zd.ZoneName` sites in `queryresponder` / `updateresponder`). That is exactly stage 2 / #419. Do not pull those sites into #417; do not land #417 on a running auth without them.

---

## FINDING 2 — Folding `zd.ZoneName` left config-side equality behind

**Fix in #417: no. Pick up with the comparison-stage PRs that touch the zone API.**

`ParseZones` still stores `zconf.Name = dns.Fqdn(zconf.Name)` in the original case, and folds only `zd.ZoneName`. Then `apihandler_zone.go` compares:

```go
if dns.Fqdn(Conf.Zones[i].Name) == zd.ZoneName {
```

and the same comparison in `buildListZoneConf` against `zname` (the canonical registry key). A zone declared `Example.COM.` — the case defect 4 exists to support — no longer matches its own config entry. Policy-reset cannot find the config-base policy; list-zones override display loses the config policy name.

`zoneNameKey` still uses `strings.ToLower`, and its comment is now false (“Zones stay registered under `dns.Fqdn(name)` with their case as written”). Duplicate detection still works for ASCII mixed case, but it is not the same function as the registry, and it still Unicode-folds (Kelvin sign, long s).

**Extent of the fix:** one `EqualNames` or `CanonicalizeName` at the `Conf.Zones` scan, and `zoneNameKey` should be `CanonicalizeName(dns.Fqdn(...))` so duplicate detection and `Zones` share a function. That is a comparison/API site, not an index site. It is not needed for #417 to be a correct stage-1 PR. It should not be forgotten when the series reaches those files.

---

## FINDING 3 — Comment drift (nit)

**Fix in #417: no. Optional, any later touch of those files.**

The old `FindZone` comment was left in place and the new `normalizeZoneName` comment was appended to it. `FindZone` has no godoc; `go doc normalizeZoneName` is a history of #415. Same file stacked two comments on `getOwnerFrom`.

`EqualNames` in #416 still says a map key needs `dns.CanonicalName`. This PR exists because that is unsafe. The comment should point at `CanonicalizeName`.

No behaviour change.

---

## Out of stage 1 (correctly left for later)

These are not omissions in #417:

- The remaining `== zd.ZoneName` sites in `queryresponder`, `updateresponder`, `zone_updater`. (`sign.go` operands are owner-map keys against `zd.ZoneName`, both canonical after this PR, so they are safe by construction and belong with the signer in stage 5.)
- Cache / IMR indexes (#421).
- Catalog member maps as their own indexes.
- Working set remaining a plain map: every current helper folds, but a new `workingSet[wireName]` site will recreate defect 2. Acceptable for a mutex-held working copy; `NameMap` would be the structural version.
- Enforcement (CI grep / `Name` type) — stage 7.

---

## Tests

The seven tests in `name_case_test.go` plus the core unit tests are the right tests for an index PR, and the “revert and watch it go red” check is real for those four defects.

What they do not cover, given FINDING 1: a query through `QueryResponder` / `DefaultQueryHandler` with a 0x20-style qname (`WWW.EXAMPLE.com.` A). That test belongs in #419, next to the `findDelegationFrom` conversion, not in this PR.

---

## Series landing

Merge #416, then #417, then #419 before anything in this stack is served. #417 onto a running `tdns-auth` without #419 is the 0x20 self-referral. The series as planned is the right size: indexes first, then the comparisons the rewrite used to paper over.
