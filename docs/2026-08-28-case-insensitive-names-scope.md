# Case-insensitive DNS name comparison: scope

2026-08-28. Branch `feature/case-insensitive-names`, stacked on
`feature/equalnames-util` ([#416](https://github.com/johanix/tdns/pull/416),
which adds `core.EqualNames`). Closes [#415](https://github.com/johanix/tdns/issues/415).

## The answer up front

**Closer to a hundred than to twenty.** 149 candidate comparison sites in
non-test code, plus 4 name-keyed indexes, plus ~39 test-file sites.

From a 21-site sample (14%, every 7th site) hand-triaged with context:

| Class | Sample | Extrapolated to 149 |
|---|---:|---:|
| False positive — not a name comparison, or already canonical on both sides | 5 | ~35 |
| Latent — correct only because the store happens to be consistent; no edit, but needs a covering test | 2 | ~15 |
| Mechanical — already case-insensitive, but via `strings.EqualFold`, so Unicode-unsafe | 5 | ~35 |
| **Real bug — case-sensitive today, wrong answer for a mixed-case name** | **9** | **~64** |

So roughly **100 sites need an edit, of which ~60 are live defects.** The
sampling error on a 21-site draw is wide; treat ±15 as the honest band. The
first task of the work is triaging all 149, which replaces this estimate
with a count.

## Scope boundary: v2 and cmdv2 only

`tdns/` (v1) and `cmd/` are frozen — 2 and 5 commits since February, all
dependency bumps, against 1215 in `v2/`. `music/` has none. They carry the same
bugs and are excluded deliberately; the alternative is doubling the work for
code nobody runs. Worth stating in the PR so it reads as a decision rather than
an oversight.

Distribution across the six live packages:

| Package | Sites |
|---|---:|
| `v2` (root) | 110 |
| `v2/cli` | 16 |
| `v2/cache` | 10 |
| `v2/debug` | 7 |
| `v2/core` | 5 |
| `v2/edns0` | 1 |

Concentrated but with a long tail: `zone_updater.go` alone has 17, `dnslookup.go`
9, `sign.go` 8 — and 28 files have exactly one.

## Four defects confirmed by running the code

Not read-and-inferred. A fixture zone `example.com.` with mixed-case owners,
loaded through `testZone`, `OptFoldCase` off (the default):

```
*** SortFunc: zone example.com.: RR mixedzone.EXAMPLE.com. 3600 IN A 192.0.2.4 is not in zone. Ignored.
owner names stored:      [Upper.example.com. example.com. lower.example.com. ns.example.com.]
GetOwner("Upper.example.com.") -> found=true
GetOwner("upper.example.com.") -> found=false
GetOwner("mixedzone.EXAMPLE.com.") -> found=false
```

**1. Silent data loss at zone load.** `dnsutils.go:873` gates each RR on
`strings.HasSuffix(rr.Header().Name, zd.ZoneName)`. An owner that spells the
*zone-name part* in another case fails the suffix test and is dropped with a log
line and no error. `$ORIGIN EXAMPLE.com.` with relative names produces exactly
this. The record is then unreachable by any spelling. This one is worth fixing
on its own merits whatever happens to the rest.

**2. Names findable only by their stored spelling.** `GetOwner` is
`snap.Data[qname]`, an exact map lookup, and the store folds case only when the
`fold-case` zone option is set — which it is not by default, and is not set in
either shipped sample config.

**3. The apex-only fold in `FindZone`.** `zone_utils.go:1154` tries the exact
qname first and only lowercases on the second pass, returning a `folded` flag;
`defaultqueryhandlers.go:153` then lowercases the qname *only if that flag is
set*. So a query whose zone suffix matches exactly but whose left-hand labels do
not — `WWW.example.com.` — takes the unfolded path straight into the exact map
lookup and NXDOMAINs. This is #415.

**4. The zone registry folds one side only.** `Zones` is keyed by the zone name
as written in config (`parseconfig.go:820` says so explicitly). `FindZone`'s
fallback lowercases the *qname* but not the keys, so a zone configured
`Example.COM.` is unreachable by any query. The fold rescues lowercase-keyed
zones and nothing else.

## `dns.CanonicalName` is not a safe map key

Verified, not assumed. It is correctly ASCII-only for case — it agrees with
`EqualNames` on both Unicode traps — but it is built on `strings.Map`, which
decodes UTF-8:

```
raw   len=13  6e 73 ff 31 2e 65 78 61 6d 70 6c 65 2e
canon len=15  6e 73 ef bf bd 31 2e 65 78 61 6d 70 6c 65 2e   (0xff -> U+FFFD)
```

Any non-UTF-8 octet becomes U+FFFD, so two distinct names collide as keys and
neither is retrievable by its own bytes. Wire-sourced names are escaped to
printable ASCII by miekg and so are safe; names from zone files and YAML are
not. This changes the fix I proposed for #415: the canonical key must be
byte-wise. That is a second small function next to `EqualNames`, not a reuse of
`dns.CanonicalName`.

## Shape of the fix

The user's rule — *store as it arrives, compare with a function* — holds for
stored data. It cannot hold for an index: a hash table cannot consult a
function. So:

- **Comparisons** → `core.EqualNames`. Replaces `==`, `!=`, and
  `strings.EqualFold` on names.
- **Suffix / bailiwick tests** → `dns.IsSubDomain`, which is already
  ASCII-fold-correct (`CompareDomainName` calls miekg's `equal`). This is the
  bigger win of the two: `strings.HasSuffix(ns.Ns, child)` is wrong on *case*
  and on *label boundary* — it matches `evilchild1.example.` against
  `child1.example.`. `update_policy_eval.go:100` already carries a comment about
  precisely this trap.
- **Indexes** → a new byte-wise `core.CanonicalizeName` for the key, with the
  arrived spelling kept in `OwnerData.Name` and in the RR headers, which is
  where it is observable on the wire and in AXFR out.

Three new things in `v2/core`: `CanonicalizeName`, a `NameKey` alias for
intent at map sites, and tests. `EqualNames` is already there.

## Staging

Seven PRs, each independently testable and revertable. Order matters: 1 must
land first, the rest are parallel.

| # | Area | Sites | Contents |
|---|---|---:|---|
| 1 | Boundary | ~10 | `core.CanonicalizeName`; canonical keys for `Zones` and `snap.Data`; `GetOwner`/`FindZone`/`SortFunc`. Fixes all four confirmed defects. |
| 2 | Auth query + update | ~35 | `queryresponder`, `updateresponder`, `zone_updater`, `zone_update_verbs`, `defaultqueryhandlers`, `rrset_utils` |
| 3 | IMR + cache | ~25 | `dnslookup`, `imrengine`, `cache/*` — wire-sourced names, so the most reachable after #1 |
| 4 | Delegation / childsync / dsync | ~20 | includes the `HasSuffix` label-boundary bugs |
| 5 | Keystore / sign / zonemd | ~20 | `sign.go`'s apex tests are latent-severe: a miss signs a delegation NS or skips the apex NS |
| 6 | CLI + debug | ~23 | cosmetic, but `keystore_cmds.go:1018` `log.Fatalf`s on a case mismatch |
| 7 | Enforcement | — | see below |

## Enforcement

Without a check, this regresses within months — the 149 accumulated the same
way. Two options:

- **Cheap:** a CI grep for `strings.EqualFold` and `strings.HasSuffix` in `v2`,
  with an explicit allowlist of the non-name uses (digests, algorithms,
  transports, key states). Ugly, effective, half a day.
- **Proper:** a `go-critic`/ruleguard rule matching those calls on
  name-typed arguments. Needs a distinct `core.Name` string type to match on,
  which is a much larger refactor but is the only version the compiler enforces.

Recommend the cheap one now and the type as a separate question later.

## Two things found in passing, not part of this work

- `FindZoneNG` (`zone_utils.go:1178`) has zero callers and a broken loop:
  `i = strings.Index(qname[i:], ".")` treats a relative index as absolute.
  Delete it.
- `dnslookup.go:1735` hardcodes `p.axfr.net.` in a debug-log condition. This is
  a public repo.

## Interaction with open work

#413 Stage 1 also edits `defaultqueryhandlers.go` — the `RefreshCount` guards
sit a few lines from the `folded` fold at :153. Doing Stage 1 inside PR 2 above,
rather than separately, avoids a conflict in that file.
