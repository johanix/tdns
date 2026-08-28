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
| 1 | Boundary | ~10 | **DONE.** `core.CanonicalizeName` + `core.NameMap`; canonical keys for `Zones`, `zd.Data`, the snapshot and the working set; `GetOwner`/`FindZone`/`SortFunc`; `zd.ZoneName` folded at construction. Fixes all four confirmed defects. |
| 2 | Auth query + update | ~29 | **DONE.** `queryresponder`, `auth_utils`, `updateresponder`, `zone_updater`, `zone_update_verbs`, `defaultqueryhandlers`, `ops_uri`/`ops_svcb`/`ops_key`, `dnsutils`, `zone_utils` |
| 3 | IMR + cache | ~24 | **DONE.** `dnslookup`, `imrengine`, `imr_helpers`, `chase`, `apihandler_imr`, `cache/*` — plus the cache's own name-keyed indexes |
| 4 | Delegation / childsync / dsync | ~20 | **DONE.** `childsync_utils`, `scanner_csync`, `dsync_api_*`, `delegation_coherence`, `delegation_backend_*`, `config_delegationsync`, `ops_delegation_read` |
| 5 | Keystore / sign / zonemd | ~20 | **DONE.** `zonemd` canonical ordering, `sign`, `keystore_bulk`, `bind_convert`, `rollover_lock`, plus the two items the series owed |
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


## Addendum, after PR 1

**The site count barely moved: 149 → 148.** That is the expected result and
worth stating plainly — PR 1 fixed the *indexes*, not the *comparisons*, and the
one site it removed is `dnsutils.go:873`'s `HasSuffix` becoming
`dns.IsSubDomain`.

**But the triage shifts in PRs 2–6's favour.** Owner-map keys and `zd.ZoneName`
are both canonical now, so every `name == zd.ZoneName` where `name` came out of
`GetOwnerNames()` or a map key is correct by construction rather than by
accident. The "latent" class from the sample — ~15 sites — largely converts to
genuinely safe. What remains unsafe is narrower and easier to describe: names
that arrive from the wire or from an API request and are compared without going
through an index first. `dnslookup.go:2651` (a DS owner from an upstream
response) and `rrset_utils.go:239` (an Additional-section owner) are the shape
to look for.

**`fold-case` is now inert.** Folding is unconditional, so the option does
nothing. Still accepted, so existing configs parse; documented as a no-op in
`enums.go` and the sample template.

**`FindZone` lost its second return value.** It used to report whether the
match needed folding so callers could rewrite the qname; nothing needs that now
and both consumers of the flag are gone. 15 call sites updated, 13 of which were
discarding it already.

**One design note for later PRs.** `dns.CanonicalName` is fine for comparing —
it is ASCII-only — but must not be used to build a key, for the U+FFFD reason
above. `core.CanonicalizeName` is the key builder; `core.EqualNames` is the
comparison. Both live in `v2/core` so the sibling repos can use them.


## Addendum, after PR 2

148 → 119 sites. Two defects found that the static scan had classed as ordinary
`==`/`HasSuffix` sites, both of which turned out to be worse than the label
suggested.

**The server referred queries to itself.** `findDelegationFrom`
(`auth_utils.go:26`) walks up from the qname looking for a child delegation and
stops at `child == zd.ZoneName`. Compared byte-wise, so a query spelling the
zone-name part in any other case never recognised the apex, picked up the
**apex NS RRset as though it were a child delegation**, and answered a referral
to itself instead of the data. `WWW.EXAMPLE.` in `example.` did it;
`WWW.example.` did not, which is why it had never been noticed.

PR 1 made this reachable. Before it, a fully mis-cased qname failed the
`Zones.Get` fast path, went through `FindZone`'s fold, and was rewritten to
lowercase before it got here. PR 1 removed that rewrite because the lookups fold
themselves — correct, but it let the raw spelling travel further into the query
path than it used to. The scan had this site; the severity only appeared when
the whole path was driven end to end.

**`selfsub` was not bounded by label.** The child update policy asked
`strings.HasSuffix(rr.Header().Name, us.SignerName)`. That is true for
`evilchild.example.` against `child.example.` — a signer authorised for one name
could write records under a different name that merely ends with it. Now
`dns.IsSubDomain`. Confirmed by restoring the old check and watching the test
approve `evilchild.example.`, `xchild.example.` and `notchild.example.`

**Method note.** The end-to-end differential test — ask the same question in
four spellings, require identical responses — found both. Neither would have
come out of reading the 149-site list, and the second is not a
case-sensitivity bug at all. Worth repeating for the IMR path in PR 3: drive it,
don't only read it.

**Still not converted, deliberately:** `sign.go`'s apex tests. Its operands are
owner-map keys against `zd.ZoneName`, both canonical since PR 1, so they are
safe by construction; they belong to PR 5 with the rest of the signer.


## Addendum, after PR 3

119 → 108 in the comparison scan, but that number understates it: PR 3's larger
half was the resolver cache's **indexes**, and a `.Get()` is not a comparison,
so 76 converted call sites do not appear in the count at all.

**The cache is the auth server's problem again, one layer out.** `ZoneMap`,
`Servers`, `ServerMap`, `AuthServerMap` and `ServerTLSA` were `ConcurrentMap`s
keyed by a bare DNS name; `RRsets` and the DNSKEY cache by `"<name>::<n>"`. All
of them are fed names a resolver does not control: an authoritative server's
own spelling, and — once 0x20 randomisation is on — a different mixture of case
on every single query. Keyed by exact bytes, the cache stores the same name
repeatedly and finds it never. The five bare-name maps are `core.NameMap` now;
the two composite keys fold the name half where the key is built.

`GetOrCreateAuthServer` is the sharpest of these: it exists to guarantee one
`AuthServer` instance per nameserver, and keyed by raw bytes it guaranteed one
per *spelling*, so per-server health, transport capability and TLSA state were
silently split across duplicates.

**A correction to the PR 2 write-up's method claim.** I recorded "drive it,
don't only read it" as the lesson, and then wrote a referral test that passed
before the fix as well as after — within one response the NS owner and the DS
owner come from the same zone, so they agree, and the comparison between them
cannot fail. The test only became real once the two owners were spelled
independently, which is what a parent whose zone file spells them differently
serves — something tdns itself now does, because #417 preserves the arrived
spelling instead of folding it. **Passing is not evidence; reverting the fix and
watching the test fail is.**

**And a claim withdrawn.** `isSubdomainOf` in the cache was already correct: it
canonicalised both names and added the leading dot a byte-wise suffix test needs
to respect a label boundary. I had it on the list and changed it to
`dns.IsSubDomain` before reading the two lines above the comparison. The change
stands as a simplification — one line, no allocations — but it fixes nothing,
its comment says so, and its test is characterisation rather than regression.

Real defects fixed here: the closest-known-zone walk (`strings.HasSuffix` with
no boundary and no folding, so a cached `ample.` could be chosen as the enclosing
zone for `example.`), the negative-answer SOA gate (same shape — an SOA for
`ample.` authorising a denial for `example.`), the SOA-authorises-this-denial
test in `dnslookup`, the DS-and-RRSIG pair in a referral, and the `_853._udp`
TLSA owner prefixes.


## Addendum, after PR 4

108 → 96.

**Glue for other people's delegations was being deleted.** `CreateChildUpdate`
removes an NS record and, if that nameserver is in bailiwick, its glue with it.
The in-bailiwick test was `strings.HasSuffix(ns.Ns, child)`, which is true for
`ns1.evilchild.example.` against `child.example.` -- so touching one delegation
deleted A and AAAA belonging to a *different* delegation in the same parent. The
same test, run on the new records, decides which glue the replace path clears
first. Both are `dns.IsSubDomain` now. In the other direction it missed
in-bailiwick glue whose case differed from the child name, leaving the parent
serving glue for a nameserver that was gone.

**`NSInBailiwick` fixed, as promised in #419.** It is the live twin of the dead
`InBailiwick` fixed there, and it had the same body.

**A credential principal could be shared by two different names.**
`canonDsyncApiUser` normalised with `strings.ToLower`, which folds by Unicode:
U+212A KELVIN SIGN maps onto `k`, so `\u212a.example.` and `k.example.` --
distinct DNS names -- reduced to one principal. A principal is what a
self/selfsub policy compares owner names against, so it decides what a
credential may write. Same for the zone key and the parent-zone lookup.

**Three spellings of one predicate.** The tree now has `BailiwickNS` (correct,
with its own tests, in `bailiwick_test.go`), `NSInBailiwick` (fixed here) and
`InBailiwick` (fixed in #419, no callers). They should be one function.
Consolidating is a separate change and not one this series was asked for, so
it is noted rather than done.

**One clause removed rather than fixed.** `delegation_backend_direct.go:95` read
`!dns.IsSubDomain(childZone, ownerName) && ownerName != childZone`. IsSubDomain
is already true for the name itself, so the second clause could never be
reached; it was case-sensitive, which would have made it wrong if it ever had
been.

## Review of #417 (external, 2026-08-28)

`docs/2026-08-28-pr417-case-insensitive-names-review.md`, on `main`. Verdict:
approve as stage 1; no change required to #417 itself. Three findings.

**FINDING 1 — the query-path self-referral.** Already the subject of #419, and
the reviewer places it there. Two sites #419 has NOT yet converted, found by
the review and confirmed against the stack tip:

- `IsChildDelegation` (`zone_utils.go`), `qname == zd.ZoneName` — a mixed-case
  apex has NS, so it classifies as a child.

I also listed `queryresponder.go:329`'s `cdd.ChildName == qname` here as an
unconverted defect. **That was wrong**, and the re-review is right to strike it:
both strings come from the same walk of the same qname, so they match by
construction whenever the walk returns a real child. It looked like a bug only
while `findDelegationFrom` was still handing back the apex as a fake child —
which is the defect, and the one `EqualNames` on the walk stop actually fixes.
#419 correctly left the `==` alone and covered the path with DS shapes in the
query differential instead. Do not convert it.

**FINDING 2 — config-side equality left behind by folding `zd.ZoneName`.**
`zoneNameKey` is fixed here, in #417: it is a key function, and #417 is what
falsified its comment (which claimed zones stay registered in the case they were
written in). It now shares `core.CanonicalizeName` with the registry, and a test
pins that the two agree — including that neither Unicode-folds, so two zones
differing only by U+212A are not quarantined as duplicates of each other.

The two `dns.Fqdn(Conf.Zones[i].Name) == zd.ZoneName` comparisons in
`apihandler_zone.go` are NOT fixed here. They are comparison sites, and a zone
declared `Example.COM.` currently loses its config policy through them — a
regression the series introduces, so it must not ship unfixed. Scheduled with
FINDING 1's sites, pending the review of #419.

**FINDING 3 — comment drift.** Fixed here: `normalizeZoneName` had been inserted
between `FindZone`'s godoc and `FindZone` itself, so `go doc FindZone` showed
nothing and `go doc normalizeZoneName` showed the history of #415; and a second
godoc had been stacked on `getOwnerFrom`'s existing one. The `EqualNames`
comment naming `dns.CanonicalName` as the map key is fixed in #416, where it
lives -- it was advice to do the exact unsafe thing this stage exists to stop.

**Method note the review makes, worth keeping.** Stage 1's tests never send a
query, so the self-referral could not have gone red under "revert the fix and
watch the test fail". That check verifies a fix is load-bearing; it says nothing
about consequences elsewhere. Only driving the path does.

## Review of #419 (external, 2026-08-28)

`tdns-project/reviews/2026-08-28-tdns-PR419-query-and-update-review.md`.
Verdict: request changes -- four findings, all inside #419's own surface.
All four addressed.

**FINDING 1 — `IsChildDelegation`.** Converted. The review is right that this is
not merely the same hole as `findDelegationFrom`: `UpdateResponder` now folds
the zone-section qname, so the apex branch is entered correctly, and the damage
is one level in -- the OWNERS inside that branch are passed to
`IsChildDelegation`, so an apex NS update spelled `EXAMPLE.` was classified as a
CHILD update and judged against `allow-child-updates` instead of
`allow-updates`.

**FINDING 2 — three sites missed in `ZoneUpdateChangesDelegationDataNG`.** A
real miss, and worth naming the cause: the replacement list for that file was
assembled by hand from a 17-line enumeration, and three lines were dropped
between enumerating and patching. The re-sweep after the fix (`grep` for any
remaining wire-owner-vs-apex `==` in the six files) is what should have run
before the PR, not after the review.

**FINDING 3 — the glue walk's `childDel != ancestor`.** Converted.

**FINDING 4 — 14 unrelated `docs/` files, ~3000 lines.** `git add -A` swept
untracked review documents from the working tree into the commit. Removed with
`git rm --cached`, so they return to being untracked rather than being deleted
from disk. Net diff against the base is now clean.

`v2/probe_src_test.go` keeps its two-line gofmt change: the file was merged
unformatted in #410, and un-formatting it again to tidy this diff would leave
the tree worse than it found it.

**Coverage.** New tests for findings 1 and 2, each verified by reverting the
fix. The pre-switch apex-NS guard needed a differential test rather than a
value assertion -- it only has an effect for a DUPLICATE apex NS add, every
other path setting `InSync` from its own arm, and whether "in sync" is right
for a duplicate add is a separate question from whether spelling may change it.
DS shapes added to the query differential, as the review suggested.

FINDING 3 is **not covered by a test**. It sits inside `UpdateResponder`'s
message-driven classification, which has no unit harness at all; building one
for a one-line fix is out of proportion to this PR, and worth doing on its own.

Sites the review confirms belong to later stages, not #419: `rrset_utils`
(outbound `AuthQueryEngine`), `sign.go` (canonical operands since #417),
`NSInBailiwick` (stage 4, done), `ops_delegation_read` (stage 4, done), and the
`Conf.Zones[i].Name` pair from #417 FINDING 2, which is still open.


## Review of #421 (external, 2026-08-28)

`tdns-project/reviews/2026-08-28-tdns-PR421-imr-and-cache-review.md`.
Verdict: request changes -- four findings, all inside #421's own surface.
All four addressed. Two of them were breakage this PR introduced.

**FINDING 1 — the `_dns.` prefix test folded and the strip did not.** I changed
`strings.HasPrefix(owner, "_dns.")` to fold the name and left the
`strings.TrimPrefix(owner, "_dns.")` beside it comparing bytes, so
`_DNS.ns1.example.` cleared the test and then kept its prefix: `baseName` stayed
the whole owner and the transport signal was dropped. `baseFromTLSAOwner`, in
the same commit, already had the right pattern -- fold to test, slice the
original by `len(prefix)` so the base name keeps the case it arrived with. The
prefix is a named constant now, so the test and the strip cannot drift again.

**FINDING 2 — `ServerMap` folded the zone and not the nameserver.** The type is
`NameMap[map[string]*AuthServer]`: the outer key folds, the inner one was still
the bytes an upstream sent. Worse, this PR *introduced* a miss --
`collectInBailiwickNS` now returns canonical names with a comment saying they
are used as map keys downstream, and they were being looked up in a map keyed by
wire spelling. Every subscript of that inner map (31 of them) goes through a
shared `cache.ServerKey` now. Not a second `NameMap`: a concurrent map per zone
would be the wrong shape for a handful of nameservers, as the review says.

`GetOrCreateAuthServer` stopping the identity split is not the same as the
per-zone map finding the server. Both were needed.

**FINDING 3 — the zone-backoff dump compared a now-canonical key to a raw
filter.** Also breakage from this PR: before `ZoneMap` became a `NameMap`, a
filter matching the stored spelling worked. Fixed by routing it through
`ZoneMatchesSelector`, which the sibling handler already used -- two copies of
one predicate is how the drift happened, so there is one now.

**FINDING 4 — `dns.CanonicalName` still building keys in `FlushDomain` and the
TLSA store.** Converted. Worth noting how nearly this went untested: the first
version of the test used ASCII fixtures, where `dns.CanonicalName` and
`CanonicalizeName` agree exactly, so reverting the fix stayed green. It only
became a real test once it stored two nameservers differing by a single
non-UTF-8 octet -- which is the entire reason the two functions are not
interchangeable.

**Left for later, as the review confirms:** `rrset_utils` (outbound
`AuthQueryEngine`), `sign.go` (canonical operands since #417), and the
`Conf.Zones[i].Name` pair from #417 FINDING 2, still open. The review also notes
`visitedZones`'s composite key mixes a folded qname with a wire-sourced
zonename, so a mixed-case repeat referral would miss the loop detector -- not in
this diff, not requested, and worth picking up.


## Re-review of #421 (external, 2026-08-28)

Findings 1-4 accepted; approved as stage 3. Three niggles, two fixed and one
deliberately not.

**`ServerKey` had stolen `isSubdomainOf`'s godoc.** Fixed. This is the SECOND
time in the series -- #417 FINDING 3 was the same thing, `normalizeZoneName`
landing between `FindZone`'s comment and `FindZone`. Both times the cause was
the same: my patch script inserts a new function before a `func X {` anchor,
and when a doc comment sits immediately above that anchor the new function is
spliced into the middle of it. Insert before the COMMENT, not before the `func`.

**`FlushAll` read `rootNSHosts` with `dns.CanonicalName` while building it with
`CanonicalizeName`.** Fixed. Adjacent to FINDING 4 rather than inside it, but a
set built with one key function and read with another is precisely the drift
this stage exists to remove, so it is completing the finding rather than
expanding it. Covered by a test that caches root glue under a name with a
non-UTF-8 octet -- the shape the review pointed at -- and watches it survive a
flush. Reverting the read side flushes it.

**`nsMap[baseName]` in `ParseAdditionalForNSAddrs` is still byte-wise, and is
deliberately left.** The review is explicit: it is a per-message set of NS
hostnames built and read inside one function, not the cache index FINDING 2
named, and expanding a finding after the named map has been converted makes the
follow-up harder to verify than the fix is worth. The residue is that a
first-pass OOTS or glue record whose NS is spelled differently *within the same
referral* can miss; later queries go through `serverMap`, which folds. Recorded
here so it is a decision rather than an oversight.


## Review of #422 (external, 2026-08-28)

`tdns-project/reviews/2026-08-28-tdns-PR422-delegation-and-dsync-review.md`.
Verdict: approve as stage 4. **No change requested.**

That completes review of stages 1-4. All four are approved; #417, #419 and
#421 each went through a re-review after their findings were addressed.

One item the review raises and parks, recorded here so it does not rot:

**The NOTE on `InBailiwick` (`dnsutils.go`) is now false.** It says
`NSInBailiwick` "still carries the HasSuffix version; it is fixed with the rest
of the scanner rather than here." I wrote that in #419 pointing forward at this
PR, and this PR fixed it. The review's instruction is not to pull `dnsutils.go`
into #422's diff for one line, and to update it when someone next touches that
comment.

Worth flagging that "next touches" has no owner: stages 5-7 are keystore, CLI
and enforcement, none of which go near `dnsutils.go`, and the series lands as
one merge -- so on current plans the sentence becomes false on `main` and stays
that way. It is one line and it is wrong. Left as the review asks, but it should
be picked up by whichever stage is convenient rather than left to chance.

Also confirmed as correctly out of stage 4, unchanged from the earlier lists:
`rrset_utils` (outbound `AuthQueryEngine`), `Conf.Zones[i].Name`, `scanner.go`
keying in-bailiwick NS sets with `dns.CanonicalName` (ASCII agrees; the
non-UTF-8 shape is the same one #421's TLSA keys had), and consolidating the
three in-bailiwick predicates.


## Addendum, after PR 5

96 → 85.

**The canonical-order folder was `strings.ToLower`.** `canonicalSortKey` and
`canonicalOwnerLess` implement RFC 4034 §6.1 ordering, and that order is not a
presentation detail: it IS the NSEC chain, and it is the order records are fed
to the ZONEMD digest. §6.1 orders names as OCTET strings with US-ASCII A-Z
folded and nothing else. `strings.ToLower` broke that twice over:

    canonicalSortKey("\u212a.example.")  == canonicalSortKey("k.example.")
    canonicalSortKey("ns\xff1.example.") -- keyed on ef bf bd, bytes the name does not contain

Two distinct names sharing one position is a chain no validator accepts and a
digest no other implementation computes. The comment above `canonicalSortKey`
already said this class of bug is "wrong in a way no test zone would ever show"
— it was describing the zero-octet case, and the folding had the same property.

**Also converted:** the keystore's bulk selector (it decides which PRIVATE keys
an export writes out, and under Unicode folding a selector for one zone also
selected another), the per-zone rollover lock key, the signer's apex and
delegation-occlusion tests, the BIND keystore's zone matching, and the apex
ZONEMD exclusion.

**The two items the series owed are in here**, because nothing later was going
to touch those files:

- `apihandler_zone.go`'s two `Conf.Zones[i].Name == zd.ZoneName` scans -- the
  regression this series introduced in #417 by folding `zd.ZoneName` while
  `ZoneConf.Name` keeps the operator's spelling. A zone declared `Example.COM.`
  could not find its own config entry: list-zones lost its policy name and
  policy-reset refused, reporting the zone as having no configured policy.
- The NOTE on `InBailiwick` saying `NSInBailiwick` "still carries the HasSuffix
  version". #422 fixed it and the sentence became false.

**Not claimed as a fix.** The apex test inside `digestBlock` is `EqualNames`
now, but `==` was already correct there: every in-tree caller passes a canonical
apex and `name` is folded a few lines above by the same function. It is defended
because `ZoneDigest`/`ZoneDigestHex` are exported and an outside caller's apex is
not covered by that invariant. The comment says so rather than implying a bug.

**Method, again.** Two of the five new tests passed against the unfixed code on
the first attempt, because ASCII fixtures make `strings.ToLower` and
`CanonicalizeName` indistinguishable. Both only became tests once they used an
input where the two folders disagree. That is now three stages running where the
first draft of a test proved nothing; the ASCII happy path is not evidence for
any claim in this series.
