# D-3b, step 1: extract the RFC 7477 NS/glue rules from the scanner

**Written 2026-09-02.** The first of D-3b's two PRs in
`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md`: extract
the CSYNC acceptance logic into free functions with the scanner still the
only caller. Branch `feature/ddns-keystate-d3b-csync-extract`, **off
`main`**, not stacked: a pure refactor should merge on its own, and nothing
in it depends on the D-7/D-6/K-4 stack (#472, #473, #476). The one-line
`_dsboot` signal-name change D-6 made in scanner.go will be a trivial
merge-forward.

## What moved, and what did not

`ProcessCSYNCNotify` (scanner.go) is RFC 7477 §3 for the parent, driven by a
CSYNC NOTIFY: fetch SOA and CSYNC from every child nameserver and require
agreement, validate flags, dedup by serial, honour soaminimum, then per
type (NS first) compare what the child serves with what the parent holds,
then re-check the SOA. Steps 1–6 and 8–10 are network and bookkeeping and
stay where they were. Step 7 — the rules — is now `delegation_csync.go`:

- `csyncFlags` (unknown flag bits refuse; the two defined bits),
  `csyncSuppressedBySoaMinimum`, `csyncTypes` (NS first, always processed),
  `inBailiwickNSNames`.
- `computeCsyncDelta(ctx, child, types, currentNS, currentGlue, fetch, …)`
  returning the NS and glue adds/removes. The network is behind
  `childRRsetFetcher` (the scanner passes `queryAllNSAndCompare`), the
  parent's stored delegation behind `currentGlueLookup` (the scanner passes
  the delegation-backend map). Same shape as `dnskeyFetcher` in
  `delegation_coherence.go`.

Behaviour is unchanged by construction, quirks included: the NS pass is
terminal on fetch error, disagreement or an empty RRset; a glue fetch that
fails or disagrees skips that nameserver; a removed nameserver's glue is
removed when the backend holds an entry for it, and an entry that exists
but is empty still counts as a change. The scanner's log lines and
`ErrorMsg` strings are byte-identical, prefix included.

**Deleted, in its own commit:** `CheckCSYNC`, `CsyncAnalyzeNS/A/AAAA`,
`UpdateCsyncStatus` and `TypeBitMapToString` in scanner_csync.go. They were
the pre-NOTIFY CSYNC scanner (single-server queries through `AuthQueryNG`,
a commented-out database) and had no callers anywhere in `v2/`. The plan and
the handover named `CsyncAnalyze*` as the logic to extract; the live logic
was in `ProcessCSYNCNotify`, and that is what was extracted.

## Why the fetcher returns "all in sync"

RFC 7477's parent asks every child nameserver and only acts when they
agree. That agreement is part of the acceptance rule, not of transport, so
the fetcher reports it and `computeCsyncDelta` enforces it. The UPDATE path
(step 2) will supply a fetcher that asks the child's nameservers the same
way, so an UPDATE asserting an NS set the child does not consistently serve
is refused on the same rule.

## What step 2 will look like

`ApproveChildUpdate` already calls `CheckDelegationCoherenceForUpdate` for
DS. Step 2 adds the NS/glue counterpart: apply the update's NS/A/AAAA
actions to the parent's current delegation, then require the resulting NS
set to be non-empty, glue only for in-bailiwick nameservers of the
resulting set, every in-bailiwick nameserver to have glue, and the
resulting NS set (and each in-bailiwick nameserver's glue) to be served by
the child's nameservers in agreement — the CSYNC rule applied to an
asserted change rather than a scanned one. The DS-duplication question
(`CheckDelegationCoherence` vs `ProcessCDSNotify`) is deliberately untouched
here and is not part of step 2 either.

**`computeCsyncDelta` is NOT the UPDATE entry point, and step 2 must not wire
it as one.** The two have different shapes, and the difference is the whole
reason step 2 needs its own driver:

| | input | question | output |
|---|---|---|---|
| `computeCsyncDelta` (scanner) | a CSYNC record | what has the child changed? | a delta to apply |
| step 2's acceptance | a set of asserted actions | may the result stand? | accept / refuse |

One DERIVES a change from what the child publishes; the other VALIDATES a
change somebody has asserted. Calling the delta API from the UPDATE path would
mean asking the child what it wants and then applying that, which is not what
an UPDATE is.

What step 2 SHOULD reuse, and what this extraction exists to make reusable:
`childRRsetFetcher` (ctx plus the agreement requirement across the child's
nameservers), `csyncTypes`, `inBailiwickNSNames` and `canonicalNameSet`. The
acceptance rule itself is then expressed once more, against those shared
primitives, in step 2's own function.

That leaves the RFC 7477 rule stated in two drivers, which is worth naming
rather than discovering later: if the rule changes, both have to change, and
the UPDATE path silently becomes a bypass if only one does. The mitigation is
that everything below the rule is shared, and that both sites should say so.

## Tests

`delegation_csync_test.go`, all with a map-backed fetcher: flags and the
unknown-bit refusal; soaminimum; NS-first ordering including a bitmap
without NS; the in-bailiwick test including the suffix trap; NS changed /
unchanged / fetch error / disagreement / empty; glue for kept, new and
removed in-bailiwick nameservers with an out-of-bailiwick one never asked;
glue failures skipping rather than aborting; the empty-entry quirk; unknown
types ignored. There were no scanner tests before this.
