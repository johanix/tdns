# A reload computes the delta: IXFR after a reload, and no serial for no change

**Written 2026-11-08.** For #1006. Line references are to main at `0cc79ba3`.

**Status:** implemented on `claude/1006-reload-delta` (parts A, B, C, E) and
`claude/1006-reload-signatures` (part D), each in its own PR. Part F was ruled
out.

## The problem

A primary zone reloaded from its file replaced the old content wholesale.
`applyRefreshReplacementLocked` set `wsIxfrEpochReset` for every replacement
except an applied inbound IXFR (`v2/zone_mutation.go:1168`), so
`updateIxfrChainLocked` emptied the IXFR history (`v2/ixfr.go:72`). Three things
followed, and they are one problem: tdns did not compute the difference between
the old and the new version.

- A secondary asking for IXFR after an edit-and-reload got the whole zone.
- After a reload that changed content, the zone served `max(served, file) + 1`
  (`v2/zone_mutation.go:1109`), so the file's serial and the served one never
  met again.
- At a restart, the first load lifted the serial past the highest one published
  (#655) even when the content was what had been published, and every
  secondary fetched the zone again in full.

## The decisions

Taken with the maintainer on 2026-11-08:

1. Diffing a wholesale replacement is an **option**, not mandatory, because it
   compares the whole zone: `ixfr-from-differences`, per zone, off by default,
   as in BIND. It covers a reload of the file and an inbound AXFR alike.
2. If the zone has not changed, its serial does not change, forced reload or
   not.
3. A serial that has to move follows the zone's `outbound-soa-serial` mode.
4. Re-using signatures across a reload (part D) is its own PR.
5. Keeping the serial across a restart (part E) is only for zones that do not
   sign their own content.
6. Persisting the IXFR history across restarts (part F) is not done, now or
   probably ever.

## The parts

**A. The option.** With `ixfr-from-differences`, a replacement does not set
`wsIxfrEpochReset`, and `updateIxfrChainLocked` diffs it like any publish. Its
existing guards cover what can go wrong across a replacement: a serial that does
not advance in RFC 1982 order, content that changed under an unchanged serial,
and a delta over `ixfr-chain-max-bytes`. A replacement shares no storage with
the snapshot it replaces, so its diff compares every owner;
`computeZoneDeltaBounded` stops as soon as the estimate passes the budget,
instead of comparing the rest of the zone only to throw the result away.

**B. No publish for no change.** A reload whose file serial is not ahead of the
served one sets `wsSkipIfUnchanged`. `publishWorkingSetLocked` then compares the
working set with the published snapshot (`authoredContentEqual`) and, if they
match, drops the working set and restores the serial: no new serial, no NOTIFY,
no IXFR link. The comparison runs after signing, the NSEC restitch and the
ZONEMD, because a signed zone gains its keys and signatures only in those steps;
it ignores what they regenerate (RRSIGs, the NSEC property, a managed ZONEMD)
and the SOA serial. It stops at the first difference, so a reload that did
change something costs little.

The ordinary unchanged file never gets this far: the content digest of the file
already stops it (`FetchFromFile`). B is what makes a forced reload, or a reload
with no recorded file identity, harmless. A file the operator folded the journal
into by hand is the one case where the merge path runs after B declined to
publish; `MergeJournalOverNewFile` assumes the published snapshot is the file,
and after B it is, in content.

**C. The file's own serial.** A file whose serial is ahead of the served one is
served at that serial. #362 needs the journal anchor (`zd.fileSerial`) not to be
ahead of the served serial; equal is enough, and the next journalled change runs
from it to the serial after. That serial was never published before: the first
load put the served serial past every published one. A file whose serial is not
ahead gets `nextOutboundSerial`, which follows the zone's mode.

**E. Restart.** C removes most of the restart case: a zone whose reloads served
the file's own serial restarts with a published floor equal to the file's
serial, and the first load lifts nothing. What remains is a zone that published
past its file. For a file-backed zone that does not sign its own content, a
reload or first-load publish now stores a digest of the content it publishes (`authoredContentDigest`,
the same terms as B) in a new `OutgoingSerials.content_digest` column. Raising
the recorded serial clears it. At the first load, if the floor is the recorded
serial and the digest of the content just loaded matches, the zone serves that
serial instead of the next one. The file digest alone could not decide this:
load-time callbacks and stored dynamic owners add content the file does not
have.

A zone with journalled changes still rises twice at a restart (the replay
publishes after the first load). Fixing that means replaying before the first
publish, which this does not attempt.

**D. Signatures.** Without D, a signed zone's reload signs every RRset afresh,
and the delta holds every RRSIG and NSEC twice; it usually exceeds the budget
and the downstream gets a full transfer, as before. D gives each RRset of the
reloaded working set the RRSIGs it had in the published snapshot when its
records are exactly the same (same RDATA set, same TTLs), and each owner still
present its NSEC. The scoped signing pass then stands down on what carries a
valid signature, and the restitch repairs only around what changed, exactly as
after an incremental update. Carrying signatures only over identical records is
what avoids serving changed records under an old signature.

## Tests

`v2/reload_delta_test.go` (A, B, C, E), `v2/reload_signatures_test.go` (D, in
its own PR), and
the changed `TestReloadOfAFileWhoseSerialJumpedAhead`, which now expects the
file's own serial.

## Amendment, 2026-11-08: part D as implemented

- The NSEC records are not carried when the SOA's negative TTL changed: the
  restitch would keep the old TTL on every NSEC it did not rewrite.
- A one-record edit's link also carries the apex DNSKEY's new signature and the
  NSEC signatures around the apex, not only around the edit. The file carries
  no DNSKEY, so the signer puts it back, and the apex counts as changed for the
  restitch. Carrying the DNSKEY RRset too was not done: whether the signer then
  notices a changed key set has not been checked.

## Changes from the first review (2026-11-09)

CodeRabbit's first round led to these changes:

- **A zone signed elsewhere.** When a zone does not sign its own content,
  any RRSIGs and NSEC records in its file came with the content, so the
  unchanged-content check and the restart digest now compare them
  (`contentTerms.withSigs`). A file re-signed under the same serial is
  published, and the old signatures are not served until they expire. A
  file whose SOA carries a signature also keeps its own serial on a reload,
  whatever it is, because that signature covers it. A first load still
  lifts such a zone past the published-serial floor, as it did before this
  change.
- **The floor does not depend on the new column.** If the migration that
  adds `content_digest` failed, `RaiseOutgoingSerial` retries without
  clearing the digest, so the floor is still recorded. No digest can have
  been stored without the column.
- **ZONEMD parameters count.** A ZONEMD the zone makes is compared on its
  scheme and hash pairs, not its digest. Turning it on, or changing its
  algorithms, before a reload therefore publishes.
- **An unchanged reload records its digest,** at the serial it keeps. A
  journal folded into the file by hand then survives a restart without a
  new serial.
- **A refused publish keeps its flags.** When signing fails and the working
  set stays staged, the retry still skips an unchanged reload and still
  records the digest.
- **Smaller:** a serial regression is reported as one even when the delta
  is also over budget, and the bounded-delta test checks the estimate's
  lower bound.

## Changes from the external review (2026-11-09)

- **A file signed elsewhere keeps its own serial, on a first load too.** The
  first round's change still let a first load lift such a zone past the
  published-serial floor. The served SOA then carried a serial its
  signature did not cover. The unchanged check ignored the serial, so
  reloading the same file never put the file's serial back. Now a first
  load serves the file's serial, with a warning when the zone has published
  a higher one: a downstream holding that higher serial will not fetch it,
  and only a re-signed file with a newer serial fixes that. When the SOA
  came with a signature, the unchanged check and the restart digest also
  compare it serial and all (`serialCovered`).
- **A zone that makes its own ZONEMD restores its serial at a restart.** The
  restart digest takes the zone's configured ZONEMD parameters instead of
  the record. The record exists when the digest is recorded but not yet
  when it is compared.
- **A publish that panics clears the two staged flags,** as it does the
  others.

## Changes from the third review (2026-11-09)

- **No later step moves the serial of a zone signed elsewhere.** The first
  load kept the file's serial, but `outbound-soa-serial` has two later paths,
  after the initial load and after each refresh. In `persist` mode they put
  back a higher stored serial; in `unixtime` mode they set the time. Either
  left the served SOA with a serial its signature did not cover. Both now
  leave alone a zone that serves an SOA signed elsewhere.
- **A file signed elsewhere that changed under the served serial is
  refused** (accepted by the project owner, 2026-11-09). Downstreams that hold
  that serial would never transfer the change, and could go on serving its
  old signatures until they expired. The reload fails with
  `ErrSignedFileChangedUnderServedSerial`, which says to re-sign with a newer
  serial, and the published version stays. The check runs on the built working
  set, before anything is published. This is the rule tdns already keeps for
  unsigned zones: no new content under an old serial. A file whose serial is
  behind the served one is still served, with a warning, as before.
- **An owner holding only an NSEC counts as content** where NSEC records are
  content, in a zone that does not sign itself.
- **The ZONEMD parameters are resolved, defaults included,** before they go
  into the comparison, as the publish resolves them. A config that spells out
  the default no longer reads as a change.

## Part D, changes from the external review (2026-11-09)

- **No NSEC is carried under a TTL clamp that can lower the negative TTL.**
  The carry compares the SOAs before the publish signs, and the publish
  signs the SOA under the zone's TTL clamp. A ceiling below the negative
  TTL lowers the SOA's TTL, and with it the TTL every NSEC must take, after
  that comparison. The carry now also asks the zone's clamp
  (`ClampParamsForZone`). When its ceiling is below the negative TTL, no
  NSEC is carried and the chain is rebuilt. That costs a full chain rebuild
  on a reload inside a clamp window. In the test zone the whole chain was
  re-signed under such a clamp with or without this guard, so the test
  checks the outcome but does not show the guard is needed. The guard makes
  the outcome independent of whatever re-signed it there.
- **The SOA's signatures are never carried.** Every publish signs the SOA
  afresh, since its serial moves. A carried signature over the old serial
  would stand if that re-sign failed.

## Part D, changes from the third review (2026-11-09)

- **A carried NSEC's signatures are checked.** The signing pass skips NSEC
  records, and the restitch rewrites only the names around a change, so
  nothing in the publish looked at a carried NSEC's signatures again. A
  carried RRset's signatures, by contrast, go through `SignRRset`, which
  re-signs any that are due. A carried signature is no older than the one
  already served, and the resigner renews NSEC signatures at the same
  threshold, so this never introduced an expired signature. What the carry
  lost was the repair a full re-sign used to make on the way. Now an NSEC is
  carried only while every active ZSK has a signature on it that is not due
  for renewal. Otherwise it is left out, and the restitch rebuilds and signs
  it.
- **The clamp guard is tested at the carry,** where it acts. Under a clamp
  below the negative TTL no NSEC record or signature is carried; without the
  clamp they are. Unlike the end-to-end test above, this one fails without
  the guard.
