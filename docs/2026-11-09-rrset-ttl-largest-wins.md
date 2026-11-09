# One TTL per RRset, the largest: on load, on transfer, on UPDATE

**Written 2026-11-09.** For #996, part 1. Stacked on #1015
(`claude/1006-reload-signatures`), which changes the same load path.

**Status:** implemented on `claude/996-rrset-ttl-unify`, revised the same day
for the ruling on secondaries (see "Changes from the first version"). Part 2,
the DNSKEY RRset and the keystore rows, is not in this change.

## The problem

The records of an RRset share one TTL (RFC 2181 §5.2). tdns made that true on
UPDATE only, by giving the whole RRset the added record's TTL (#767). A zone
file, an AXFR or an IXFR delta that brought an RRset at two TTLs was served
that way. And a signer's TTL clamp read the first record's TTL
(`applyClampToRRset`), so which TTL it clamped from depended on record order.

Why it matters now: a multi-provider zone is served by several signers. If one
of them serves a shorter TTL than another, a key roll timed on the shorter one
can leave resolvers that hold the other signer's longer-lived RRset without the
new key (johanix/tdns-mp#369).

## The rulings

From the project owner, 2026-11-09:

1. **The largest TTL in an RRset always wins**: on zone load, on inbound
   AXFR/IXFR, and on UPDATE. On UPDATE this replaces #767's rule that the
   added record's TTL wins.
2. **The keystore reflects reality**: a key row carries the TTL that is
   actually served. This is part 2, and comes later with the multi-provider
   key work.
3. **A copy that is already signed**: a rewritten TTL never goes above the
   covering RRSIG's original TTL.

And later the same day, on a review finding about a relayed ZONEMD:

4. **A secondary zone is immutable, and doubly so if it has a ZONEMD.** "We
   should never touch a zone with a zonemd, signed or not, unless explicitly
   instructed (i.e by a config telling us to sign the zone, or to accept api
   updates, or something)." This narrows rule 1 on inbound transfers to the
   zones this server is told to modify. Zone load and UPDATE keep rule 1.

## Which zones are unified

Content a zone adopts is unified when this server is told to modify the zone
(`toldToModify`, `v2/rrset_ttl.go`). That is a zone that may originate content
at all (`zoneMayOriginateContent`, the secondary-zone invariant of
`docs/2026-07-25-secondary-zones-immutable.md`) and is one of:

- a **primary**: its content is this server's own, read from its zone file;
- a zone **signed here**: `online-signing` or `inline-signing`;
- a zone that **accepts changes**: `allow-updates`, `allow-child-updates`,
  `allow-api-updates`, or `allow-edits` (the combiner's edits).

On tdns-auth a secondary may originate content only when it is inline-signing,
and the configuration parser strips the update options from any other
secondary (`normalizeOptionsForRole`). So on tdns-auth the zones unified are
the primaries and the inline-signing secondaries. A derived app that did not
register for the invariant has its zones' options decide.

Every other zone is a copy of its upstream: a plain secondary, a secondary
whose zone file is a saved copy of a transfer. It is served as received, mixed
TTLs included, and the adoption logs a warning naming the RRsets whose TTLs
differ (at most ten, with the count).

**The unification never breaks a ZONEMD this server does not compute.** A ZONEMD
covers every record's TTL, so unifying content that carries one leaves a
digest that no longer describes the zone, and a downstream that verifies it
(`verify-zonemd`, whose default is to refuse) rejects the zone. So even in a
zone told to modify, content with an apex ZONEMD is unified only when this
server computes the zone's ZONEMD itself (`publish-zonemd`, `zoneManagesZonemd`).
That digest is computed again at the publish, after the unification. Without
it the content is served as received, with the same warning. This holds for a
zone signed here as well: the ZONEMD it carries is not ours to break, and the
warning tells the operator to fix the TTLs at the source or to have this
server compute the digest.

## Where it runs

`applyRefreshReplacementLocked` (`v2/zone_mutation.go`), the step that every
zone file load (first load and reload), AXFR and applied IXFR delta goes
through, decides (`adoptedTTLsUnify`) and then unifies (`unifyAdoptedTTLs`)
or warns (`mixedTTLRRsets`). Each RRset whose TTLs differ goes to the largest
of them. Each record whose TTL changes is replaced by a copy, so no record
that a published snapshot may share is written in place.

Where in that function, and why:

- **After the inbound ZONEMD gate.** A ZONEMD digest covers each record's TTL,
  so the gate has to see the TTLs as they arrived.
- **After the journal overlay**, whose records join the RRsets of the
  replacement.
- **Before the working set is built from the replacement.** Four later steps
  compare the new content with what is already served, and that content is
  unified as the new content is: carrying the signatures of unchanged RRsets
  across a reload (#1015, `identicalRecords` compares TTLs), the restart
  digest (#1011), the refusal of a file signed elsewhere that changed under
  the served serial (#1011, `ErrSignedFileChangedUnderServedSerial`), and the
  IXFR diff under `ixfr-from-differences`. If the unification came after them,
  every mixed-TTL RRset would count as changed on every reload: re-signed and
  put into the IXFR link, or, in an unchanged file signed elsewhere, refused.

An applied IXFR delta shares its untouched owners with the published snapshot,
so only the owners the delta touched are walked, for the unification and for
the warning alike.

Not touched:
- the SOA, which is a single record;
- NSEC, whose TTL follows the SOA's negative TTL (RFC 9077) and which is
  stored outside the ordinary RRsets;
- DNSKEY, in a zone that signs its own content. The signer rebuilds that RRset
  from its keystore, and that is part 2. In a zone that does not sign here
  DNSKEY is an ordinary RRset, unified like the others and capped by rule 3.

## A zone signed here, as against a copy signed elsewhere

**A zone that signs its own content** (online or inline signing) unifies to
the largest TTL with no cap. A rewritten RRset loses the RRSIGs it came with,
and the publish signs it again, so the new signature's original TTL is the
unified TTL.

**A copy signed elsewhere** that this server is told to modify -- in practice
a primary whose zone file was signed by another signer -- keeps the signatures
it came with, because it has no keys to sign again. So the unified TTL is the
largest record TTL, but never above the smallest original TTL among the RRSIGs
that cover the RRset (rule 3). A validator would cap the TTL at the original
TTL anyway (RFC 4035 §5.3.3). The RRSIGs stay as they came, except for their
own TTL, which follows the RRset (RFC 4034 §3). The signature does not cover
that TTL. An RRset with no RRSIGs, such as a delegation's NS RRset or glue,
takes the largest TTL with no cap.

An RRset whose records already share one TTL is left as it came, even when
that TTL is above the original TTL of its RRSIGs. Nothing is rewritten, so
rule 3 does not apply, and a validator caps it at the original TTL anyway.

A signed secondary this server only relays is not touched at all (rule 4).

## The order: unify, then clamp

The served-TTL clamp (`ttls.max-served`, #949, and the KSK rollover K-step
clamp, `v2/ksk_rollover_clamp.go`) applies only when this server signs. It
runs inside `SignRRset`. `applyClampToRRset` records the RRset's own TTL from
its first record in `UnclampedTTL`, then serves
`min(UnclampedTTL, ceiling)`.

Unification runs when the content is adopted, before anything is signed. By
the time the clamp reads the first record, every record has the largest TTL,
so the clamp starts from the largest. Records 300 and 7200 under a max-served
of 600 are served at 600 and signed for 600. If the clamp ran first, it would
take 300 from whichever record came first.

A zone that does not sign here is never clamped: the clamp is a signing
policy.

**The negative-TTL / SOA guard is unaffected.** #1015 does not carry NSECs
across a reload when the SOA's negative TTL changed, or when the clamp may
lower it (`clampMayLowerLocked`). Unification never changes the SOA, so the
negative TTL that guard compares is the file's, as before.

## UPDATE

`setRRsetTTL` (`v2/zone_updater.go`) gives the RRset the larger of the added
record's TTL and the RRset's own TTL. It is used by both the zone and the child
update appliers. For an RRset the signer has clamped, the RRset's own TTL is
`UnclampedTTL`, as before #996, and signing clamps the records again.

What changes for operators: **an add can raise an RRset's TTL but no longer
lower it.** Lowering takes a replacement: delete the RRset and add its records
in the same update (`replacerrset`). A DDNS child adding a record at the
update-policy TTL leaves an RRset with a longer TTL at that longer TTL. A
duplicate add at a higher TTL still raises the RRset to it, since
`dns.IsDuplicate` ignores TTLs.

## Side effects

- **The first start after the upgrade** can lift the serial once for a primary
  with mixed TTLs in its zone file. The restart digest the old binary recorded
  was over content that was not unified, and the new content is, so they
  differ. That costs one extra transfer, once.
- **A later IXFR delete still matches** in a secondary that unifies. Inbound
  deletes match records with `core.IsDuplicate`, which ignores the TTL. A
  delete the primary sends at the record's original TTL still finds the record
  that is now held at the unified TTL.
- **A relay of a zone with mixed TTLs warns** at every adoption that brings
  them: each AXFR, and each IXFR delta that touches such an RRset.

## Tests

In `v2/rrset_ttl_test.go`:

- `TestLoadOfMixedTTLsServesTheLargest`: a zone file with an RRset at 300 and
  3600 is served at 3600 after the first load. After a reload with 60/3600/7200
  it is served at 7200. An RRset at one TTL keeps it.
- `TestAxfrOfMixedTTLs`: a primary serves 300/3600 over AXFR. A plain
  secondary serves 300/3600 and warns, and so does one whose transfer carries
  a ZONEMD, which still describes what it serves. A secondary told to modify
  its zone (`allow-edits`, in a derived app) serves 3600.
- `TestIxfrOfMixedTTLs`: in a secondary told to modify its zone, a delta
  adding a record at 7200 to an RRset at 3600 raises it to 7200, one adding a
  record at 300 leaves 7200, and a delete at the record's original 300 still
  matches; untouched owners stay as they were. In a plain secondary the delta
  is served as it came, 3600 and 7200, with the warning.
- `TestCopySignedElsewhereIsNeverRaisedAboveTheOriginalTTL`: a zone file
  signed elsewhere with records at 300 and 3600. Under an RRSIG with an
  original TTL of 1800 it is served at 1800. Under one of 7200 it is served at
  3600. The signature is unchanged, and its own TTL follows the RRset.
- `TestZonemdNotComputedHereKeepsTheTTLs`: a zone file with records at 300 and
  3600 and a ZONEMD over them is served as it arrived, its ZONEMD still
  matching, with the warning. With `publish-zonemd` it is served at 3600, and
  the ZONEMD it computes describes the unified zone.
- `TestReloadOfAnUnchangedSignedFileWithMixedTTLsPublishesNothing`: a file
  signed elsewhere, reloaded unchanged at the served serial, is neither
  published nor refused. The content compare sees unified content on both
  sides.
- `TestSignedZoneUnifiesThenClamps`: records 300 and 7200 in a zone signed
  here are served and signed at 7200. Under a max-served of 600 they are served
  and signed at 600, and both cases validate.
- `TestSignedReloadOfMixedTTLsKeepsTheSignature`: a reload whose mixed-TTL
  RRset unifies to what is already served keeps its signature (#1015's carry).
- `TestToldToModify`: on tdns-auth, a primary and an inline-signing secondary
  are told to modify; a plain secondary is not, nor one with `allow-updates`
  left on. In a derived app, a secondary is told to modify by `allow-edits`,
  `allow-api-updates` or `online-signing`, and not without them.
- `TestUnifyAdoptedTTLs`: DNSKEY is left alone in a zone that signs here and
  unified in one that does not. An owner outside the given set is not walked.
  Records are copied, not written in place.

The tests that expect a unified RRset fail with the call in
`applyRefreshReplacementLocked` taken out. The plain-secondary tests fail with
the `toldToModify` check taken out, and the ZONEMD test with the ZONEMD check
taken out.

In `v2/zone_updater_ttl_test.go` and `v2/update_ttl_clamp_test.go`, #767's
tests were rewritten for the new rule. A DDNS, API or child add below the
RRset's TTL leaves the RRset's TTL. One above it raises the RRset to it. A
replacement lowers it. On a clamped RRset, an add below its own TTL changes
nothing, an add above it raises `UnclampedTTL` and is still served at the
clamp, and a replacement at 60 is served at 60.

## Changes from the first version

The first version unified every adopted zone, plain secondaries included, and
capped a relayed signed copy at its signatures' original TTL. A review found
that a relayed zone carrying a ZONEMD over mixed TTLs was then served with a
digest that no longer described it, which a downstream that verifies ZONEMD
refuses. Rule 4 followed: a plain secondary is now served as received, and a
ZONEMD this server does not compute is never broken by the unification, in
any zone.
