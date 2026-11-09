# One TTL per RRset, the largest: on load, on transfer, on UPDATE

**Written 2026-11-09.** For #996, part 1. Stacked on #1015
(`claude/1006-reload-signatures`), which changes the same load path.

**Status:** implemented on `claude/996-rrset-ttl-unify`. Part 2, the DNSKEY
RRset and the keystore rows, is not in this change.

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
3. **A relayed copy that is already signed**: a rewritten TTL never goes above
   the covering RRSIG's original TTL.

## What this change does

### Load and transfer: one place

`unifyAdoptedTTLs` (`v2/rrset_ttl.go`) runs once in
`applyRefreshReplacementLocked`, the step that every zone file load (first
load and reload), AXFR and applied IXFR delta goes through. Each RRset whose
TTLs differ goes to the largest of them. Each record whose TTL changes is
replaced by a copy, so no record that a published snapshot may share is
written in place.

Where in that function it runs, and why:

- **After the inbound ZONEMD gate.** A ZONEMD digest covers each record's TTL,
  so the gate has to see the TTLs as they arrived. Unify first, and a zone
  that carries a correct ZONEMD over mixed TTLs would fail verification.
- **After the journal overlay**, whose records join the RRsets of the
  replacement.
- **Before the working set is built from the replacement.** Four later steps
  compare the new content with what is already served, and that content is
  now unified: carrying the signatures of unchanged RRsets across a reload
  (#1015, `identicalRecords` compares TTLs), the restart digest (#1011), the
  refusal of a file signed elsewhere that changed under the served serial
  (#1011, `ErrSignedFileChangedUnderServedSerial`), and the IXFR diff under
  `ixfr-from-differences`. If the unification came after them, every
  mixed-TTL RRset would count as changed on every reload: re-signed and put
  into the IXFR link, or, in an unchanged file signed elsewhere, refused.

An applied IXFR delta shares its untouched owners with the published snapshot,
so only the owners the delta touched are walked. The rest were unified when
they arrived.

Not touched:
- the SOA, which is a single record;
- NSEC, whose TTL follows the SOA's negative TTL (RFC 9077) and which is
  stored outside the ordinary RRsets;
- DNSKEY, in a zone that signs its own content. The signer rebuilds that RRset
  from its keystore, and that is part 2. In a relayed zone DNSKEY is an
  ordinary RRset and is unified like the others, capped by rule 3.

### A zone this server signs, as against a signed copy it only relays

**A zone that signs its own content** (online or inline signing) unifies to
the largest TTL with no cap. A rewritten RRset loses the RRSIGs it came with,
and the publish signs it again, so the new signature's original TTL is the
unified TTL. The signatures a zone file or upstream brought are not this
server's anyway; the publish signs over them.

**A relayed copy** (a secondary of a signed zone, or a zone file signed
elsewhere) keeps the signatures it came with, because it has no keys to sign
again. So the unified TTL is the largest record TTL, but never above the
smallest original TTL among the RRSIGs that cover the RRset (rule 3). A
validator would cap the TTL at the original TTL anyway (RFC 4035 §5.3.3). The
RRSIGs stay as they came, except for their own TTL, which follows the RRset
(RFC 4034 §3). The signature does not cover that TTL. An RRset with no RRSIGs
in a relayed signed zone, such as a delegation's NS RRset or glue, takes the
largest TTL with no cap.

An RRset whose records already share one TTL is left as it came, even when
that TTL is above the original TTL of its RRSIGs. Nothing is rewritten, so
rule 3 does not apply. The upstream serves it that way, and a validator caps
it at the original TTL anyway. Pulling it down would change the content of
zones that already keep RFC 2181 §5.2, and a ZONEMD over that content would
stop matching.

### The order: unify, then clamp

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

A relayed copy is never clamped: the clamp is a signing policy.

**The negative-TTL / SOA guard is unaffected.** #1015 does not carry NSECs
across a reload when the SOA's negative TTL changed, or when the clamp may
lower it (`clampMayLowerLocked`). Unification never changes the SOA, so the
negative TTL that guard compares is the file's, as before.

### UPDATE

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

- **The first start after the upgrade** can lift the serial once for a
  file-backed zone with mixed TTLs. The restart digest the old binary recorded
  was over content that was not unified, and the new content is, so they
  differ. That costs one extra transfer, once.
- **A later IXFR delete still matches.** Inbound deletes match records with
  `core.IsDuplicate`, which ignores the TTL. A delete the primary sends at the
  record's original TTL still finds the record that is now held at the
  unified TTL.
- **A relayed zone that carries a ZONEMD over mixed TTLs** is served with the
  TTLs unified. Its ZONEMD then no longer matches what this server serves.
  That ZONEMD came from a zone that broke RFC 2181 §5.2 in the first place.

## Tests

In `v2/rrset_ttl_test.go`:

- `TestLoadOfMixedTTLsServesTheLargest`: a zone file with an RRset at 300 and
  3600 is served at 3600 after the first load. After a reload with 60/3600/7200
  it is served at 7200. An RRset at one TTL keeps it.
- `TestAxfrOfMixedTTLsServesTheLargest`: a primary serves 300/3600 over AXFR,
  and the secondary serves 3600.
- `TestIxfrOfMixedTTLsServesTheLargest`: a delta adding a record at 7200 to an
  RRset at 3600 raises it to 7200. One adding a record at 300 leaves 7200. A
  delete at the record's original 300 still matches, and untouched owners stay
  as they were.
- `TestRelayedSignedCopyIsNeverRaisedAboveTheOriginalTTL`: a signed copy
  received over AXFR with records at 300 and 3600. Under an RRSIG with an
  original TTL of 1800 it is served at 1800. Under one of 7200 it is served at
  3600. The signature is unchanged, and its own TTL follows the RRset.
- `TestReloadOfAnUnchangedSignedFileWithMixedTTLsPublishesNothing`: a file
  signed elsewhere, reloaded unchanged at the served serial, is neither
  published nor refused. The content compare sees unified content on both
  sides.
- `TestSignedZoneUnifiesThenClamps`: records 300 and 7200 in a zone signed
  here are served and signed at 7200. Under a max-served of 600 they are served
  and signed at 600, and both cases validate.
- `TestSignedReloadOfMixedTTLsKeepsTheSignature`: a reload whose mixed-TTL
  RRset unifies to what is already served keeps its signature (#1015's carry).
- `TestUnifyAdoptedTTLs`: DNSKEY is left alone in a zone that signs here and
  unified in a relay. An owner outside the given set is not walked. Records
  are copied, not written in place.

All of the end-to-end tests above fail with the call in
`applyRefreshReplacementLocked` taken out.

In `v2/zone_updater_ttl_test.go` and `v2/update_ttl_clamp_test.go`, #767's
tests were rewritten for the new rule. A DDNS, API or child add below the
RRset's TTL leaves the RRset's TTL. One above it raises the RRset to it. A
replacement lowers it. On a clamped RRset, an add below its own TTL changes
nothing, an add above it raises `UnclampedTTL` and is still served at the
clamp, and a replacement at 60 is served at 60.
