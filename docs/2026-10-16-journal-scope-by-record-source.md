# The journal of a transferred zone, scoped by record source

- **Status:** PROPOSAL, 2026-10-16. No code yet.
- **Issues:** #919, #732. Builds on #922 (open), which discards a transferred
  zone's journal at first load when it does not start at the serial received.
  #923 (open) anchors the journal to the zone file a refresh writes. This note
  is independent of it.
- **Related:** `docs/2026-09-24-journal-overlay-on-transfer.md` (the overlay),
  `docs/2026-09-24-cds-publication-and-rfc-conformance.md` §1.2 (the CDS
  follows the keys).

## 1. Summary

- Today, which records a signing secondary keeps across a full transfer is
  decided per zone, by app type and the multi-provider option: the overlay
  applies to an inline-signing secondary on tdns-auth that is not
  multi-provider.
- The question that matters is per record: **does anything put it back after
  a full transfer?** CDS and CDNSKEY usually have such a source, the DS engine,
  which derives them from the keys. CSYNC, and a CDS published by delegation
  sync under `cds: false`, have none.
- Proposal: treat CDS and CDNSKEY as **derived data**, like NSEC, on a zone
  whose DS engine publishes them on its own. They are then not journalled. The
  journal, and so the overlay, keeps only what has no second source.
- This stops the journal of a zone outside the overlay from growing by one dead
  delta per full transfer. It also stops a stale CDS from coming back out of the
  journal.

## 2. Where we are

### 2.1 Two kinds of transferred zone

| | Overlay zone | Other journalling secondary |
|---|---|---|
| Which | tdns-auth or tdns-signer, inline-signing, not multi-provider | multi-provider zones; signing secondaries of other apps (tdns-mpsigner) |
| Journal anchored to | the served serial (own serial space) | the serial received, or the journal's tail |
| At a full transfer | CDS, CDNSKEY and CSYNC re-applied; journal compacted | journal untouched and not applied |
| At restart | not replayed; the overlay already applied it | replayed if it starts at the serial received; otherwise discarded (#922) |

### 2.2 What is journalled on a transferred zone, and who puts it back

| Record | Published by | After a full transfer |
|---|---|---|
| DNSKEY, SIG(0) KEY | the keystore | put back by the transfer itself (`CollectDynamicRRs`); not journalled |
| CDS + CDNSKEY, owned multi-provider zone signed here | the DS engine, from the owner's DS set (KLO arrow 1) | put back by the transfer (`ownedZoneCDS`), and the DS engine keeps it in step |
| CDS + CDNSKEY, `none` model, signed here, not multi-provider, `cds:` not false | the DS engine, from the keys (always published) | **put back by the DS engine's next run**, about 10 s after the transfer in the runs behind #919 |
| CDS + CDNSKEY, `none` model with `cds: false` | delegation sync, or by hand | **nothing**: the engine follows a CDS only while one is served |
| CDS + CDNSKEY, `multi-ds` | the rollover engine, through the DS engine | the rollover engine's next push |
| CSYNC | delegation sync over NOTIFY, with `allow-updates` | **nothing** |
| anything an operator adds by API or UPDATE | the zone updater | **nothing**, by decision (2026-09-24, #732): local edits to the upstream's data are lost at a full transfer |

The overlay was designed before the always-published rule existed. The overlay
merged at 09:49 on 2026-09-24 (#747), and the DS engine rule at 18:05 the same
day (#761). The overlay document's §1 table ("gone for good" under `none`)
describes the engine as it was before #761.

### 2.3 What goes wrong

On a zone outside the overlay, the DS engine re-derives CDS and CDNSKEY after
every full transfer. The publish is journalled as a new delta from the
journal's tail. The journal is never applied, so it only grows, until a restart
discards it (#922). In the deployment behind #919, each multi-provider zone's
journal held the same CDS/CDNSKEY pair three times
(1792143556 → 559 → 579 → 582), one per full transfer. By the table above,
the transfer should have carried an owned zone's CDS (`ownedZoneCDS`). Why
the engine still re-added the pair has not been checked yet (Q4).

Two further effects:

- **A refused CDS publish.** On a zone outside the overlay with an empty
  journal, the DS engine's publish is journalled from the serial received to
  the signer's next serial. It is refused when the upstream's serial is ahead
  (the overlay design's §3), and the CDS publish fails with it.
- **A stale CDS.** A journalled CDS that is replayed or overlaid can name a key
  the keys no longer warrant, until the engine's next run corrects it.

## 3. The principle

The journal carries what this server authored and cannot get back any other
way. What it derives again from state it already holds is derived data. NSEC,
and a ZONEMD the zone manages itself, are already left out of the journal for
that reason (`withoutDerivedRecords`): journalling them reinstates records
nobody authored, and a file merge then reports conflicts on them.

A CDS the DS engine publishes on its own, from the keys or from the owner's DS
set, is derived in the same sense.

## 4. Proposed rules

**R1. CDS and CDNSKEY are derived data on a zone whose DS engine publishes them
on its own.** That means either of these:

- an owned multi-provider zone signed here;
- a zone signed here under `none`, whose keys tdns manages, with the
  always-published rule in effect: `cds:` not false, or a zone in child
  delegation-sync mode.

On such a zone they are left out of the journal, as NSEC is. Everywhere else
they are journalled as today. The predicate also requires that the DS engine
runs in this app (`StartAuth`, `StartAgent`, and apps built on them); where it
does not, nothing re-derives them.

**R2. The overlay mechanism is unchanged.** It applies the zone's own records
that are in the journal. Under R1, a zone whose DS engine publishes on its own
has no CDS or CDNSKEY in its journal, so its overlay holds only CSYNC. After a
full transfer the CDS comes back with the engine's next run, not with the
transfer. Under RFC 7344 an absent CDS asks the parent for no change, so the
gap does nothing on the wire. On a zone where the engine does not publish on
its own, CDS and CDNSKEY stay in the journal and the overlay, as today.

**R3. A zone outside the overlay keeps today's journal handling.** Under R1 the
DS engine's publishes no longer reach its journal. What is left there is
operator edits, CSYNC, and a CDS with no second source. That accumulates only
at the rate those records change, and #922's restart discard still clears it
once the upstream has moved on.

**R4. Nothing else changes:** not the overlay predicate, not the decision that
local edits are lost at a full transfer, not #922.

## 5. Effects

- The per-transfer growth on zones outside the overlay stops.
- The DS engine's CDS publish on such a zone writes no delta, so the refusal
  in the overlay design's §3 can no longer hit it.
- A stale CDS cannot come back out of the journal.
- Cost: on an overlay zone under `none`, the CDS is absent for one engine run
  after each full transfer, about 10 s.
- Size: small. A per-zone predicate beside `withoutDerivedRecords`, used only
  for the journal delta. The IXFR chain keeps everything. Tests for the
  predicate's cases and for both kinds of zone.

## 6. Open questions

- **Q1. Primaries too?** R1 as written applies to any zone. On a primary, a
  derived CDS left out of the journal is still written to the file by
  `zone write`. After a restart without a write, it is absent until the
  engine's next run. A file merge would stop reporting conflicts on a CDS
  nobody authored. Apply to all zones (recommended), or only to transferred
  ones?
- **Q2. Signing secondaries of other apps, not multi-provider.** They have no
  overlay. CSYNC, and a CDS with no second source, are lost at every full
  transfer: #732, for them. The overlay predicate excludes them by app type,
  not by anything about their records. Extend the overlay to them, now that it
  would carry only records with no second source?
- **Q3. Evaluated when?** R1 is decided at each publish. If `cds: false` is
  turned on, or multi-provider ownership moves away from this signer, a CDS
  that was derived and not journalled is not published again after the next
  full transfer. That matches what both settings mean. Confirm.
- **Q4. Why the owned cells re-added the pair.** In the #919 runs, the
  multi-provider zones' journals show the DS engine adding CDS and CDNSKEY
  after each full transfer, although `ownedZoneCDS` should have carried them
  across. Had it carried the CDS, the journal would show at most a CDNSKEY add,
  so the transfer did not carry the CDS. Why is not known: ownership as seen
  by the refresh path and by the DS engine may differ at that moment. Worth
  checking before R1 is built. It does not change R1, since the pair is
  derived either way.
