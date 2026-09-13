# The child-side DS engine

Written 2026-09-13. Step 1 implemented on branch `feat/ds-engine-cds`.

## Why

What a child asks its parent to hold as DS had two half-owners and a gap
between them.

- **Delegation sync** knows what the parent should hold (`DSIntentForZone`,
  keystore-driven) and pushes it over UPDATE or the DSYNC API. Its NOTIFY scheme
  sent NOTIFY(CDS) with no CDS behind it: nothing in tdns publishes a CDS for a
  zone the KSK rollover engine does not manage. The only general publisher,
  `PublishCdsRRs`, sits in the delegation syncher's `SYNC-DNSKEY-RRSET` arm, and
  nothing in tdns sends that command since the multi-provider code moved to
  tdns-mp. The parent scans, finds no CDS, concludes there is nothing to do, both
  ends report success, and the DS never appears. Because the plan walk stops at
  the first success, UPDATE or API is never tried either.
- **The KSK rollover engine** publishes CDS for its own target set, pushes DS
  itself, and removes its CDS after the parent confirms. Its publish is
  queue-and-forget, so the NOTIFY that follows can race it -- #507's shape.
- The only coordination is a lock-out: `rolloverOwnsDS` makes delegation sync
  leave the DS alone while a rollover phase is busy.

A child-side DS engine that both send their requests to replaces that with one
owner.

## DS models

The engine cannot be a "make sure key K has a CDS" service. Which DS belong at
the parent, and when one may be withdrawn, depends on how the zone rolls its
keys:

| Model | Source | Target DS set |
|---|---|---|
| `none` | no automated rollover (`rollover.method: none` or no policy) | `DSIntentForZone`: KSKs from `ds-published` to `active` |
| `multi-ds` | `rollover.method: multi-ds` | the rollover target (`loadTargetKSKsForRollover`: `created` to `retired`), a pipeline of pre-published DS |
| `double-signature` | `rollover.method: double-signature` | the new key is published and signs alongside the old one before the DS is swapped; accepted by the policy parser, not implemented by the rollover engine |
| `multi-provider` | zone option `multi-provider` | every provider's KSK: the SEP keys of the served DNSKEY RRset, which carries them all |

Every request the engine serves starts by asking the zone's model for the target,
and a model the engine does not implement is refused by name rather than
approximated.

## What the engine owns

Eventually: the served CDS RRset, publish-and-wait before any NOTIFY(CDS), the
UPDATE and API DS pushes, confirmation that the parent holds the target, and
periodic reconciliation of target against parent. Clients state what they need;
the engine decides what goes on the wire.

## Steps

1. **CDS publication.** (This branch.)
   - The engine is a goroutine (`KeyDB.DSEngine`, queue `KeyDB.DSEngineQ`),
     started next to the delegation syncher in tdns-auth and tdns-agent.
   - The rollover engine is a client: its NOTIFY push asks the engine to publish
     the rollover target's CDS, and its cleanup triggers ask the engine to release
     it. Behaviour is unchanged except that the publish, and the unpublish, now
     wait until the zone serves the result.
   - Delegation sync's NOTIFY scheme asks the engine for the CDS its model wants
     before it sends NOTIFY(CDS). A refusal fails that candidate, so the plan moves
     on to UPDATE or API instead of reporting a vacuous success. Under `multi-ds`
     with a rollover phase in flight the engine answers "deferred": the DS is the
     rollover's, and no NOTIFY(CDS) is sent for it.
   - The `SYNC-DNSKEY-RRSET` arm asks the engine instead of publishing directly.
2. **Pushes.** Move the UPDATE and API DS pushes, and confirmation polling, into
   the engine; `rolloverOwnsDS` disappears.
3. **Reconciliation.** Periodic comparison of each zone's target with the
   parent's DS, from the engine. This also covers a child whose one-shot sync
   failed at startup.
4. **double-signature.** When the rollover engine implements it, the model's
   target moves into the engine with it.

## CDS lifecycle per model in step 1

- **`multi-ds`.** Unchanged ownership rules: the engine records the rollover
  target's index range (`last_published_cds_index_low/high`) when it publishes,
  and releases the CDS on the rollover's cleanup triggers with the existing
  compare-on-cleanup. A CDS published on delegation sync's behalf is recorded the
  same way, so the rollover's cleanup covers it; if the target has keys without a
  rollover index the engine refuses, because nothing could ever clean that CDS
  up.
- **`none`.** The CDS stays published once delegation sync has asked for it, and
  follows the keys, as BIND and Knot keep theirs. A CDS left behind after the keys
  change is the dangerous case -- a parent that polls CDS would point the DS at
  keys the zone no longer uses -- so `PublishDnskeyRRs`, the one place the apex
  DNSKEY RRset is built from the keystore, tells the engine when a zone that
  serves a CDS changes its KSK set, and the engine brings the CDS back to the
  target, or withdraws it when no key warrants a DS. Removal after the parent
  confirms arrives with step 2's confirmation polling.
- **Keys tdns does not manage** (a zone signed elsewhere). The engine writes no
  CDS. If the zone already serves one, published by its signer, delegation sync's
  NOTIFY(CDS) points the parent at it; if it serves none, the NOTIFY candidate
  fails.
- **`multi-provider`.** The engine publishes the SEP keys of the served DNSKEY
  RRset, which is what the `SYNC-DNSKEY-RRSET` arm did. The multi-provider agent in
  tdns-mp publishes its own CDS and is not changed.
- **`double-signature`.** Refused.

Withdrawing a DS through CDS needs an RFC 8078 delete CDS, which tdns does not
publish; the engine refuses to publish an empty target and delegation sync falls
back to UPDATE or API.

## Not in step 1

- The UPDATE and API pushes, confirmation polling, periodic reconciliation.
- `PublishCdsRRs`, `UnpublishCdsRRs` and `SynthesizeCdsRRs` stay exported: tdns-mp
  calls them. Inside tdns every CDS write goes through the engine.
- tdns-mp builds `RolloverEngineDeps` for the rollover engine and has to start
  `KeyDB.DSEngine` when it next re-pins tdns; without it a NOTIFY-scheme DS push
  fails with a local error instead of racing its CDS.
