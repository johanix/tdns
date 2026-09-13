# The child-side DS engine

Written 2026-09-13. Step 1 implemented on branch `feat/ds-engine-cds`.

Revisions:
- r1 2026-09-13: first version.
- r2 2026-09-13: step 2 re-scoped. The DS engine does not talk to the parent;
  the rollover engine's DS pushes move into the delegation syncher, not into the
  DS engine. Added "Why not inside the delegation syncher".

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
- **The rollover engine carries its own copy of delegation sync's transport**:
  scheme selection (`pickRolloverSchemes`) and UPDATE, NOTIFY and API push paths
  (`pushDSRRsetViaUpdate`, `pushDSRRsetViaNotify`, `pushDSRRsetViaApi`), beside
  the delegation syncher's plan walk and senders. Two components talk to the
  same parent about the same delegation, and in replace mode delegation sync's
  UPDATE rewrites the DS as well.
- The only coordination is a lock-out: `rolloverOwnsDS` makes delegation sync
  leave the DS alone while a rollover phase is busy.

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

## The split

- **The DS engine** owns what a zone asks its parent to hold as DS: the DS model,
  the CDS RRset and its lifecycle, and the criterion for the parent's DS being
  in step (does the parent hold the model's target). It does not talk to the
  parent.
- **The delegation syncher** is the one component that talks to the parent, for
  NS, glue and DS alike: DSYNC discovery, the plan, the UPDATE, NOTIFY and API
  senders.
- **The KSK rollover engine** runs the key state machine. It tells the DS engine
  what its phase needs and hands DS delivery to the delegation syncher, instead
  of pushing itself.

## Why not inside the delegation syncher

Folding CDS ownership into the delegation syncher, rather than a separate engine,
was considered after step 1 was built. It was not chosen:

- **Different knowledge, different triggers.** The syncher answers "how does
  delegation data reach the parent". The CDS answers "which DS does this zone
  want", from the keystore and the rollover state, and changes on key events
  (`PublishDnskeyRRs`), not delegation events. CSYNC sits naturally with the
  syncher because its content is NS and glue; CDS content is key data.
- **Latency.** The syncher is one goroutine doing network round trips for every
  zone; a plan walk can take tens of seconds, and some senders take no context. A
  rollover tick asking for its CDS would wait behind other zones' parent traffic.
  The DS engine answers from the keystore and the zone updater.
- **The queue.** `DelegationSyncQ` holds ten requests and the zone updater sends
  `SYNC-DELEGATION` into it with a blocking send. The key-change notification
  runs with the zone lock held and must be non-blocking; in that queue it would
  be dropped exactly when the syncher is busy.

The duplication that matters is the transport, and step 2 removes it.

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
2. **One transport.** The rollover engine's DS pushes (`pickRolloverSchemes`,
   `pushDSRRsetViaUpdate`, `pushDSRRsetViaNotify`, `pushDSRRsetViaApi`) move into
   the delegation syncher, which already discovers the parent's schemes and walks
   them for NS and glue. The rollover hands its DS to the syncher; the syncher
   asks the DS engine for the CDS as delegation sync does in step 1.
   `rolloverOwnsDS` disappears: with one sender there is nothing to lock out.
   Where confirmation polling lives is settled in this step; the criterion is the
   DS engine's.
3. **Reconciliation.** Periodic comparison of each zone's DS target (from the DS
   engine) with the parent's DS, handing a zone that is out of step to the
   syncher. This also covers a child whose one-shot sync failed at startup.
4. **double-signature.** When the rollover engine implements it, the model's
   target moves into the DS engine with it.

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
  confirms comes with confirmation in step 2.
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

- The rollover engine's own parent pushes, which step 2 moves into the delegation
  syncher; confirmation; periodic reconciliation.
- `PublishCdsRRs`, `UnpublishCdsRRs` and `SynthesizeCdsRRs` stay exported: tdns-mp
  calls them. Inside tdns every CDS write goes through the engine.
- tdns-mp builds `RolloverEngineDeps` for the rollover engine and has to start
  `KeyDB.DSEngine` when it next re-pins tdns; without it a NOTIFY-scheme DS push
  fails with a local error instead of racing its CDS.
