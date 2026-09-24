# CDS publication and the CDS RFCs: a design for #736, #752, #753, #755, #756 and #757

**Written 2026-09-24.** Line references are to main at `81a22644`.

**Status:** proposal, reviewed. Johan answered §8 on 2026-09-24. He then decided that the CDS is always published, with telling the parent gated by `parentsync` (1.2 (a), (c)), and answered Q10. The doc is written to those decisions and to three external reviews. Part 1 is implemented and merged (PR #761, 6d3e5aaf). Part 2 is implemented and merged (PR #766, 18c23c11). Part 3 is implemented in the PR that adds its §10 entry, not merged. Parts 4 and 5 are not implemented.

## Summary

A check of tdns against RFCs 7344, 8078, 9615, 9975, 8901 and 9859 found gaps on both sides. Five of the resulting issues are designed here, and so is #736, which Part 1 closes with #752. #754 (RFC 9975 consistency in the scanner) is not.

| Part | Issue | What | Priority |
|---|---|---|---|
| 1 | #752, #736 | A served CDS goes stale when a KSK's DS status changes without a DNSKEY change; a zone that serves no CDS is never followed; nothing compares the parent's DS with the keys on its own; neither a follow-keys change nor an operator's edit of CDS, CDNSKEY or CSYNC tells the parent | **first; a route to a bogus zone** |
| 2 | #755 | The parent treats any algorithm-0 CDS as the delete signal | second; small and dangerous |
| 3 | #757 | DSYNC RR presentation, port 0, the root's `_dsync` name | third |
| 4 | #753 | The child publishes CDS but never CDNSKEY; the parent never checks CDNSKEY | fourth |
| 5 | #756 | NOTIFY receiver: no rate limiting, multi-zone NOTIFY accepted, Report-Channel unused | fifth |

Each part is its own PR, in that order. Part 1 stands alone.

Sizes are in §7, and the questions with Johan's answers in §8.

## 1. #752 and #736: publish the CDS the keys call for, and tell the parent

### 1.1 What goes wrong

The DS engine owns the CDS RRset (`v2/ds_engine.go`). For a zone that serves a CDS, `followKeysWithCDS` (`:435`) makes that RRset match the DS intent:
- the intent is the zone's SEP keys whose `ds` column is 1 (`DSIntentForZone`, `v2/ds_intent.go`);
- the `ds` column is written at key state transitions, according to the zone's DS model (`v2/keyrow_ds.go:15-35`).

`followKeysWithCDS` has one trigger: `PublishDnskeyRRs`, when the zone serves a CDS **and** the set of SEP keys in the served DNSKEY RRset has changed (`v2/ops_dnskey.go:141`).

Two transitions change the intent without changing that set:

| Transition | Who | `ds` | Served SEP set |
|---|---|---|---|
| published → standby | key state worker (`v2/key_state_worker.go:208`) | 0 → 1 | unchanged; both states are published |
| manual KSK roll: standby → active, active → retired | `keystore dnssec rollover` with KSK (`RolloverKey`, `v2/keystore.go:1607`) | new 1 → 1, old 1 → 0 | unchanged; a retired key stays published, but no longer signs (`v2/keyrow.go:69-80`) |

A scratch test, with `rollover.method: none` and real keys, confirmed the result:
- a standby KSK's DS is never offered through CDS;
- after a manual roll, the zone serves a CDS naming only the retired key.

A parent that follows that CDS keeps a DS for a key that no longer signs the DNSKEY RRset, and the zone is bogus.

The exported `KeysChanged` (`v2/ds_engine.go:214`) exists for this purpose, but nothing in tdns or tdns-mp calls it.

There is a second reason the trigger is late. After a keystore change, the DNSKEY RRset is republished only by the next signing pass. `republishSigningKeysForZone` (`v2/signing_keys_snapshot.go:102`) rebuilds the signing-key snapshot and publishes nothing.

When `followKeysWithCDS` does change the CDS, it sends no NOTIFY (RFC 9859 §4.2, SHOULD). Nor does an operator's edit of the CDS, CDNSKEY or CSYNC through the management API or DNS UPDATE.

**A zone that serves no CDS is never followed (#736).** A zone serves a CDS only after delegation sync has asked for one (`v2/ds_engine.go:443-448`), and only a sync over the NOTIFY scheme asks (`v2/delegation_sync.go:621-622`). Nothing compares the parent's DS with the keys on its own: not at the first signing, not at a restart, not after a KSK changed by hand. So:
- A zone signed while its parent already held the right DS serves no CDS. Nor does any zone whose parent takes UPDATE or API.
- For those zones, neither transition in the table reaches the parent.
- As long as the CDS stays conditional, the fixes below would not reach them either.

**A downstream agent sees only what is served.** A `parentsync-proxy` agent downstream of the signer acts on the zone it transfers (`ProxyDelegationPreRefresh`, `v2/delsync_proxy.go:59`):
- A changed CDS or DNSKEY RRset makes it send NOTIFY(CDS), which points the parent at the served CDS. With no CDS served, the parent finds nothing.
- Over UPDATE or API it sends a DS for every published SEP key (`currentDelegationRRs`, `v2/delsync_proxy_update.go:403`), whatever the key's `ds` column says: standby, retired and just-published keys included.
- Neither transition in the table changes the DNSKEY RRset, so neither reaches the agent unless the CDS changes.

### 1.2 Design

The rule becomes: **the CDS follows the keys, not the history of the zone.** Publishing it is not gated by `parentsync`; telling the parent is.

**(a) Publish the CDS the keys call for, always.** The DS engine publishes a CDS equal to the DS intent, and keeps it equal, for every zone that:
- is signed here (online or inline signing), and serves its DNSKEY RRset;
- has DS model `none`;
- has keys tdns manages (`DSIntentForZone(…).Known`).

For these zones `followKeysWithCDS` loses its rule that a zone serving no CDS is left alone (`v2/ds_engine.go:443-448`). Owned multi-provider zones already work this way (`ownedZoneCDS`, `v2/ds_engine.go:579`).

- **Not gated by `parentsync`.** The signer is not always the one that talks to the parent. A `parentsync-proxy` agent downstream acts on the CDS it transfers, and with (a) there always is one. On an inline-signing secondary, the journal overlay keeps the CDS across upstream transfers (#732).
- **At startup.** The engine runs once for each such zone after the zone is loaded and signed; the backstop in (b) would reach it within a tick anyway. When the CDS survived the restart (journal replay, or the overlay), that run finds it matching and publishes nothing.
- **It stays published.** RFC 7344 §4.1 lets a child remove its CDS once the parent is in step, but does not require it. Keeping it means a parent that polls always sees the current state, and a NOTIFY never waits for a publish.
- **An empty intent** withdraws the CDS, as today.
- **Multi-DS zones** keep the rollover engine's CDS, unchanged.
- **One consequence:** a parent that bootstraps a delegation from CDS (RFC 9615, or a registry's own policy) can now make a signed zone secure without `parentsync`.
- **A policy setting turns (a) off (Q10).** `dnssec.policies.<p>.cds: true | false`, default `true`. It is for an operator who signs a zone but is not ready for a parent to act on its CDS. Two limits keep it from reopening #752 and #736:
  - **It suppresses only (a)'s own publish** of a CDS the zone does not serve. A CDS the zone already serves, whether published by hand or by delegation sync, is still followed by (b). Otherwise a manual roll under `false` would be the bogus-zone path again.
  - **It has no effect on a `parentsync` zone,** which publishes as under `true` and logs once at Info that the setting was ignored. `parentsync` is the operator asking tdns to tell the parent, and (c) learns of a KSK going to standby or being rolled only through the CDS changing. Without a CDS, an UPDATE or API parent would again never hear of either.
  - It governs (a) only: delegation sync, the rollover engine and an owned zone's CDS are unchanged. The re-re-review recommended no setting at all; Johan chose to have it.

**(b) Tell the DS engine whenever keys may have changed.** "Keys changed" is a hint, not a result. The engine compares the DS intent with the served CDS and publishes only when they differ (`followKeysWithCDS`, `v2/ds_engine.go:470-472`), so extra hints cost a comparison and nothing more.

- **Prompt hints.** Two places already mean "this zone's keys changed":
  - `republishSigningKeysForZone`, called after every keystore API transaction that changes key rows (`v2/keystore.go:451`, `:463`);
  - `triggerResign` (`v2/key_state_worker.go:520`), called after every key state worker transition and by owners (`TriggerResign`, `v2/key_lifecycle_owner.go:132`).

  Both call `kdb.KeysChanged(zd)` for the zone. It takes no zone lock and never blocks, so either call is safe. Neither needs to know whether the zone serves a CDS.
- **A backstop.** At the end of `checkAndTransitionKeys` (`v2/key_state_worker.go:110`), mark every zone (a) covers, every other zone that serves a CDS, and every owned zone signed here. This runs every `kasp.check-interval`, one minute by default. It catches writers that pass neither hook:
  - the DS reconciliation after a policy bind (`reconcileDsAfterBind`, `v2/keyrow_ds.go:255`);
  - an owner's `UpdateKeyRow`;
  - a key deleted by the purge commands;
  - an edit made to the database outside tdns.
- **Keep** the existing `PublishDnskeyRRs` trigger. It is the prompt hint for DNSKEY changes that do show in the served RRset.

The marks coalesce per zone (`dsEngineKeysChanged`), so the backstop adds at most one comparison per zone per tick:
- one `DSIntentForZone` query;
- one read of the served CDS.

`followKeysWithCDS` returns before the query for any zone outside that set. The key state worker already makes several passes over every zone's keys in the same tick (`checkAndTransitionKeys`, `v2/key_state_worker.go:110-131`); this adds one.

**One consequence to accept.** A CDS an operator published by hand on a zone whose keys tdns manages is now replaced within a tick, or at once when the edit came through the API or DNS UPDATE (d). Today it is replaced only at the next SEP change. That follows from the existing rule that the DS engine owns the CDS RRset. It is documented, not guarded against.

**(c) Tell the parent, after a CDS change and at startup: `parentsync` zones only.** When `followKeysWithCDS` has published a **changed, non-empty** CDS, it queues an `EXPLICIT-SYNC-DELEGATION` for the zone. Only for zones in child delegation-sync mode (`childDelegationSyncPredicate`, `v2/delsync_refresh.go:34`), read under `zd.mu`. That predicate requires `parentsync` and excludes `parentsync-proxy` and multi-provider zones.

The explicit sync compares the parent's DS with the DS intent (`AnalyseZoneDelegation`, `v2/delegation_utils.go:243`; the DS comparison is at `:375-389`). It then syncs through whatever scheme the parent advertises:
- **NOTIFY:** `ensureCDS`, then NOTIFY(CDS) (`v2/delegation_sync.go:626-671`);
- **UPDATE or API:** the DS directly.

The explicit sync covers the whole delegation, so a follow-keys change also pushes an NS or glue difference that was already there. That is accepted. There is no CDS-only variant of the command.

**`ensureCDS` stops republishing a CDS that is already served.** Today it always calls `publishCDSAndWait` (`v2/ds_engine.go:417-418`). That update deletes the CDS RRset and adds it back, so the updater sees a change even when the records are identical: another serial and another journal row. After a follow-keys change the parent's DS is still the old one, so the explicit sync is out of step and would do exactly that. `ensureCDS` therefore compares the CDS it wants with the served one (`cdsTupleSetsEqual`, as `followKeysWithCDS` does) and returns the served set without publishing when they match. That holds for every model that builds its CDS from the intent: `none`, and an owned multi-provider zone. The NOTIFY then goes out as before.

No new NOTIFY path is needed.

The rest of (c):
- **The queue is not blocked on.** The DS engine sends with `select … default`. A blocking send could deadlock the DS engine against a `DelegationSyncher` that is itself waiting in `askDSEngine`.
- **A dropped send is retried by the DS engine.** A full `DelegationSyncQ` puts the zone on a sync-pending list that only the DS engine's goroutine touches. Whenever the engine runs for a zone on that list, it tries the send again, whether or not the CDS changed this time; a send that gets through takes the zone off the list. The backstop in (b) runs the engine for every CDS-serving zone each tick, so a dropped send is retried within `kasp.check-interval`. Without the list, the next tick would find the CDS matching the intent, return, and never tell the parent. Whether the parent is in step is `AnalyseZoneDelegation`'s question, not the DS engine's.
- **A withdrawal (an empty intent) queues nothing,** and takes the zone off the sync-pending list. For a zone whose keys tdns manages, the explicit sync treats an empty intent as an instruction to remove the parent's DS (`v2/delegation_utils.go:385-389`, `NewDS` is authoritative even when empty). Going insecure stays an operator's action.
- **Multi-DS zones are untouched.** `followKeysWithCDS` returns early for them, and the rollover engine pushes their DS itself.
- **At startup, one compare (#736).** The engine's first run for a zone counts as a change. That is the first run for that `ZoneData` after it is loaded and signed, not after the server starts. A zone added later, or a secondary that finishes its first signing well after start, gets its compare too. A flag on the `ZoneData`, set by the engine's goroutine, records that the run happened.
  - On that run, a zone in child delegation-sync mode whose intent is non-empty queues one `EXPLICIT-SYNC-DELEGATION`, whether or not the CDS changed.
  - A first run that also publishes the zone's first CDS queues one sync, not one for the publish and another for the first run.
  - This is the reconciliation step of the DS engine design (`docs/2026-09-13-ds-engine-design.md`, step 3), done once per zone load. It covers the first DS after signing, and a KSK changed while the server was down.
  - The sync compares first. A parent that already holds the intent costs one DS lookup, and is sent no NOTIFY, UPDATE or API request.
  - It waits for the resolver to be ready. Today the `EXPLICIT-SYNC-DELEGATION` arm does not wait (`v2/delegation_sync.go:94-133`), so the wait is added to the arm for every explicit sync, on the signal the proxy's deferred requests use (`deferForImr`, `v2/delegation_sync.go:714`). A follow-keys change right after start has the same window. The DS engine itself never waits.
  - One `DelegationSyncher` serves the queue, so the startup syncs run one after another rather than as a burst. A full queue is retried from the sync-pending list.
  - Nothing about the parent is persisted. The parent's DS in DNS is the record. A stored "in step" would go stale when the parent changes without us (registrar, operator) and would suppress the one check that notices. It would save a DS lookup, not a request, because the sync compares first anyway.

**(d) Tell the parent after an operator edits CDS, CDNSKEY or CSYNC.** This covers an edit through the management API (`v2/zone_update_api.go:80`) or through DNS UPDATE admitted by `allow-updates`.

- **Where.** In the ZoneUpdater's `ZONE-UPDATE` arm, after a successful apply, beside the existing `SYNC-DELEGATION` enqueue (`v2/zone_updater.go:468`).
- **Which updates.** Only those without `InternalUpdate`. Every tdns writer of these RRsets sets it, and sends its own NOTIFY where one is due:
  - the DS engine;
  - the rollover push;
  - the CSYNC publisher (`v2/ops_csync.go:130`);
  - `PublishCdsRRs` for tdns-mp (`v2/ops_cds.go:93`);
  - the RFC 9615 republisher;
  - journal replay and zone merge.

  That is how the hook recognises them, with no extra marker.
- **Which zones.** Those for which `childDelegationSyncPredicate` holds, read under `zd.mu`. Multi-provider zones are excluded, so tdns-mp's use is untouched.
- **What counts as an edit.** Before applying, the ZoneUpdater reads the served apex RRsets of the three types; it does so only when an action names the apex with one of them, or `ANY`. After the apply it reads what the apply staged: the working set's apex when one is left, otherwise the served zone the apply just published. Under a transaction hold the served zone is still the old one, so a second read of it would see no edit. A type whose RRset differs has been edited, so an identical republish sends nothing.
- **What is queued.** One `SIGNALS-EDITED` request on `DelegationSyncQ`, naming the edited types. It uses the same cancellable enqueue as the `SYNC-DELEGATION` beside it.

**Nothing goes out before the edit is served.** A NOTIFY(CDS) tells the parent to come and read the CDS, so it must not precede the publish, the rule `SyncZoneDelegationViaNotify` already follows. When the zone has an open transaction, the handler does nothing yet. It re-queues the request from its own goroutine once the hold ends, as `deferForImr` does for the resolver; a hold is bounded by `txHoldLimit`. When it runs, it reads the served RRsets again.

The `DelegationSyncher` handles `SIGNALS-EDITED` according to what was edited:
- **CDS or CDNSKEY, on a zone whose keys tdns manages** (`DSIntentForZone(…).Known`):
  - The DS engine owns this CDS, so the parent is told the intent, not the edit.
  - The handler runs the `EXPLICIT-SYNC-DELEGATION` path. A NOTIFY parent gets `ensureCDS`, which publishes the intent's CDS if the edit differs, then NOTIFY(CDS). An UPDATE or API parent gets the DS. A parent already in step gets nothing.
  - It then marks the DS engine (`KeysChanged`), so an edit that differs from the intent is replaced now rather than at the next tick.
  - Sync first, then mark. When the sync ran `ensureCDS`, the CDS already matches the intent, the engine finds nothing to change, and (c) queues no second sync. The parent gets one NOTIFY.
  - With the parent already in step, the sync sends nothing; the mark then restores the CDS, and (c) queues a sync that finds the parent in step and sends nothing either. That extra sync is accepted. Marking before the sync would avoid it, but would send two NOTIFYs when the parent is behind.
- **CDS or CDNSKEY, on a zone whose keys tdns does not manage:**
  - Here the CDS is the operator's, and `AnalyseZoneDelegation` leaves the parent's DS alone (`v2/delegation_utils.go:340-373`). So the handler sends the NOTIFY itself.
  - If either RRset is non-empty, it looks up the parent's NOTIFY target (`LookupDSYNCTarget(ctx, zone, dns.TypeCDS, core.SchemeNotify)`, `v2/dsync_lookup.go:200`) and hands one NOTIFY(CDS) to the notifier. RFC 9859 uses NOTIFY(CDS) for both types.
  - A parent that advertises no NOTIFY target for CDS gets nothing, and that is logged at Info. The UPDATE and API schemes carry a DS, not a pointer to the CDS, and tdns does not turn an operator's CDS into a DS.
  - A hand-published delete CDS is non-empty and is announced. Q2 is about tdns taking a zone insecure on its own; a delete CDS the operator published is the operator's action.
- **CSYNC:** if non-empty, NOTIFY(CSYNC) to the parent's NOTIFY target for CSYNC, in the same way.
- **An RRset removed:** nothing is sent. Under RFC 8078, removing the CDS means "no change".

If the same update also changed the DNSKEY RRset, the `SYNC-DELEGATION` beside it runs as well. The two do not conflict, because each sync compares with the parent first.

A CDS, CDNSKEY or CSYNC that arrives by zone reload or transfer is not covered. Nor is an edit on a zone not in child delegation-sync mode.

**(e) A proxy's DS comes from the CDS.** For a `parentsync-proxy` zone that serves a CDS, the DS the agent sends over UPDATE or API is that CDS turned into DS. Today it is the DS of every published SEP key (1.1). With (a), the CDS is the signer's statement of what the parent should hold, and the agent relays it.
- `currentDelegationRRs` (`v2/delsync_proxy_update.go:403`) takes the DS from the served CDS when there is one. A CDS containing any algorithm-0 record leaves the parent's DS alone (`NewDSKnown` false) and is logged, until Part 2's classifier decides such sets.
- A zone serving no CDS keeps today's DS from the SEP keys, so a signer that publishes none (another implementation, or an older tdns) is handled as before.
- The startup reconcile (`ProxyStartupReconcile`, `v2/delsync_proxy_update.go:471`) compares the parent's DS with the same set. Today `AnalyseZoneDelegation` leaves the DS alone for a zone whose keys tdns does not manage (`v2/delegation_utils.go:340-373`), which a proxy zone normally is. For a proxy zone serving a CDS it compares the parent's DS with the CDS instead.
- The NOTIFY path is unchanged; it already points the parent at the served CDS.

Also out of this part: the manual KSK roll itself does not check that the parent has the new key's DS before it retires the old one. With (a) and (b), the standby's DS is offered by CDS as soon as the key becomes standby, so a parent that follows the CDS has it by the time an operator rolls. Whether `RolloverKey` for a KSK should refuse without a confirmed DS is a separate question.

### 1.3 Tests

For (a):

1. **First signing.** A zone with keys tdns manages, `none`, no `parentsync`, serving no CDS: once loaded and signed, it serves the intent's CDS.
2. **Restart.** The same zone restarted with its CDS already served: nothing is published, the serial is unchanged, nothing is journalled.
3. **Not covered:** a zone whose keys tdns does not manage, an unsigned zone and a multi-DS zone get no CDS from (a).
4. **`cds: false`:** a zone without `parentsync` under such a policy, serving no CDS, gets none from (a) at signing, at startup or on a key change. Once it serves one (published by hand), a manual KSK roll moves that CDS to the new key. A `parentsync` zone under `false` publishes as under `true`, and logs once that the setting was ignored.

For (b):

5. **Standby.** Zone serving CDS {A}, `none`, B published → standby (through `UpdateDnssecKeyState` and `triggerResign`). The engine is marked, and the CDS becomes {A, B}. Today it stays {A}.
6. **Manual roll.** Then `RolloverKey` KSK through the keystore API: CDS becomes {B}. Today it stays {A}.
7. **Backstop.** A `ds` change made directly in the database with no hook: within one `checkAndTransitionKeys` the CDS follows.
8. **No churn.** A tick with nothing changed publishes nothing: the zone serial is unchanged and nothing is journalled.

For (c):

9. **NOTIFY.** With a child-sync zone and a parent advertising NOTIFY for CDS, a follow-keys change queues one `EXPLICIT-SYNC-DELEGATION`. It then leads to one NOTIFY(CDS), using the DS engine rig with `serveNotify` (`v2/ds_engine_test.go:31`).
10. **No second publish.** In test 9, the explicit sync's `ensureCDS` publishes nothing: the serial is the one the follow-keys change produced, and it journalled one change.
11. **No NOTIFY on withdrawal:** an intent that goes empty queues nothing.
12. **A full queue:** a follow-keys change with `DelegationSyncQ` full does not block the DS engine. Once the queue has room, the next engine run for the zone, with the CDS now unchanged, queues the `EXPLICIT-SYNC-DELEGATION`. The run after that queues none.
13. **Startup, parent in step:** a child-sync zone whose parent holds the intent: one DS lookup, and no NOTIFY, UPDATE or API request.
14. **Startup, parent behind:** the parent holds the old KSK's DS: one sync, through the parent's scheme.
15. **Loaded after start:** a child-sync zone added after the server started, or a secondary first signed after start, whose served CDS already matches and whose parent is behind: one sync on the engine's first run for it.
16. **First run that publishes:** a child-sync zone serving no CDS, parent behind: its first run publishes the CDS and queues exactly one sync.
17. **Resolver not ready:** an `EXPLICIT-SYNC-DELEGATION` queued before the resolver is ready waits, then runs once it is. The DS engine does not wait.
18. **Startup, no `parentsync`:** the CDS is published (test 1), and nothing is queued for the parent. The same for a `parentsync-proxy` zone.
19. **Multi-DS and not-managed zones** are unchanged: the existing `TestAPublishedCdsFollowsTheKeys` cases pass.

For (d), with a child-sync zone and a parent advertising NOTIFY for CDS and CSYNC:

20. **Not managed, CDS edited:** a CDS added through the management API sends one NOTIFY(CDS). So does the same edit through DNS UPDATE.
21. **Identical republish:** the same API edit repeated sends nothing.
22. **Managed, edit differs from the intent:** the served CDS goes back to the intent's. With the parent's DS differing from the intent, exactly one NOTIFY(CDS) goes out, after the zone serves the intent's CDS. With the parent in step, none.
23. **CSYNC edited:** one NOTIFY(CSYNC).
24. **Removed:** deleting the CDS RRset, or the CSYNC, sends nothing.
25. **Internal writers:** a DS engine publish, a rollover publish, `PublishCsyncRR` and the RFC 9615 republisher queue no `SIGNALS-EDITED`.
26. **Inside a transaction:** a CDS edit through the API while the zone has an open transaction sends nothing until the commit publishes it, then one NOTIFY(CDS).
27. **Other zones:** a multi-provider zone, and a zone without the `parentsync` option, queue nothing.
28. **No NOTIFY target:** a parent advertising only UPDATE for CDS gets nothing from an edit on an unmanaged zone, and the log says so.

For (e), a `parentsync-proxy` zone whose upstream serves DNSKEY {A retired, B active, C standby} and CDS {B, C}:

29. **UPDATE:** the replace-form UPDATE carries DS {B, C}, not {A, B, C}.
30. **No CDS served:** the DS comes from the SEP keys, as today.
31. **Startup:** with the parent holding {A}, the startup reconcile finds the DS out of step and syncs.
32. **Algorithm 0:** a served CDS with an algorithm-0 record leaves the parent's DS alone.

## 2. #755: only an exact delete CDS deletes

### 2.1 What goes wrong

`cdsIsRemoval` (`v2/scanner_trust.go:118-125`) is true if **any** CDS in the RRset has algorithm 0. With a DS present, every DS is then removed (`v2/scanner.go:1161-1170`).

The RFCs say otherwise:
- RFC 8078 §4: the delete RRset MUST be one RR with exactly `0 0 0 0`;
- RFC 7344 §4.1: a CDS that breaks the rules MUST be ignored.

A set mixing a delete record with real records therefore takes a secure child insecure.

### 2.2 Design

Replace `cdsIsRemoval` with `classifyCDS(rrset) (kind cdsKind, reason string)`, where `kind` is one of:
- **update**: no algorithm-0 record;
- **delete**: exactly one RR, with keytag 0, algorithm 0, digest type 0, and a digest that decodes to the single byte `0x00`;
- **malformed**: any algorithm-0 record in any other shape. That includes a mixed set, a second delete record, or a non-zero keytag, digest type or digest.

What each kind does:
- **Malformed:** the scan ends with no change and a refusal verdict, is logged, and is reported on the Report-Channel once Part 5 lands. This holds with and without a DS, so a mixed set neither deletes nor bootstraps.
- **Delete:** the existing path, unchanged.
- **The RFC 9615 path** classifies the signalling copy the same way. It already asks `cdsIsRemoval` twice (`v2/scanner.go:1138`, `:1161`).

**The digest check uses the unpacked value.** On the wire the RFC's `0 0 0 0` is one zero byte of digest, which the library shows as `"00"`.

A related point, **not in scope**: the RFC's literal spellings `CDS 0 0 0 0` and `CDNSKEY 0 3 0 0` parse in the DNS library, but fail to pack ("odd length hex string", "illegal base64"). A zone file written the RFC's way therefore cannot be served. That belongs in the library fork, and matters once tdns publishes a delete CDS itself (it does not today).

Part 4 adds the CDNSKEY delete form, `0 3 0 AA==` on the wire, when the parent starts reading CDNSKEY.

### 2.3 Tests

- **Exact delete:** with a DS, everything is removed. Without a DS, no change (the existing test).
- **Mixed set** (a delete plus a real CDS): with a DS, no change and a refusal; without a DS, no change and no bootstrap.
- **Malformed single records:** `0 13 2 <digest>` and `0 0 0 01` are refused.
- **Two delete records:** refused.
- **The RFC 9615 path:** a signalling copy that is a mixed set is refused.

## 3. #757: the DSYNC RR type and the root's names

### 3.1 What goes wrong

A scratch test against `v2/core/rr_dsync.go` showed:
- **Parsing:**
  - The null scheme 0, unassigned schemes (for example 5) and private-use schemes (for example 200) fail to parse (`:92-95`).
  - An RRtype field in `TYPEnnn` form fails, for example `TYPE59` (CDS's number). That is the first field of the DSYNC's rdata, the type it signals for, not the DSYNC type itself.
  - The port is not range-checked: 70000 becomes 4464, and -1 becomes 65535.
- **Printing:** a scheme without a mnemonic prints as an empty field (`:79-81`).
- **Unpacking:** truncated rdata returns early without an error (`:140-175`).

Consumers ignore scheme 0 and unknown schemes, by exact matching, but not port 0:
- `v2/ksk_rollover_schemes.go:341`;
- `v2/dsync_lookup.go:257`;
- `v2/delegation_sync_plan.go:347`.

`dsyncOwnerLabel` maps `.` to `root` (`v2/ops_dsync.go:416-421`). So a root zone publishes at `_dsync.root.`, and a TLD child looks up `<tld>._dsync.root.` and `_dsync.root.`, where RFC 9859 has `_dsync.` and `<tld>._dsync.`.

### 3.2 Design

- **`Parse`:**
  - RRtype field: a mnemonic, or `TYPEnnn`.
  - Scheme: a mnemonic, or a decimal 0–255 (`strconv.ParseUint(…, 10, 8)`).
  - Port: a decimal 0–65535 (`ParseUint(…, 10, 16)`).
  - Target: unchanged.
- **`String`:** the type through `dns.Type(t).String()`, which prints `TYPEnnn` for an unknown type; the scheme's mnemonic if it has one, otherwise its decimal.
- **`Unpack`:** an error when the rdata ends before the target.
- **Consumers:** one predicate, `dsyncUsable(rr)`: scheme ≠ 0, port ≠ 0, and the target is not the root. It is applied where DSYNC records are selected:
  - `findDsync`, `v2/delegation_sync_plan.go:257`;
  - `selectRolloverDsyncRRs`, `v2/ksk_rollover_schemes.go`;
  - the scheme match in `v2/dsync_lookup.go:216`.
- **Root names:**
  - The owner of the root's DSYNC becomes `_dsync.`, and a TLD's per-child name `<tld>._dsync.`.
  - A clean switch (Q8): the publisher publishes only the RFC names, and discovery looks up only the RFC names, with no fallback to `…_dsync.root.`. There is no installed base to carry.
  - A root zone's publisher logs at Info, once, that its DSYNC is at `_dsync.` and no longer at `_dsync.root.`, so a test set up against an older build shows why it finds nothing.
  - A root and its TLD children therefore move to a build with this change together.
- **The scheme numbers** UPDATE=2, SCANNER=3 and API=4 (`v2/core/rr_dsync.go:40-48`) stay as they are for now (Q9). They are unassigned in the IANA registry, whose 2–127 range is the IETF's to assign, and 128–255 is private use (RFC 9859 §6.2). Moving them is one table when that is decided.

### 3.3 Tests

- **Parse and print round trip:** scheme 0, 5, 200 and every mnemonic; `TYPE59`; ports 0, 65535 and 65536 (the last refused).
- **Unpack of truncated rdata:** an error.
- **Port 0:** a DSYNC with port 0 is never selected; with a second, usable record, that one is selected.
- **The root:** a root zone publishes at `_dsync.` and nothing at `_dsync.root.`; discovery for a TLD child queries `<tld>._dsync.` and `_dsync.`, and never a `…_dsync.root.` name.

## 4. #753: CDNSKEY alongside CDS

### 4.1 What goes wrong

The child publishes CDS only:
- `cdsFromDS` builds CDS;
- `publishCDSAndWait` deletes and adds CDS alone (`v2/ds_engine.go:489-505`, `:602`).

RFC 7344 §4 says to publish both (SHOULD), and they MUST match. RFC 9975 §3.1: a key referenced in the CDS but not the CDNSKEY, or vice versa, MUST be treated as inconsistent, and a NODATA answer counts. A parent that checks both types may therefore refuse every tdns CDS.

The parent reads CDS only and never fetches CDNSKEY.

### 4.2 Design, child

- **The DS intent also returns the keys.** `DSIntent` gains `Keys []*dns.DNSKEY`, parallel to `Set`, filled from the same rows (`keyrr`, `v2/ds_intent.go`). For an owned zone, the owner's DS set is matched against the keystore rows, own and `foreign`, by digest. If any DS has no matching key, the intent has no `Keys` and the zone publishes CDS alone, as today, and says so in the log.
- **One RRset pair, one update.** `publishCDSAndWait` becomes `publishDSSignalsAndWait(ctx, kdb, cds, cdnskey)`:
  - it deletes both RRsets (`cdsDeleteRR` plus a `cdnskeyDeleteRR`) and adds both in one internal ZONE-UPDATE;
  - the read-back postcondition checks both;
  - `unpublishCDSAndWait` deletes both.

  Built from the same key rows in the same update, the two are consistent by construction. The CDNSKEY TTL is the CDS TTL, 120 (`cdsFromDS`).
- **Every writer passes both:**
  - `ensureCDS`;
  - `followKeysWithCDS`;
  - `publishRolloverCDS` (the snapshot rows carry `keyrr`: `cdsSetFromSnapshot`, `v2/ksk_rollover_ds_push.go:231`);
  - `ownedZoneCDS` (restored after every refresh);
  - the withdrawals: `releaseRolloverCDS`, `withdrawUnclaimedCDS`.
- **Comparisons stay on the CDS.** Rollover claims and the follow-keys comparison keep comparing CDS; the CDNSKEY follows it.
- **The exported helpers stay as they are:** `PublishCdsRRs` and `UnpublishCdsRRs` (`v2/ops_cds.go:67`, used by tdns-mp), and `PublishCDSAndWait`. Each also writes the CDNSKEY when it can derive one.
- **A policy setting.** `dnssec.policies.<p>.cdnskey: true | false`, default `true` (Q5). Under `cds: false` (1.2 (a)) the CDNSKEY follows the CDS: published only when a CDS is. RFC 7344 lets a child that knows its parent reads only CDS publish CDS alone. The default is what lets a tdns child pass a parent that applies RFC 9975 strictly.
- **The key-row invariant** check I7 (`v2/keyrow_check.go:291-330`) also compares the served CDNSKEY with the CDS.
- **Already in place:**
  - the journal overlay's allowlist has CDNSKEY (`v2/journal_overlay.go:52-56`);
  - the RFC 9615 republisher copies both (`v2/signal_republish.go:77`).

  A hand-added CDNSKEY is replaced by the DS engine's the same way a hand-added CDS is.

### 4.3 Design, parent

The scanner keeps consuming CDS; RFC 7344 §6 lets it choose. It also fetches CDNSKEY from the same servers, through the same fetch, to check consistency.

A parent that fetches both types is bound by RFC 9975 §3.1: a key referenced in the CDS but not the CDNSKEY, or the other way round, makes the state inconsistent, and a NODATA answer counts as an answer. A CDS served everywhere with no CDNSKEY anywhere is therefore inconsistent under 9975. What follows departs from that in one case, as local policy (Q4):
- **CDNSKEY served by any server:** 9975 applies strictly. The keys the CDNSKEY names, turned into SHA-256 DS, must equal the keys the SHA-256 CDS records name. Otherwise the state is inconsistent and nothing changes.
- **CDNSKEY absent at every server that answered:** accepted as a CDS-only child. This is **local policy, not a reading of 9975**. It keeps existing CDS-only children working, tdns children of older builds among them. It is logged at Info as a 9975 exception.
- **Digest types.** Only SHA-256 CDS records take part in the comparison. 9975 checks only the digest types marked MUST, and CDS records of other digest types are ignored for it. They still go to the DS the way they do today (`v2/scanner.go:1177-1195`).
- **The CDNSKEY delete** `0 3 0 AA==` counts as a delete only alongside an exact delete CDS (Part 2). A CDNSKEY-only child is still not processed. That is unchanged, and allowed.

Until #754 lands, the fetch has #754's limits: the first address, and skipped servers.

### 4.4 Tests

- **Child:**
  - Every writer publishes a matching CDS and CDNSKEY.
  - Withdrawal removes both.
  - `cdnskey: false` publishes CDS alone.
  - An owned zone whose owner DS has no matching key publishes CDS alone and logs it.
  - A multi-DS rollover's CDNSKEY names the target set, and cleanup removes both.
- **Parent:**
  - CDS and CDNSKEY matching → accepted.
  - A key in CDS only, with a non-empty CDNSKEY → inconsistent.
  - CDNSKEY absent everywhere → accepted, with the local-policy log line.
  - CDNSKEY served by one server only → inconsistent.
  - A CDS with SHA-256 and SHA-384 records, and a CDNSKEY matching the keys: the SHA-384 records do not make it inconsistent.

## 5. #756: the NOTIFY receiver

### 5.1 What goes wrong

- **No rate limiting.** It is a TODO at `v2/notifyresponder.go:118`. RFC 9859 §5 makes it a MUST.
- **Multi-question NOTIFY.** One with more than one question is not discarded; `Question[0]` is used (`v2/do53.go:356`, `:368-370`). RFC 9859 §4.3: MUST discard.
- **Report-Channel.** The option is parsed and carried to the scan (`v2/notifyresponder.go:347`), but CDS and CSYNC errors are never reported (§4.3, SHOULD). The sender, `SendRfc9567ErrorReport` (`v2/rfc9567.go:15`), does not check §4.2.1's MUST: the agent domain has to be at or under one of the delegation's NS names.

### 5.2 Design

- **Rate limiting.** A small in-house token-bucket limiter (no new dependency), applied in `NotifyResponder` before a `ScanRequest` is queued (`v2/notifyresponder.go:342`, `:360`). Two buckets must both allow:
  - **per source:** IPv4 /32, IPv6 /64;
  - **per child zone.**

  Configuration: `scanner.notify-limit: { per-source: "10/s", per-source-burst: 50, per-zone: "1/10s", per-zone-burst: 3 }`, with those defaults. Idle entries are pruned. A limited NOTIFY is still answered NOERROR (§4.3 option 2: acknowledge to stop retries), with no scan queued. It is counted, logged at Debug, and reported with EDE 15 (Blocked) when the Report-Channel allows. NOTIFY(SOA) is left out (Q6, deferred).
- **Coalescing.** A NOTIFY for a child that already has a scan of the same type queued or running queues no second one. Fewer scans, and a NOTIFY storm for one zone costs one scan.
- **The order** is per-source bucket, then coalescing, then per-zone bucket, then the queue:
  - Every NOTIFY takes a per-source token, a coalesced one included. It is a message received from that source.
  - Only a NOTIFY that would queue a scan takes a per-zone token. The per-zone bucket bounds scans, and a coalesced NOTIFY would otherwise spend the zone's burst on messages that start nothing.
  - A coalesced NOTIFY is answered NOERROR like any other.
- **Multi-question NOTIFY:** answered FORMERR, no action, for any NOTIFY opcode message with `len(Question) != 1`.
- **Report-Channel:**
  - A NOTIFY-started scan that ends in a refusal or failure reports through `SendRfc9567ErrorReport`.
  - It does so only when the NOTIFY carried the option, and the agent domain is at or under one of the child's NS names in the parent zone. That check is added in the scanner, before sending, so `SendRfc9567ErrorReport` stays generic.
  - Scan outcomes map to EDE codes through one table (Q7, as proposed):

| Outcome | EDE |
|---|---|
| validation failed | 6 DNSSEC Bogus |
| no usable answer from any nameserver | 22 No Reachable Authority |
| answers inconsistent across nameservers | 0 Other, with the EXTRA-TEXT saying so |
| continuity check failed | 6 |
| malformed delete CDS | 0 |
| rate-limited | 15 Blocked |

### 5.3 Tests

- **The limiter:** a burst beyond the per-zone bucket queues exactly the bucket's worth of scans. Every NOTIFY is still answered. Buckets for different sources and different zones are independent.
- **Coalescing:** two NOTIFY(CDS) for one child, while its scan is running, queue one scan.
- **Coalescing before the per-zone bucket:** NOTIFYs coalesced into a running scan leave the zone's per-zone tokens untouched, but each takes a per-source token.
- **Multi-question NOTIFY:** FORMERR and no scan.
- **Report-Channel:**
  - A refused scan with the option and a valid agent domain sends one report query, with the mapped EDE.
  - An agent domain outside the delegation's NS names sends none.
  - Without the option, nothing is sent.

## 6. Order

One PR per part, in the table's order. Part 1 is the fix that matters in the short term.

- **Parts 1 and 2:** no dependencies between them or on anything else. Part 2's classifier replaces Part 1's interim algorithm-0 check in the proxy (1.2 (e)).
- **Part 3:** no dependencies. The root-name change is a clean switch, so there is nothing to remove later.
- **Part 4, parent half:** uses Part 2's `classifyCDS` for the CDNSKEY delete form.
- **Part 5:** its reporting covers Part 2's malformed-delete verdict. Otherwise independent.

`SUPPORTED-RFCs.md` is corrected in each PR for what that PR changes. RFC 9975 is added in the first of them. Part 1 does not touch it.

## 7. Size

| Part | Non-test code | Tests |
|---|---|---|
| 1 (#752, #736) | ~290: always publish (a) with its policy setting ~25, hints ~10, backstop ~20, NOTIFY after follow ~40, sync-pending list ~20, `ensureCDS` short-circuit ~10, first-run compare ~25, resolver wait on the explicit-sync arm ~10, operator edits (d) with the hold wait ~90, proxy DS from CDS (e) ~40 | ~750 |
| 2 (#755) | ~40 | ~120 |
| 3 (#757) | ~80 | ~140 |
| 4 (#753) | ~200: child ~130, parent ~70 | ~300 |
| 5 (#756) | ~250: limiter ~100, coalescing ~40, FORMERR ~10, reporting ~70, config ~30 | ~300 |

## 8. Questions and answers

Johan answered Q1–Q9 on 2026-09-24, after the external review of the first version of this doc. He then decided the rule in 1.2: the CDS is always published, at startup too, so that a downstream `parentsync-proxy` agent always has one; checking the parent and sending it a request is gated by `parentsync` (1.2 (a), (c)). Q10 follows from that. He answered it the same day, and kept the proxy change (1.2 (e)) in Part 1.

| Q | Question | Answer | Where |
|---|---|---|---|
| Q1 | Both the prompt hints and the per-tick backstop, or the backstop alone? | Both | 1.2 (b) |
| Q2 | No explicit sync after a follow-keys change that empties the CDS? | None; going insecure stays an operator's action | 1.2 (c) |
| Q3 | A NOTIFY for a CDS, CDNSKEY or CSYNC edited through the API or DNS UPDATE: now or later? | **Now**, in Part 1. The first version proposed later | 1.2 (d) |
| Q4 | The parent's reading of an absent CDNSKEY | Accept CDS-only, written as local policy and not as RFC 9975; strict once any server serves CDNSKEY | 4.3 |
| Q5 | The `cdnskey` policy setting, default `true`? | Yes | 4.2 |
| Q6 | Rate-limit NOTIFY(SOA) too? | Deferred; not in this part | 5.2 |
| Q7 | The EDE mapping | As proposed | 5.2 |
| Q8 | The root names: a one-release fallback or a clean switch? | Clean switch | 3.2 |
| Q9 | UPDATE=2, SCANNER=3, API=4, unassigned at IANA: keep, move into 128–255, or request assignments? | Keep for now. The review recommended moving them | 3.2 |
| Q10 | A policy setting to turn (a) off, for an operator who signs a zone but does not yet want a parent that bootstraps from CDS to act on it? Proposed: `dnssec.policies.<p>.cds: true \| false`, default `true`; `false` restores today's behaviour, a CDS only when delegation sync asks for one | Yes, in the DNSSEC policy. Limited after the re-re-review, which recommended no setting: it suppresses only a first publish, never the following of a served CDS, and has no effect on a `parentsync` zone | 1.2 (a) |

## 9. Not in scope

- **#754:** RFC 9975 consistency in the scanner (every address, retries, CSYNC glue and SOA, digest types, the older-CDS guard).
- **Multi-DS zones outside a rollover:** whether they, too, should always serve a CDS, for a downstream agent's sake. (a) covers `none` only.
- **#641:** CDS signed by the ZSK. With Part 4, CDNSKEY is signed the same way; #641 changes both.
- **Other findings of the same check, not filed:**
  - waiting for a consistent public view before NOTIFY;
  - NOTIFY retransmission;
  - a delete CDS published by the child;
  - the RFC 9615 producer;
  - the served serial going down at a restart in `keep` mode;
  - an unsigned CDS on a signing failure.

## 10. Amendments

**Part 2, 2026-09-24.** §2.3's example malformed record `0 13 2 <digest>` is key tag 0 with algorithm 13, not algorithm 0. Under §2.2's rule it is an ordinary update record, and the implementation treats it as one. The test for "an algorithm-0 record with a real key tag, digest type and digest" uses `12345 0 2 <digest>` instead. Also in Part 2, as §6 says: the classifier replaces Part 1's interim algorithm-0 check in the proxy, so a `parentsync-proxy` agent delivers the exact delete as a DS withdrawal (#737) and leaves the parent alone on a malformed set.

**Part 3, 2026-09-24.** Where the code differs from §3.2:
- **The predicate** is a method, `(*core.DSYNC).Usable()`, not `dsyncUsable(rr)`, so that the CLI can use it too.
- **Where it applies:** the three sites in §3.2, and two more that pick a record to act on:
  - `advertisesDsyncNotify`: a parent whose own NOTIFY record has port 0 does not advertise NOTIFY;
  - the REPORT lookup in `tdns-cli auth report`.
- **Target templates:** only the owner names change. A `{ZONENAME}` in a target template still becomes `root` for the root zone, as before. A target is the operator's choice, not a name RFC 9859 fixes, and an empty expansion would make `dsync-api.{ZONENAME}` the invalid `dsync-api..`.
- **Parse and print:**
  - Mnemonics are case-insensitive, as elsewhere in a zone file.
  - Every type prints as something that parses back. Types 0 and 65535 print as `TYPE0` and `TYPE65535`, because the DNS library's names for them, `None` and `Reserved`, do not parse. Both parse as `TYPEnnn`, since a record carrying either can arrive by transfer and be written to a zone file.
  - The decimal entries in `StringToScheme` are gone, since the decimal parse covers them.
- **A leftover `_dsync.root.`:** a root zone that still serves a DSYNC RRset at the old name gets a warning each time its publication is built. The RRset is not deleted: it may be the operator's, and one in the zone file would come back at the next load.
