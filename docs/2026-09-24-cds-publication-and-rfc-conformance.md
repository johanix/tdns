# CDS publication and the CDS RFCs: a design for #752, #753, #755, #756 and #757

**Written 2026-09-24.** Line references are to main at `81a22644`.

**Status:** proposal. Nothing implemented.

## Summary

A check of tdns against RFCs 7344, 8078, 9615, 9975, 8901 and 9859 found gaps on both sides. Five of the resulting issues are designed here; #754 (RFC 9975 consistency in the scanner) is not.

| Part | Issue | What | Priority |
|---|---|---|---|
| 1 | #752 | A served CDS goes stale when a KSK's DS status changes without a DNSKEY change, and a follow-keys change sends no NOTIFY(CDS) | **first; a route to a bogus zone** |
| 2 | #755 | The parent treats any algorithm-0 CDS as the delete signal | second; small and dangerous |
| 3 | #757 | DSYNC RR presentation, port 0, the root's `_dsync` name | third |
| 4 | #753 | The child publishes CDS but never CDNSKEY; the parent never checks CDNSKEY | fourth |
| 5 | #756 | NOTIFY receiver: no rate limiting, multi-zone NOTIFY accepted, Report-Channel unused | fifth |

Each part is its own PR, in that order. Part 1 is small and stands alone.

Sizes are in §7 and the questions for Johan in §8.

## 1. #752: keep the CDS in step with the keys, and tell the parent

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

When `followKeysWithCDS` does change the CDS, it sends no NOTIFY (RFC 9859 §4.2, SHOULD).

### 1.2 Design

**(a) Tell the DS engine whenever keys may have changed.** "Keys changed" is a hint, not a result. The engine compares the DS intent with the served CDS and publishes only when they differ (`followKeysWithCDS`, `v2/ds_engine.go:470-472`), so extra hints cost a comparison and nothing more.

- **Prompt hints.** Two places already mean "this zone's keys changed":
  - `republishSigningKeysForZone`, called after every keystore API transaction that changes key rows (`v2/keystore.go:451`, `:463`);
  - `triggerResign` (`v2/key_state_worker.go:520`), called after every key state worker transition and by owners (`TriggerResign`, `v2/key_lifecycle_owner.go:132`).

  Both call `kdb.KeysChanged(zd)` for the zone. It takes no zone lock and never blocks, so either call is safe. Neither needs to know whether the zone serves a CDS.
- **A backstop.** At the end of `checkAndTransitionKeys` (`v2/key_state_worker.go:110`), mark every zone that serves a CDS, and every owned zone signed here. This runs every `kasp.check-interval`, one minute by default. It catches writers that pass neither hook:
  - the DS reconciliation after a policy bind (`reconcileDsAfterBind`, `v2/keyrow_ds.go:255`);
  - an owner's `UpdateKeyRow`;
  - a key deleted by the purge commands;
  - an edit made to the database outside tdns.
- **Keep** the existing `PublishDnskeyRRs` trigger. It is the prompt hint for DNSKEY changes that do show in the served RRset.

The marks coalesce per zone (`dsEngineKeysChanged`), so the backstop adds at most one comparison per zone per tick:
- one `DSIntentForZone` query;
- one read of the served CDS.

This is only for zones that serve a CDS or are owned, and followKeysWithCDS returns before the query for any other zone.

**One consequence to accept.** A CDS an operator published by hand on a zone whose keys tdns manages is now replaced within a tick. Today it is replaced only at the next SEP change. That follows from the existing rule that the DS engine owns the CDS RRset. It is documented, not guarded against.

**(b) Tell the parent after a follow-keys change.** When `followKeysWithCDS` has published a **changed, non-empty** CDS, it queues an `EXPLICIT-SYNC-DELEGATION` for the zone. Only for zones in child delegation-sync mode (`childDelegationSyncPredicate`, `v2/delsync_refresh.go:34`), read under `zd.mu`.

The explicit sync compares the parent's DS with the DS intent (`AnalyseZoneDelegation`, `v2/delegation_utils.go:243`; the DS comparison is at `:375-389`). It then syncs through whatever scheme the parent advertises:
- **NOTIFY:** `ensureCDS`, which finds the CDS already published, then NOTIFY(CDS) (`v2/delegation_sync.go:626-671`);
- **UPDATE or API:** the DS directly.

No new NOTIFY path is needed.

The rest of (b):
- **The queue is not blocked on.** The DS engine sends with `select … default`. A full `DelegationSyncQ` is logged, and the next backstop tick tries again if the parent is still out of step. A blocking send could deadlock the DS engine against a `DelegationSyncher` that is itself waiting in `askDSEngine`.
- **A withdrawal (an empty intent) queues nothing.** For a zone whose keys tdns manages, the explicit sync treats an empty intent as an instruction to remove the parent's DS (`v2/delegation_utils.go:385-389`, `NewDS` is authoritative even when empty). Going insecure stays an operator's action.
- **Multi-DS zones are untouched.** `followKeysWithCDS` returns early for them, and the rollover engine pushes their DS itself.

**(c) Not in this part.** A CDS, CDNSKEY or CSYNC edited directly through the API or DNS UPDATE still sends no NOTIFY. The clean place for that is a publish-level hook: "this publish changed an apex CDS, CDNSKEY or CSYNC RRset of a child-sync zone". But the rollover push and the NOTIFY scheme already send their own NOTIFY for the same change, so the hook needs a way to recognise those. That is §8 Q3.

Also out of this part: the manual KSK roll itself does not check that the parent has the new key's DS before it retires the old one. With (a), the standby's DS is offered by CDS as soon as the key becomes standby, so a parent that follows the CDS has it by the time an operator rolls. Whether `RolloverKey` for a KSK should refuse without a confirmed DS is a separate question.

### 1.3 Tests

1. **Standby.** Zone serving CDS {A}, `none`, B published → standby (through `UpdateDnssecKeyState` and `triggerResign`). The engine is marked, and the CDS becomes {A, B}. Today it stays {A}.
2. **Manual roll.** Then `RolloverKey` KSK through the keystore API: CDS becomes {B}. Today it stays {A}.
3. **Backstop.** A `ds` change made directly in the database with no hook: within one `checkAndTransitionKeys` the CDS follows.
4. **No churn.** A tick with nothing changed publishes nothing: the zone serial is unchanged and nothing is journalled.
5. **NOTIFY.** With a child-sync zone and a parent advertising NOTIFY for CDS, a follow-keys change queues one `EXPLICIT-SYNC-DELEGATION`. It then leads to one NOTIFY(CDS), using the DS engine rig with `serveNotify` (`v2/ds_engine_test.go:31`).
6. **No NOTIFY on withdrawal:** an intent that goes empty queues nothing.
7. **A full queue:** a follow-keys change with `DelegationSyncQ` full does not block the DS engine.
8. **Multi-DS and not-managed zones** are unchanged: the existing `TestAPublishedCdsFollowsTheKeys` cases pass.

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
  - `TYPE59` fails.
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
  - RRtype: a mnemonic, or `TYPEnnn`.
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
  - Discovery tries the RFC name first. For one release it also falls back to the old `…_dsync.root.` names, and logs when it has to. That is §8 Q8.
  - The publisher publishes only the RFC names.
- **The scheme numbers** UPDATE=2, SCANNER=3 and API=4 (`v2/core/rr_dsync.go:40-48`) are unassigned in the IANA registry. What to do about them is §8 Q9. The code change is one table if they move.

### 3.3 Tests

- **Parse and print round trip:** scheme 0, 5, 200 and every mnemonic; `TYPE59`; ports 0, 65535 and 65536 (the last refused).
- **Unpack of truncated rdata:** an error.
- **Port 0:** a DSYNC with port 0 is never selected; with a second, usable record, that one is selected.
- **The root:** a root zone publishes at `_dsync.`, discovery for a TLD child queries `<tld>._dsync.`, and the legacy fallback is found and logged.

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
- **A policy setting.** `dnssec.policies.<p>.cdnskey: true | false`, default `true`. RFC 7344 lets a child that knows its parent reads only CDS publish CDS alone (§8 Q5).
- **The key-row invariant** check I7 (`v2/keyrow_check.go:291-330`) also compares the served CDNSKEY with the CDS.
- **Already in place:**
  - the journal overlay's allowlist has CDNSKEY (`v2/journal_overlay.go:52-56`);
  - the RFC 9615 republisher copies both (`v2/signal_republish.go:77`).

  A hand-added CDNSKEY is replaced by the DS engine's the same way a hand-added CDS is.

### 4.3 Design, parent

The scanner keeps consuming CDS; RFC 7344 §6 lets it choose. It also fetches CDNSKEY from the same servers, through the same fetch, to check consistency (RFC 9975 §3.1):
- **CDNSKEY served somewhere:** the keys it names, turned into SHA-256 DS, must equal the keys the CDS names (SHA-256 records). Otherwise the state is inconsistent and nothing changes.
- **CDNSKEY absent at every server that answered:** a CDS-only child, accepted. That is this doc's reading of 9975: the requirement applies when both types are published. §8 Q4.
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
  - CDNSKEY absent everywhere → accepted.
  - CDNSKEY served by one server only → inconsistent.

## 5. #756: the NOTIFY receiver

### 5.1 What goes wrong

- **No rate limiting.** It is a TODO at `v2/notifyresponder.go:118`. RFC 9859 §5 makes it a MUST.
- **Multi-question NOTIFY.** One with more than one question is not discarded; `Question[0]` is used (`v2/do53.go:356`, `:368-370`). RFC 9859 §4.3: MUST discard.
- **Report-Channel.** The option is parsed and carried to the scan (`v2/notifyresponder.go:347`), but CDS and CSYNC errors are never reported (§4.3, SHOULD). The sender, `SendRfc9567ErrorReport` (`v2/rfc9567.go:15`), does not check §4.2.1's MUST: the agent domain has to be at or under one of the delegation's NS names.

### 5.2 Design

- **Rate limiting.** A small in-house token-bucket limiter (no new dependency), applied in `NotifyResponder` before a `ScanRequest` is queued (`v2/notifyresponder.go:342`, `:360`). Two buckets must both allow:
  - **per source:** IPv4 /32, IPv6 /64;
  - **per child zone.**

  Configuration: `scanner.notify-limit: { per-source: "10/s", per-source-burst: 50, per-zone: "1/10s", per-zone-burst: 3 }`, with those defaults. Idle entries are pruned. A limited NOTIFY is still answered NOERROR (§4.3 option 2: acknowledge to stop retries), with no scan queued. It is counted, logged at Debug, and reported with EDE 15 (Blocked) when the Report-Channel allows. NOTIFY(SOA) is left out (§8 Q6).
- **Coalescing.** A NOTIFY for a child that already has a scan of the same type queued or running queues no second one. Fewer scans, and a NOTIFY storm for one zone costs one scan.
- **Multi-question NOTIFY:** answered FORMERR, no action, for any NOTIFY opcode message with `len(Question) != 1`.
- **Report-Channel:**
  - A NOTIFY-started scan that ends in a refusal or failure reports through `SendRfc9567ErrorReport`.
  - It does so only when the NOTIFY carried the option, and the agent domain is at or under one of the child's NS names in the parent zone. That check is added in the scanner, before sending, so `SendRfc9567ErrorReport` stays generic.
  - Scan outcomes map to EDE codes through one table (§8 Q7). Proposed:

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
- **Multi-question NOTIFY:** FORMERR and no scan.
- **Report-Channel:**
  - A refused scan with the option and a valid agent domain sends one report query, with the mapped EDE.
  - An agent domain outside the delegation's NS names sends none.
  - Without the option, nothing is sent.

## 6. Order

One PR per part, in the table's order. Part 1 is the fix that matters in the short term.

- **Parts 1 and 2:** no dependencies between them or on anything else.
- **Part 3:** no dependencies. Its root-name fallback is removed a release later.
- **Part 4, parent half:** uses Part 2's `classifyCDS` for the CDNSKEY delete form.
- **Part 5:** its reporting covers Part 2's malformed-delete verdict. Otherwise independent.

`SUPPORTED-RFCs.md` is corrected in each PR for what that PR changes. RFC 9975 is added in the first of them. Part 1 does not touch it.

## 7. Size

| Part | Non-test code | Tests |
|---|---|---|
| 1 (#752) | ~70: hints ~10, backstop ~20, NOTIFY after follow ~40 | ~250 |
| 2 (#755) | ~40 | ~120 |
| 3 (#757) | ~90 | ~150 |
| 4 (#753) | ~200: child ~130, parent ~70 | ~300 |
| 5 (#756) | ~250: limiter ~100, coalescing ~40, FORMERR ~10, reporting ~70, config ~30 | ~300 |

## 8. Questions for Johan

1. **Part 1:**
   - **Q1.** Both the prompt hints and the per-tick backstop, or the backstop alone? The backstop alone brings the CDS back in step within `kasp.check-interval`. The hints make it immediate. Proposed: both.
   - **Q2.** No explicit sync after a follow-keys change that empties the CDS? Proposed: none; going insecure stays an operator's action.
   - **Q3.** A NOTIFY for CDS, CDNSKEY or CSYNC edited directly through the API or DNS UPDATE: a publish-level hook later, as its own change? Proposed: later.
2. **Part 4:**
   - **Q4.** The parent's reading of an absent CDNSKEY under RFC 9975. Proposed: absent at every server that answered = a CDS-only child, consistent.
   - **Q5.** The `cdnskey` policy setting, default `true`?
3. **Part 5:**
   - **Q6.** Rate-limit NOTIFY(SOA) too? Proposed: not in this part; the refresh path coalesces already.
   - **Q7.** The EDE mapping in §5.2.
4. **Part 3:**
   - **Q8.** The root names: a one-release fallback to `…_dsync.root.`, or a clean switch?
   - **Q9.** The scheme numbers UPDATE=2, SCANNER=3 and API=4, which are unassigned at IANA: keep them, move them into 128–255 until assigned, or request assignments?

## 9. Not in scope

- **#754:** RFC 9975 consistency in the scanner (every address, retries, CSYNC glue and SOA, digest types, the older-CDS guard).
- **#641:** CDS signed by the ZSK. With Part 4, CDNSKEY is signed the same way; #641 changes both.
- **Other findings of the same check, not filed:**
  - waiting for a consistent public view before NOTIFY;
  - NOTIFY retransmission;
  - a delete CDS published by the child;
  - withdrawing the CDS once the parent is in sync under `none`;
  - the RFC 9615 producer;
  - the served serial going down at a restart in `keep` mode;
  - an unsigned CDS on a signing failure.
