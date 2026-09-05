# Splitting `SignZone`: building a signed zone is not the same job as renewing its signatures

**Status:** design, for review. Nothing implemented.
**Base:** `main` @ `b4825f50`. `v2/` tree only.
**Prompted by:** a field report on 2026-09-05 — every signed zone re-signed and republished
once a minute with no content change: 8 serial bumps in 7½ minutes, 869 NOTIFY lines,
`new_rrsigs=51` for one zone every 60 s.
**Related:** #515 removed the `service.resign` gate that had kept the periodic pass dormant.
That change was right; this is the cleanup it exposed.
**Cross-reference:** `2026-09-05-signing-publish-notify-correctness.md` §3.6 (C4) currently
says *"the periodic ticker keeps calling `SignZone(force=false)`"*. That sentence describes
this defect. When §3 here lands, C4 is updated to name `RenewZoneSignatures`. `ResignZone`
remains the key-state tool, and the ticker is **not** routed through `ResignQ`.

---

## 1. What is actually happening

Once a minute the resigner calls `SignZone(kdb, force=false)` on every watched zone
(`resigner.go:108`) to ask "does anything here need re-signing?". On a zone that has not
changed the answer should be no, and the pass should cost a walk and nothing else.

It costs a full re-signing and a republish, and the reason is not that the expiry logic is
wrong. `NeedsResigning` works: on the reporting deployment, `dnslab NS` and
`master.dnslab A` still carried their 16:17 signatures at 16:38, exactly as they should.
Four separate mechanisms dirty the zone before, during and after the check.

**1. The NSEC chain is rebuilt, unsigned, before anything is checked.**
`GenerateNsecChainWithDak` (`sign.go:876`) ends every iteration with

```go
zd.stageNsecLocked(name, core.RRset{RRs: []dns.RR{nsecrr}})   // sign.go:1143
```

— a fresh RRset with **no RRSIGs**, for every name in the zone. Two consequences before the
walk starts: every NSEC is now unsigned, so the freshness check has nothing to inspect and
must re-sign; and `stageNsecLocked` goes through `cloneOwner`, so the entire working set has
already been re-materialised.

**2. The DNSKEY RRset is rebuilt, unsigned.** `publishDnskeyRRsLocked` assembles it from the
keystore and stages `core.RRset{RRs: publishkeys}` (`ops_dnskey.go:105`), again with no
RRSIGs, again forcing a re-sign.

This matters because `SignRRset` is **additive**: `shouldSign` starts `true` and is only
reduced to `force || NeedsResigning(...)` inside the loop over *existing* RRSIGs. Strip the
signatures first and the freshness check is unreachable by construction.

**3. Everything is restaged, signed or not.** The walk discards the result:

```go
rrset, _ = MaybeSignRRset(rrset, zd.ZoneName)   // sign.go:944
zd.stageRRsetLocked(name, rrset)                // sign.go:945 — unconditional
```

So an RRset that was correctly left alone is still cloned into a fresh `OwnerData` with a
fresh `RRTypeStore`.

**4. The publish is unconditional.** `SignZone` ends with `publishLocked` (`sign.go:969`),
which is `publishWorkingSetLocked(gen, bumpSerial=true)` (`zone_mutation.go:347`) — and the
bump is not conditional on anything having changed. So the serial advances, the SOA is
re-signed (correctly: the serial moved), the snapshot is swapped, and a NOTIFY goes out.

**This one is the important one.** Fixing 1–3 alone would take `new_rrsigs` from 51 to about
1 and leave the serial bumps and the NOTIFY storm untouched, because the publish does not
depend on them.

All four were dormant until #515: the ticker was gated on `service.resign`, which defaults to
off, so for most deployments this pass never ran.

## 2. Why they are one problem

`SignZone` has four callers and only one of them wants what the periodic pass gets:

| caller | force | what it needs |
|---|---|---|
| `apihandler_zone.go:185` — operator "sign zone" | operator's | build / repair |
| `zone_policy_apply.go:216` — policy apply | true | build under a new policy |
| `zone_utils.go:2006` — `SetupZoneSigning` | false | first build |
| `resigner.go:65` — `resignNow`, after a key-state change | true | replace, on the key-state path |
| `resigner.go:108` — the ticker | false | **renew ageing signatures** |

Four are *build* or *replace* calls. They genuinely need a chain constructed and a DNSKEY RRset
assembled, because they run when there may not be a correct one. The fourth is maintenance on
a zone that is already correct, and it inherits all of the build behaviour.

`SignZone` conflates "produce the signed form of this zone" with "renew signatures that are
ageing out". Each of the four mechanisms above is that conflation showing through. Split the
two jobs and they stop being defects to fix individually: a renewal pass has no reason to
rebuild a chain, none to reassemble a DNSKEY RRset, none to stage what it did not sign, and
nothing to publish when it signed nothing.

**The two things it must not do are not merely wasteful — they hide bugs.** The chain is
maintained incrementally on every publish by `restitchNsecLocked`, scoped to the names whose
authoritative data actually changed (`nsec_restitch.go:100`). A chain that is wrong is a
defect in that path; re-deriving it wholesale once a minute conceals it. The same is true of
the DNSKEY RRset: key state changes are the key-state worker's business and reach the zone
through `triggerResign` → `ResignZone`, which already rebuilds the chain and the DNSKEY RRset
(`sign.go:645`, `:650`) and publishes. Rebuilding it in a maintenance pass papers over any
path that failed to.

## 3. Design

### 3.1 `SignZone` — build. Unchanged.

Ensures the NSEC chain, assembles the DNSKEY RRset, signs what needs signing, publishes.
Callers: the API sign command, the policy apply, the first sign after a policy binds. This is
the operation that produces a correctly signed zone from whatever state it is in, and it
should stay willing to rebuild derived data, because that is its job.

### 3.2 `RenewZoneSignatures` — renewal. New.

The ticker's operation, and only the ticker's.

```go
// RenewZoneSignatures re-signs the RRsets whose signatures are approaching
// expiry, and nothing else.
//
// It does not rebuild the NSEC chain: restitchNsecLocked maintains it on every
// publish, scoped to what changed. It does not reassemble the DNSKEY RRset:
// key-state changes reach the zone through ResignZone. Rebuilding either here
// would not merely waste work, it would hide a failure in the path that owns it.
//
// Returns the number of RRSIGs written. Zero means the zone was untouched --
// nothing staged, nothing published, no serial bump, no NOTIFY.
func (zd *ZoneData) RenewZoneSignatures(kdb *KeyDB) (int, error)
```

Shape:

1. Resolve keys and clamp, as `SignZone` does.
2. **Decide from the published snapshot**, not from a working set: walk the snapshot's RRsets
   and collect those with an RRSIG that `NeedsResigning` says is due. Reading rather than
   staging is what keeps a no-op pass a genuine no-op.
3. If the set is empty — the 999-in-1000 case — return `0, nil` **without touching the
   working set at all**. Not even `ensureWorkingSet`: leaving a working set staged behind
   would hand the next publish something to publish.
4. Otherwise take `zd.mu`, `ensureWorkingSet`, **clone each RRset before signing it**, sign
   the clones, stage exactly those, and publish. A publish here is correct and wanted: new
   signatures should reach downstreams, and the serial bump is how they learn.

**The clone in step 4 is not hygiene, it is the difference between correct and corrupting.**

`ensureWorkingSet` is a *shallow* copy: `workingSet[k] = snap.Data[k]`, the same `*OwnerData`,
so the same `*RRTypeStore`, so RRsets whose `RRs` and `RRSIGs` slices share backing arrays
with the snapshot being served right now. And `SignRRset` mutates in place — `applyClampToRRset`
rewrites `Header().Ttl` before any decision about signing is taken, and the deferred rollback
that undoes it fires **only on the error path**: `signOK = true` is set on every successful
return, including one where nothing needed re-signing.

Today that is harmless *by accident*. `GenerateNsecChainWithDak` has already `cloneOwner`'d
every chain name before the walk begins, so the mutation lands on clones. **The step this
design removes is the step that currently makes the walk safe.** A renewal pass that skips the
rebuild and calls `SignRRset` on a working-set RRset writes through to the published snapshot —
TTLs on a zone that is being served, with no rollback.

So, as a rule rather than a step: collect names from the snapshot under `zd.mu`, clone before
`SignRRset`, stage only clones. **Never call `SignRRset` on an RRset that shares storage with
the published snapshot.** `cloneOwner`'s own comment records the same hazard for the same
reason.

R2 below — decide and sign under one lock — is necessary and not sufficient; this is the other
half.

**What the snapshot walk visits, precisely:**

| owner / type | rule |
|---|---|
| `OwnerData.NSEC` | **visit.** It is not an `RRtypes` entry, so a walk of `RRtypes` alone misses it — and ageing NSEC signatures are exactly this pass's job. Renew the signature; do **not** regenerate the record. |
| apex SOA | **skip.** The publish bumps the serial and `resignWorkingSetSOAIfSigned` re-signs it afterwards. Signing it here signs the old serial and throws the work away. |
| apex ZONEMD, where the zone manages it | **skip.** The publish recomputes the digest and signs it. Same reason `SignZone` skips it. |
| delegation NS, and glue A/AAAA under a delegation | **skip.** Not authoritative here; same rules `SignZone` already applies. |

**An RRset with no RRSIG at all is not collected.** Renewal renews; it does not repair. A
missing signature is `SignZone`'s job, reached through the API, a policy apply, or a reload.
Stated explicitly because the alternative is attractive and wrong: widening the walk to "sign
anything unsigned" would quietly restore the behaviour that made #512 survivable-looking, and
would hide a build path that failed.

Point 4 of §1 falls out of point 3 here, without touching `publishWorkingSetLocked`. The
snapshot machinery stays closed, which is the constraint the surrounding design work has
held to throughout.

### 3.3 The unconditional staging in `SignZone` (§1.3)

Independent of the split, and worth fixing on its own: the walk should stage only when
`MaybeSignRRset` reports that it re-signed. A build pass that finds most of a zone already
correctly signed should not clone every owner either.

**It is not the two-line change it looks like**, and it should not land as one.
`applyClampToRRset` runs *before* the signing decision and is not rolled back on the
no-op path (`signOK = true` regardless of `resigned`). So skipping `stageRRsetLocked` leaves an
RRset whose TTLs were rewritten but which was never staged — the mutation applied and the
record not carried forward, on storage that may be shared.

Two ways to settle it, and it needs settling before the change is made rather than after:
apply the clamp only when the RRset is actually going to be signed, or treat a clamp rewrite
as a change in its own right and stage it. This is independent of §3.2 and can wait; §3.2 is
the storm.

Note that §3.2's clone rule makes this harmless *for the renewal pass* — a clone that is not
staged takes its mutated TTLs with it into the bin. The hazard is `SignZone`'s own walk.

## 4. Scheduling: waking only when something is due

§3 makes a no-op pass cheap. This makes it rare.

Every RRSIG's expiry is known at the moment it is written, so the zone can know when its next
renewal is due instead of discovering it by walking. Track per zone:

```go
// nextResignDue is when this zone's earliest-expiring signature crosses the
// renewal threshold. Zero means unknown -- fall back to the coarse tick.
nextResignDue time.Time
```

**It is a minimum over a per-RRset quantity, not the earliest expiry.**
`NeedsResigning`'s threshold is `servedTTL + propagationDelay + scanInterval`, and TTLs differ
across a zone, so the value is

```
min over signed RRsets of ( expiration − (that RRset's TTL + propagationDelay + margin) )
```

Computed as a by-product of signing: every pass that writes signatures already visits the
RRsets it writes and can accumulate the minimum as it goes. A pass that publishes recomputes
it wholesale rather than lowering it incrementally — an RRset that held the minimum can be
*removed*, which would leave a stale early wake if the value only ever decreased. Early is
harmless; late is not.

The resigner then sleeps until the earliest `nextResignDue` across its watchlist rather than
ticking on a fixed interval. A wake that finds nothing due costs one comparison per zone.

**Keep a coarse safety tick.** This is an optimisation and must degrade to a late renewal
rather than a missed one: a clock step, a restart with no persisted value, an unforeseen path
that signs without updating the estimate. An hourly sweep that recomputes from the snapshot
costs nothing and removes the whole class of "the schedule was wrong and nobody noticed".

## 5. What each part is worth

| change | effect on an unchanged zone |
|---|---|
| §3.2 renewal pass: no chain rebuild | no NSEC restaging, no forced re-signs |
| §3.2: no DNSKEY rebuild | no DNSKEY restaging or re-sign |
| §3.2: stage only what was signed | no `cloneOwner` per owner |
| §3.2: publish only if something was signed | **no serial bump, no SOA re-sign, no NOTIFY** |
| §4 schedule | no walk at all, almost always |

The fourth row is the one that fixes the reported symptom. The first three are what make the
fourth reachable, since today `newrrsigs` is never zero.

## 6. Risks

| # | risk | mitigation |
|---|---|---|
| R1 | The renewal pass stops rebuilding the chain, and something else was silently relying on that rebuild to repair it | That reliance is the bug this exposes rather than a reason to keep the rebuild. `restitchNsecLocked` owns the chain; if it can leave one wrong, fix it there. A test that a zone whose chain is damaged out-of-band is NOT repaired by a renewal pass pins the new contract honestly. |
| R2 | Deciding from the snapshot, then signing the working set, races a concurrent change | Decide and sign under one `zd.mu` acquisition. Necessary but **not sufficient** on its own — see R6. |
| R6 | The renewal pass signs an RRset that shares storage with the published snapshot | **The one to get right.** `ensureWorkingSet` is shallow and `SignRRset` rewrites TTLs in place without rolling them back on the success path. Today the chain rebuild clones everything first; removing it removes that protection. Clone before `SignRRset`, stage only clones, never sign snapshot-shared storage (§3.2). |
| R7 | §3.3's conditional staging lands without settling the clamp | An unstaged RRset has still had its TTLs rewritten. Settle the clamp ordering first (§3.3); do not ship it as hygiene. |
| R3 | The schedule is wrong and signatures expire | §4's coarse safety tick. The schedule must only ever make renewal *earlier* than the fallback. |
| R4 | Zones whose signatures were already written before this lands have no `nextResignDue` | Zero means unknown means fall back to the tick, which is exactly today's behaviour. |
| R5 | `SignZone`'s conditional staging (§3.3) skips a stage that something depended on | The `resigned` bool already exists and is discarded; a staged-but-unchanged RRset is by definition identical to what is published. |

### 4.1 Details settled on review

- **`nextResignDue` is in-memory only.** A restart leaves it unknown, which means the coarse
  tick, which is today's behaviour. Persisting it buys nothing and adds a value that can be
  wrong across a version change.
- **Use `ResignerInterval` as the look-ahead**, the same value `NeedsResigning` uses, so a
  scheduled wake can never land *after* the threshold it is aiming at.

## 7. Testing

- **A renewal pass over an unchanged zone writes nothing and publishes nothing.** The serial
  is identical afterwards, no NOTIFY is emitted, and the working set is still nil. This is the
  test the reported symptom would have failed.
- **A renewal pass over a zone with one ageing RRset** signs that one, stages that one,
  publishes once, and leaves every other signature byte-identical.
- **A renewal pass does not repair a damaged NSEC chain** — the honest form of R1, asserting
  the new division of responsibility rather than the old accident.
- **`SignZone` still builds**: on a zone with no chain and no DNSKEY RRset it produces both.
- **A signature renewal does not rebuild the NSEC chain.** A renewal publish still runs
  `restitchNsecLocked` and `updateZonemdLocked`; an RRSIG-only change leaves every NSEC bitmap
  identical, so the restitch must be a no-op. Worth pinning, or the chain gets rebuilt on
  every renewal "because publish always does" and §3.2's saving is given back at the publish.
- **The schedule**: a zone signed with a 14-day validity and a 900 s TTL reports a
  `nextResignDue` consistent with `expiry − (ttl + propagation + margin)`, and removing the
  RRset that held the minimum raises it rather than leaving it stale.

## 8. Sequencing

§3 first: it is contained, it stops the churn on `main`, and it needs no new state. §4 after,
as its own change — once a no-op pass is genuinely a no-op, the schedule is a pure
optimisation and can be judged on its own merits rather than as a fix.

§3.3 can go with either, or on its own; it is two lines and independent of the split.
