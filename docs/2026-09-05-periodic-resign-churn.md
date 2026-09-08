# Periodic re-sign churns every signed zone once a minute (found on PR #514)

**Status:** not filed yet. Found while verifying the master on
`v0.8-pr514-milestone-3-pq-registry-1009-gd61c0e62` (pr514 tip `d61c0e62`).
**Verdict: the master is not healthy enough to roll the group VMs forward.**

## Symptom

Master, no content change, no operator action:

```
16:22:57  serial 2026090430
16:30:28  serial 2026090438
16:41:xx  serial 2026090448
```

One serial bump per minute, on every signed zone (7 on the parent instance),
each followed by a NOTIFY burst to every downstream — 869 NOTIFY lines in the
log. `zone re-signed (periodic) zone=dnslab new_rrsigs=51` every 60 s.

The data served is *correct*: chains validate, `dnslab` is `secure`, DNSKEY
windows are a uniform 30 days. This is churn, not breakage of the answers.

## Which RRsets churn

Sampled at 16:38:52; last periodic pass 16:36:58:

| RRset | Inception | Re-signed? |
|---|---|---|
| `dnslab NS` | 16:17:50 (daemon start) | no — correct |
| `master.dnslab A` | 16:17:30 (daemon start) | no — correct |
| `dnslab NSEC` | 16:36:58 | **yes, every pass** |
| `dnslab DNSKEY` | 16:36:42 | **yes, every pass** |
| `dnslab SOA` | 16:36:30 | **yes, every pass** |

`NeedsResigning` is working: it logs at INFO when it fires and has logged
**zero** times since the restart, and ordinary RRsets keep their original
signatures. Only NSEC, DNSKEY and SOA move.

## Cause

`SignRRset` (v2/sign.go) is additive. `shouldSign` starts `true` and is only
lowered to `force || NeedsResigning(...)` *if an existing RRSIG by that
keytag is found*. Two callers hand it an RRset with the RRSIGs already
removed, so the freshness check is never reached:

1. **`v2/ops_dnskey.go:101`** — `publishDnskeyRRsLocked` rebuilds the DNSKEY
   RRset from scratch every time:
   ```go
   dnskeys := core.RRset{RRs: publishkeys}   // RRSIGs nil
   zd.stageRRsetLocked(zd.ZoneName, dnskeys)
   ```
   `SignZone` calls it on every pass, so the DNSKEY signatures are wiped and
   remade every pass.

2. **`v2/sign.go:1047`** — in `SignZone`'s NSEC branch:
   ```go
   nsec := cloneRRset(cur.NSEC)
   nsec.RRSIGs = nil
   nsec, _ = MaybeSignRRset(nsec, zd.ZoneName)
   ```
   One forced NSEC re-sign per owner name per pass. `dnslab`'s
   `new_rrsigs=51` is essentially its owner-name count.

   The identical `RRSIGs = nil` at sign.go:739 and :762 is in **`ResignZone`**,
   the deliberate replacement tool, which passes `force=true`. Correct there;
   wrong in the additive path.

The SOA follows: NSEC+DNSKEY change zone content, the publish bumps the
serial, the new SOA must be signed, and the next pass repeats. Self-sustaining.

## Why it appeared now

Both sites are old (ops_dnskey.go Feb–Jul 2026; the NSEC branch predates the
branch too). They were **dormant**: the periodic ticker was gated on
`service.resign`, which defaulted off. The old build says so itself:

```
15:16:05 resigner.go:35 ResignerEngine: periodic mode OFF; explicit triggerResign requests still honored
16:18:58 resigner.go:78 ResignerEngine starting interval_sec=60
```

`675e8003 resign: renew expiring signatures unconditionally` (#515) removed
the gate — rightly, a zone with ageing signatures should not need an opt-in to
have them renewed. That change is not itself wrong; it woke up two pre-existing
defects. No control run on the old build is needed: the log line is direct
evidence the pass did not run before.

**There is no config workaround.** `PeriodicResign` / `service.resign` is gone
from `runtime_config.go` on this branch.

## Proposed fix (small, local, two sites)

1. `publishDnskeyRRsLocked`: carry the existing RRSIGs across when the key set
   is unchanged — compare `publishkeys` against the staged DNSKEY RRs and
   preserve `RRSIGs` on equality, nil them when the set actually changed.
   Key-state changes reach the signer through `ResignZone`
   (`ResignKeyStateChanged`), which replaces signatures anyway, so nothing
   depends on this path wiping them.

2. `sign.go:1047`: drop `nsec.RRSIGs = nil` in `SignZone`. Leave the ones in
   `ResignZone` alone.

Then a periodic pass over an unchanged zone signs nothing, publishes nothing,
and the serial stops moving.

## Lab impact

Disqualifying for the October course as it stands: exercises inspect serials,
run IXFR, and watch NOTIFY. A serial that advances once a minute on its own
makes every one of those unreadable, and the NOTIFY bursts go to every
group address including unbuilt ones.

Related: #355 (no-op republish bumps the serial) is the same family, now
driven once a minute instead of occasionally.
