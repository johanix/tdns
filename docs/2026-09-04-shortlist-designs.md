# Fix designs: #502, #507, #455

Shortlisted issues whose designs fit in well under 80 lines each. The other two have their own documents:

- `2026-09-04-design-364-refresh-engine.md`
- `2026-09-04-design-443-forward-servfail.md`

Nothing here is committed. Written 2026-09-04 for review 2026-09-05; #502 added
on the 5th at Johan's request.

---

## #502 - a secondary with an unreachable upstream blocks every zone behind it

Critical, and the fix is small because the plumbing already exists.

**Cause.** `initialLoadZone` (`v2/refreshengine.go:93`) calls
`zd.Refresh(ctx, ...)` and returns whatever it gets. It does not loop. The
indefinite wait is downstream, in the SOA probe and transfer against an
unreachable primary - and `zone list` hanging during the incident confirms the
engine goroutine was blocked inside that call rather than cycling.

**What is missing is a deadline.** All three call sites pass the engine's own
long-lived context:

```
v2/refreshengine.go:637    initialLoadZone(ctx, zd, zone, zr, conf, ...)
v2/refreshengine.go:1075   initialLoadZone(ctx, zd, zone, zr, conf, ...)
v2/refreshengine.go:1149   initialLoadZone(ctx, zd, zone, ZoneRefresher{...}, ...)
```

`ctx` here is the engine context, which has no deadline, so nothing bounds an
initial load. The context is already threaded all the way down - through
`Refresh`, `FetchFrom*`, `DoTransfer` and `ZoneTransferIn` (merged 2026-08-25,
975950cc) - so a deadline set here is actually honoured. That is why this is a
small change rather than a plumbing exercise.

**Fix.**

1. Bound the attempt **inside `initialLoadZone`**, not at the three call sites:

   ```go
   ctx, cancel := context.WithTimeout(ctx, conf.provisioningTimeout())
   defer cancel()
   ```

   One place means the next call site added cannot forget it.

2. On `errors.Is(err, context.DeadlineExceeded)`, set the zone's error state so
   it appears in `broken=[...]`, and log it naming **both the zone and the
   upstream it could not reach**. The issue's sharpest complaint is that
   `broken=[]` was empty while nothing worked, and that nothing pointed at the
   one zone that caused it.

3. Return, so the engine moves to the next zone. That already happens once the
   call returns - the bug is purely that it never did.

4. Keep retrying on the existing retry counter, so a boot-order problem heals
   itself once connectivity arrives. Do not quarantine: the observed cause was a
   machine booting before its network was up, which is ordinary and transient.

**The one decision.** A single timeout has to cover both a 2s SOA probe and a
legitimate slow AXFR of a large zone, and those differ by orders of magnitude.
Either:

- **One generous bound** (60s, say). Crude, but it turns "forever" into "60s per
  zone per cycle", which is the whole point. Simplest to reason about.
- **Separate probe and transfer deadlines.** More correct, slightly more code,
  and it means a blackholed primary costs 2s rather than 60s.

I lean to the generous single bound first, because it is the change that can go
in today and be obviously safe, with the split as a follow-up if the 60s per
dead zone per cycle turns out to matter.

Make it a config value either way - the right number depends on the largest zone
a deployment transfers, and nobody will guess it correctly in advance.

**What this does NOT fix.** The engine is still serial, so a zone with a dead
upstream still costs every other zone `timeout` seconds once per refresh cycle.
At lab scale (nine zones) that is a non-issue; at scale it is #364 stage 3, the
worker pool. #502 is the stopgap that makes the failure survivable and
diagnosable, and it is worth having regardless of whether #364 ever lands.

**Test.** The reproduction is cheap and belongs in the tree: a secondary whose
primary is a blackholed address, plus a healthy primary zone, and assert that
the healthy zone answers within a few seconds of startup and that the stuck one
appears in `broken=[...]`. That test fails today, and it is the same test #364
stage 3 will want.

---

## #484 + #506 - the child-side CSYNC publisher

**Moved to its own document: `2026-09-05-design-484-506-csync-publisher.md`.**

Summary: `PublishCsyncRR` never assigns the flags word (so the parent refuses
every CSYNC), and appends instead of replacing (so the RRset grows by one per
republish). They must ship together - fixing the flag alone makes a child
publish several conflicting CSYNCs that the parent would then act on. ~15 lines
of production code in one file, ~60 with tests, no parent-side change.

## #507 - API scheme sends only the DS

**Cause.** `DsyncApiRRsetsFromSyncStatus` (`v2/dsync_api_client.go:410`) builds
the declarative payload from four fields: `NewNS`, `NewA`, `NewAAAA`, `NewDS`.
The explicit-sync analyser behind `del sync`, `AnalyseZoneDelegation`
(`v2/delegation_utils.go:27`), populates only `NewDS`/`NewDSKnown` - it fills
`NsAdds`/`NsRemoves`, `AAdds`/`ARemoves`, `AAAAAdds`/`AAAARemoves` and stops.
So the payload contains the DS and nothing else, and the parent applies exactly
that while both sides report success.

**The fix is already written, in the other path.** `computeNewNSFromCurrent`
(`v2/zone_updater.go:1506`) and `computeNewGlue` (`:1549`) build precisely these
fields from the current RRset plus the adds/removes, and the proxy path uses
them - which is why the proxy posted 8 RRsets where the primary posted 1.

So: call them from `AnalyseZoneDelegation` too, on the same
`DelegationSyncStatus` it already fills, after the adds/removes are computed.
They take `(*DelegationSyncStatus, currentNS)` and `(*DelegationSyncStatus,
zoneName, *DelegationData)` respectively, so the analyser needs the parent's
current NS and glue in hand - which it already fetched to compute the diff.

**Two things to check while doing it.**

- `computeNewGlue` takes a `*DelegationData`; confirm the explicit path has one
  or can build it, otherwise extract the part that only needs the RRsets.
- `NewDSKnown` exists because an empty `NewDS` is ambiguous ("withdraw the DS"
  versus "no opinion"). NS and glue need the same care: an empty `NewNS` must
  never be sent as "remove all nameservers". `CheckDelegationNSCoherence`
  already refuses an empty resulting NS RRset on the parent side, so a mistake
  here fails safe - but it should not be sent in the first place.

**Report the truth as well.** Today the child logs `delegation synced ...
(1 RRset)` and calls it success while the delegation is unchanged. Whatever the
payload ends up being, `SyncZoneDelegationViaApi` should compare what it
declared against what it wanted and say so when they differ, rather than
reporting NOERROR because the POST returned 200.

---

## #455 - retired key's RRSIG left on the SOA

**Reproduced 2026-09-05.** The two readings before this one were wrong; both are
recorded at the end so the same wrong turns are not taken again.

### Recipe

Scratch zone, `online-signing`, normal DNSSEC policy:

1. Two active ZSKs. `ldns-verify-zone -s`: **clean**.
2. Retire one (`keystore dnssec setstate --state retired`).
3. Change the SOA (`zone bump`).

```
$ ldns-verify-zone -s zone.axfr
Error: Bogus DNSSEC signature for z455.example.	SOA
Zone is verified and complete
```

Byte-for-byte the shape in the issue: SOA only, and only visible with `-s`.

### Mechanism

`SignRRset` removes an old RRSIG **only for keys it is about to re-sign** - the
delete sits inside `for _, key := range signingkeys` and fires only on a key-tag
match. A retired key is not in `signingkeys`, so its signature is never touched.
`v2/sign.go:184` says so deliberately: replacing those "belongs to ResignZone,
not to individual RRset additions".

Harmless while the data does not change. **The SOA is the one RRset that does**,
which is exactly why the issue sees the SOA alone go bogus while every other
RRset verifies under every signature - those still carry the retired key's
signature over data that has not moved.

### The repair exists and works

`tdns-cli auth zone dnssec resign` fixes it completely - one valid signature
afterwards, `ldns -s` clean, and it stays clean through further bumps. So
`ResignZone`'s strip-and-resign is correct; nothing invoked it.

That makes this a **trigger** problem, not a signing problem, and the fix small.

### The open question that picks the fix

Does retiring a key trigger the repair? `triggerResign` fires on key state
changes (`v2/key_state_worker.go:175`, `:260`) and runs `SignZone(kdb, true)`.
But the `setstate` used here produced **no** `DNSKEY state updated` log line,
while the worker's own promotion of a standby key did:

```
keystore.go:1556 DNSKEY state updated zone=... keyid=52945 oldstate=created newstate=published
```

So the operator-facing setstate path may write the row without going through the
machinery that triggers the resign. **Confirm this before writing code** - it is
the difference between adding one trigger and finding that the trigger exists
but does not cover this transition.

### The fix, once that is answered

**Preferred: make every path that retires a key trigger the resign**, including
the operator-facing one. It uses machinery that already exists and already
works, it matches what `v2/sign.go:184` says should happen, and it leaves the
per-RRset signing path alone.

Note it narrows rather than closes the window: retire and resign are not atomic,
so an SOA change landing between them still produces a transiently bogus SOA
that the resign then repairs. The issue describes a **stuck** state sampled
minutes apart, which is consistent with no resign having run at all rather than
with a race - so closing the trigger gap should be enough. If a transient window
is unacceptable, the retirement and the resign need to be ordered, which is a
larger change and should be argued separately.

**Alternative, not recommended: prune in `SignRRset`** - drop RRSIGs whose key
tag matches no currently-active key. It contradicts the explicit comment, moves
zone-level cleanup into a per-RRset path that runs constantly, and would need an
argument for why that comment is wrong. If someone wants this, make that
argument first.

### Tests

- The recipe above, as an integration test: two ZSKs, retire one, bump, assert
  the SOA carries exactly one RRSIG and that it verifies. It fails today.
- A unit test that a retirement enqueues a resign, once the trigger question is
  settled.

### Two dead ends, recorded so they are not repeated

**1. "Freshness is the wrong question when the data changed."** Every mutation
path passes `force=true` (`v2/zone_mutation.go:273`, `v2/zone_updater.go:785`,
`:828`, `:1049`, `:1129`), so that branch never runs there.

**2. "Two active ZSKs and a changed RRset."** Tried directly: two active ZSKs
with repeated serial bumps, `ldns -s` clean throughout. Retirement is required.
Johan's model is right - activation retires the previous ZSK, and two active
same-algorithm ZSKs are not the normal state.

**And a measurement trap:** with two active ZSKs the two SOA signatures were
consistently made 20-60s apart. That looks like one covering stale data and is
not - inception is part of each RRSIG's own signed RDATA, so two keys signing
the same RRset at different moments both verify. I called a reproduction on that
evidence before checking with ldns, and was wrong. The issue's report leads with
a six-second inception gap; that gap is a symptom of two separate signing
moments, not the fault.
