# Publishing ZONEMD

tdns computes RFC 8976 digests and never publishes one. This documents what
both halves of the code do today, what "complete" has to mean given the way
tdns publishes zones, and the design that gets there.

## 1. What exists

### 1.1 tdns: a correct digest, used as a private detector

`v2/zonemd.go` is a faithful RFC 8976 SIMPLE implementation:
`ZoneDigest(apex, rrs, scheme, alg)` with canonical owner ordering (RFC 4034
§6.1, compared label-wise from the right), RDATA domain-name case folding,
out-of-zone exclusion, apex-ZONEMD and RRSIG(ZONEMD) exclusion (§3.3.1), and
duplicate suppression. `v2/zonemd_test.go` checks it against the RFC's
Appendix A vectors.

Its only consumer is `v2/zone_file_state.go`: the `ZoneFileState` table
records a zone file's identity (serial + SHA-384 SIMPLE digest) so the delta
journal knows whether the file it is anchored to is still the file on disk.
`zoneDigestOfWorkingData()` takes it at parse time (`dnsutils.go:697`),
`ZoneDigestOfPublished()` takes it at write time (`zone_utils.go:676`).

The record type itself is not special-cased anywhere. `dns.TypeZONEMD` is in
`standardDNSTypes` (`queryresponder.go:71`), so a ZONEMD in a zone file is
parsed, stored, answered, signed, transferred and written back like any other
apex RRset — and nothing ever recomputes it. A zone file carrying a ZONEMD
loaded into tdns today serves a digest that is stale the moment the serial
moves.

There is no zone option, no config, no CLI, and no verification of an inbound
ZONEMD.

### 1.2 labstuff: computation and publication, file-to-file

`lib/zonemd_utils.go` is the other half: `Digest()` → `UpdateDigest(ha)` →
`CalculateDigest(ha)` creates or updates apex ZONEMD RRs (one per configured
hash algorithm, held separately in `zd.ZONEMDrrs`), and `VerifyDigest()` /
`ValidateOrderedZoneDigest()` check one.

It is driven as a batch pipeline in `lib/zonemgr.go:355-400`: read zone file →
`UpdateSerial` → `Sync()` → `Digest()` → `WriteZoneFile()` → `rndc reload`,
gated on `services.zonemgr.zonemd.active` with `services.zonemgr.zonemd.hashalgs`.
The verification surface is `axfr-cli zone verify` (`libcli/zone_cmds.go:92`):
AXFR the zone, then `VerifyDigest(ignoreserial)`.

Two properties of that design matter here:

- **It is a pre-processor, not a server.** The digest is computed over the
  file, then some other nameserver loads and serves it. Nothing keeps the
  digest correct across anything the server subsequently does to the zone.
- **It is not DNSSEC-aware.** `CalculateDigest` includes every RRSIG except
  RRSIG(ZONEMD), which is right — and means that any signing that happens
  *after* the digest is computed invalidates it. The pipeline is only sound
  for zones that are unsigned, or already signed at the point the file is
  read.

Its canonicalization is also weaker than tdns's: `RRArray.Less`
(`lib/rr_set.go:27`) compares owner labels case-sensitively, does not
lowercase RDATA domain names, sorts with a non-stable quicksort, and allocates
two 64 KB buffers per RDATA comparison. `intToHash` maps algorithm 0 to
SHA-384 where the registry reserves it. There is no out-of-zone exclusion.

**Nothing from labstuff's digest code should be ported.** What is worth
carrying over is its *feature surface*: a per-zone on/off switch, a
configurable algorithm list, and a verify command.

## 2. What "complete" has to mean

1. Opt-in per zone; off changes nothing.
2. `ZONEMD.Serial == SOA.Serial` for every serial the zone ever publishes, and
   the digest is over exactly the zone content published at that serial.
3. Survives signing: RRSIG(ZONEMD) is present and current, and the digest is
   computed after every other RRSIG and NSEC in the zone is final.
4. Survives updates: DDNS, the management API, child delegation sync, key
   rollover, transport-signal synthesis — anything that reaches a publish.
5. Survives the zone-file round trip: write out, read back, and the digest
   still verifies.
6. Does not corrupt the delta journal or the zone-file reconciliation.
7. Does not break the MUST-NOT-MODIFY invariant on secondaries.
8. Can be turned off again, cleanly.

Requirement 2 is the whole problem. The SOA is part of the digest input, so a
serial bump changes the digest; the SOA RRSIG is re-signed on every publish
(`resignWorkingSetSOAIfSigned`), so it changes the digest again. **Every
publish invalidates the ZONEMD.** There is no arrangement in which ZONEMD is
maintained anywhere other than inside the publish.

## 3. Design: ZONEMD as a derived record maintained by the publisher

This is the argument from `2026-08-22-nsec-chain-correctness.md` §1, applied
to a second derived record. A record whose correctness is defined relative to
a snapshot has to be computed inside the publish that builds that snapshot,
before the swap. Repairing it afterwards means a second serial: every
secondary sees two changes, and between them serves a digest that does not
describe the zone it is serving — which a verifier reports as tampering, not
as staleness.

### 3.1 Where it goes

`publishWorkingSetLocked` (`v2/zone_mutation.go:332`) gains two steps:

```
    serial bump
    setWorkingSetSOASerial(serial)
    resignWorkingSetSOAIfSigned()
    ensureZonemdPresenceLocked()     <- NEW
    restitchNsecLocked()
    updateZonemdLocked(serial)       <- NEW
    ---- no further content mutation past this line ----
    computeZoneDelta / PersistZoneDelta
    updateIxfrChainLocked
    buildSnapshotLocked / snapshot.Store
```

Two steps rather than one, because there is a cycle to break:

- the apex **NSEC bitmap** must list ZONEMD, so the record's *presence* has to
  be decided before `restitchNsecLocked`;
- the **digest** covers the NSEC records, so its *value* has to be computed
  after.

`ensureZonemdPresenceLocked` therefore only creates (or removes) the apex
ZONEMD RRset, carrying the existing RDATA forward untouched;
`updateZonemdLocked` writes the digest and signs. Changing RDATA does not
change a type bitmap, and `ZoneDigest` excludes RRSIG(ZONEMD), so signing
afterwards cannot invalidate what was just computed. One restitch pass
suffices.

Placing `updateZonemdLocked` before the delta computation is what puts the new
ZONEMD into the IXFR delta, so secondaries receive it with the change that
caused it.

### 3.2 What each step does

`ensureZonemdPresenceLocked`:
- option off and no server-managed ZONEMD → nothing;
- option on, apex ZONEMD RRset absent or its (scheme, algorithm) set differs
  from the configured one → stage the RRset with the configured pairs,
  preserving any digest already present (the value is about to be overwritten;
  preserving it avoids marking the apex changed for no reason);
- option just turned off → stage the deletion (see §3.7).

`updateZonemdLocked(serial)`:
- digest the working set once per configured algorithm, over the same RR
  collection `ownerRRsForDigest` already defines (RRsets + their RRSIGs + the
  NSEC property);
- write `Serial = serial`, `Scheme`, `Hash`, `Digest` into each RR;
- if the zone is signed, resolve `dak` under the lock with `zdLocked=true` and
  `SignRRset(..., force=true, clamp)`, exactly as `restitchNsecLocked` does —
  reaching `EnsureActiveDnssecKeys` with the lock held re-enters
  `PublishDnskeyRRs` and self-deadlocks;
- stage the result.

Failure handling follows the NSEC precedent's *reasoning* but not its verdict.
A chain that cannot be repaired refuses the publish, because a secondary
cannot repair it either. A ZONEMD that cannot be computed or signed is
different: the zone is still perfectly servable, it just carries no verifiable
digest. So on failure, **remove the apex ZONEMD RRset and publish**, logging
loudly. Absent is a defined state that a verifier handles; stale is one it
reports as corruption.

### 3.3 The signing paths need no new logic

`SignZone` and `ResignZone` both end in `publishLocked`, so the ZONEMD is
recomputed after their signature pass. Their apex loops will sign the ZONEMD
RRset with the stale digest first and have it re-signed a moment later; skip
`dns.TypeZONEMD` in both loops when the zone manages it, the way they already
skip `dns.TypeRRSIG`, to avoid the wasted signature.

`black-lies` zones have no stored NSEC chain (`zoneMaintainsItsOwnChain`
returns false), so nothing NSEC-shaped enters the digest — consistent on both
the computing and the verifying side. ZONEMD works there.

### 3.4 The journal must not carry it

`withoutDerivedRecords` (`nsec_restitch.go:246`) drops NSEC from the persisted
delta. ZONEMD must be dropped on the same grounds and in the same place: it is
recomputed on every publish, so journalling it would replay a stale digest
onto a zone file as though an operator had authored it, and the zone-file
reconciliation would then report conflicts on a record nobody wrote and offer
`.rejected` artefacts full of them.

The exclusion is **conditional**, unlike NSEC's. On a zone without
`publish-zonemd`, an apex ZONEMD is ordinary operator data and must journal
like anything else. `withoutDerivedRecords` is currently a free function; it
needs the zone's option, so give it a receiver or a boolean parameter.

The same distinction applies to DDNS and the API: while the zone manages its
ZONEMD, an update to the apex ZONEMD RRset must be refused with a reason, the
way an attempt to write an NSEC would be. Today the type is in
`standardDNSTypes` and nothing stops it.

### 3.5 The file-identity digest is unaffected, and half of it is free

`ZoneDigest` excludes the apex ZONEMD RRset and its RRSIG (`zonemd.go:194-205`).
So publishing a ZONEMD does not perturb `fileDigest` / `ZoneFileState`, and no
feedback loop exists between the detector and the published record. That is
worth stating explicitly, because it is the property that makes this whole
feature cheap to add to a codebase that already digests every zone file.

Better: when the zone's configured algorithm set includes SHA-384 (the
default, and `zoneFileStateAlg`), the value `updateZonemdLocked` computes *is*
the value the file-state record wants. `WriteZone` should reuse the cached
result rather than calling `ZoneDigestOfPublished()` and digesting the zone a
second time.

Two mechanics:
- `zoneFileStateAlg` stays pinned at SHA-384. It is a private detector and
  stability across upgrades matters more than following a zone's ZONEMD
  configuration. A zone configured for SHA-512 only pays for both.
- `ZoneDigestOfPublished()` reads the *published* snapshot. The publish path
  needs the digest of the working set before the swap, so add
  `zoneDigestOfWorkingSetLocked()` next to the existing
  `zoneDigestOfWorkingData()` (which reads `zd.Data`, the parse-time store,
  and is not the same thing).

### 3.6 Secondaries

`publish-zonemd` is origination: it writes into the zone something that did
not come from upstream. It belongs in `originationOptions`
(`zone_option_normalize.go:39`), so a tdns-auth secondary that may not
originate gets it stripped with the standard message. An inline-signing
secondary *may* originate, and should publish its own ZONEMD — it re-signs
what it receives, so any digest from upstream is invalid for what it serves.

`verify-zonemd` (§5) is not origination and must not be stripped.

### 3.7 Turning it off

When the option goes off, whatever the server put in the zone has to come out,
and the apex NSEC bitmap has to be restitched to match. Leaving it would serve
a digest that freezes at the last publish and then rots.

The flip is observable — config reload and `zone set-option` both know the old
and the new value — so handle it there: on a false transition, stage the
deletion once and let the ordinary publish carry it. Steady-state "option is
off" then means "do not touch the apex ZONEMD at all", which leaves an
operator-authored ZONEMD in a hand-written zone file alone, as it should.

## 4. Cost, and what to do about it

The number is already in the tree. `zone_utils.go:237` records ~9 s to parse
and digest a 1.1M-record zone, "the digest being some 80% of it" — about 7 s
of digest. Recomputing that on every publish is not viable for a large zone
under dynamic update, and the proposal is not honest without saying so.

Where the time goes: `canonicalRRWire` runs `dns.Copy` + `dns.PackRR` per RR,
and the sort comparator calls `SplitDomainName` + `ToLower` on both operands
per comparison. Neither the hashing nor the I/O dominates.

**The digest is not incrementally updatable.** SIMPLE is a single SHA-384 over
a canonically sorted concatenation; there is no way to patch the middle of it.
Anyone who reaches for an incremental scheme is reaching for a Merkle or
XOR-based construction, and RFC 8976 defines neither. So the cost is real and
the answer is to make the constant smaller, not the complexity.

Staged:

- **P1 — ship the straightforward version.** Full recompute per publish, only
  for zones with the option on. Note that the publish cadence (default 5 s,
  `publish-cadence`) already coalesces bursts of updates into a single
  publish, so the cost is per-publish and not per-update; an operator of a
  busy large zone raises the cadence.
- **P2 — cached canonical sort keys.** Precompute each owner name's canonical
  sort key once (reversed, lowercased labels as a single `[]byte`) and sort
  with `bytes.Compare`. This also speeds up `workingOwnerNamesLocked`, which
  every signed-zone publish already pays for the NSEC restitch, so it is worth
  doing whether or not ZONEMD ships.
- **P3 — cached wire encodings.** Keep the canonical wire form per RRset,
  invalidated when the RRset is staged. A publish that touched three owners
  then re-encodes three owners instead of the zone. This removes the dominant
  term.
- **P4 — only if measurement demands it.** Per-owner contiguous buffers so the
  hash pass reads fewer, larger slices.

Ship P1 and P2 together; P3 behind a benchmark on a zone of the size that
motivated the 9-second measurement.

One operational guard: on the first publish of a zonemd zone, log the measured
digest time at INFO, and at WARN above a threshold (say 250 ms). An operator
should learn the per-publish cost from a log line at startup, not from update
latency in production.

## 5. Configuration and control surface

### 5.1 Zone option and parameters

```yaml
zones:
  example.com:
    options: [ publish-zonemd ]
    zonemd:
      algorithms: [ 1 ]      # 1 = SHA-384 (default), 2 = SHA-512
      scheme: 1              # SIMPLE; the only scheme implemented
```

`OptPublishZonemd` is appended at the end of the `iota` list in `enums.go`
(25 of the 32 values in `TdnsZoneOptionMax` are used, so there is room), added
to both string maps, and given a case in `parseZoneOptions`
(`parseoptions.go:147`) — `zone_option_coverage_test.go` fails otherwise, and
the failure mode it guards against is the zone going off the air with "unknown
config option".

The parameters go in a `Zonemd` struct on `ZoneConf`, not in the option,
because `Options` is a `map[ZoneOption]bool` by construction.

They do **not** go in the DNSSEC policy. ZONEMD is not DNSSEC: it applies to
unsigned zones too, and binding it to a policy would make an unsigned zone
need one to get a digest.

### 5.2 Verification (phase 3)

The half labstuff has and tdns lacks:

- `verify-zonemd` zone option: verify the apex ZONEMD of a zone loaded from
  file or received over AXFR/IXFR, before publishing it. Fail-closed by
  default for a mirroring secondary — a zone whose digest does not verify is
  a zone whose contents are in question — with a config escape to warn-only.
  Skip verification when the ZONEMD's scheme or hash algorithm is not one we
  implement, rather than treating unsupported as invalid.
- `tdns-cli zone zonemd status <zone>`: published scheme/algorithm/serial/
  digest, whether a recompute over the current snapshot reproduces it, and the
  measured cost of that recompute.
- `tdns-cli zone zonemd verify <zone>`: recompute and compare, the local
  equivalent of `axfr-cli zone verify`.
- `dog` / client-side: AXFR a remote zone and verify its ZONEMD, including
  labstuff's `--ignore-serial` behaviour for zones whose serial has moved
  since the digest was taken.

## 6. Alternatives considered

**Compute at zone-file write only** (labstuff's model). Rejected: the served
zone and the file diverge immediately, AXFR and IXFR carry no valid digest,
and `ZONEMD.Serial` is wrong for every serial published after the write. It is
the right design for a file pre-processor and the wrong one for a nameserver.

**Deferred recompute at a second serial** (publish, digest, publish again).
Rejected on the NSEC-chain grounds, and it is worse than it looks: every
publish becomes two serials and two IXFRs for every secondary, and the window
between them is one in which the zone actively advertises a digest that does
not match its contents. A verifier cannot tell that from tampering.

**Compute on AXFR-out.** Rejected: the record has to be in the snapshot to
appear in the IXFR delta and in the zone file at all, and a per-transfer
digest is an uncacheable O(zone) cost per client.

**A separate zonemd engine, like the resigner.** Rejected: it is the deferred
recompute with a goroutine around it, and inherits the same second-serial
problem.

**Incremental digest.** Not available under SIMPLE. See §4.

## 7. Test plan

The whole feature reduces to one checkable invariant:

> For every serial a zonemd zone publishes, recomputing `ZoneDigest` over the
> published snapshot reproduces the apex ZONEMD RDATA, and
> `ZONEMD.Serial == SOA.Serial`.

Hang it off the existing publish-path harness (`nsec_property_test.go` has the
shape: build a zone, mutate it, serialise the published snapshot, assert). One
helper — `assertZonemdMatchesSnapshot(t, zd)` — called after each of:

- a DDNS update and an API update;
- `SignZone` and `ResignZone`;
- a key rollover step that republishes DNSKEY;
- `WriteZone` followed by a reload of the written file (requirement 5, the one
  that catches a canonicalization difference between the write and read paths);
- an inbound IXFR on an inline-signing secondary;
- an NSEC restitch that adds and removes a name (requirement 3, the one that
  catches a digest taken before the chain was final);
- the option turning on, and turning off again.

Plus: the RFC 8976 Appendix A vectors already in `zonemd_test.go` stay as the
canonicalization ground truth, and a test that `fileDigest` is unchanged by
publishing a ZONEMD (§3.5).

## 8. Phasing

1. **Publish.** Option, config, `ensureZonemdPresenceLocked` +
   `updateZonemdLocked`, signing, journal exclusion, DDNS/API gate, role
   normalization, removal-on-flip, P2 sort keys. Tests per §7.
2. **Cost.** P3 wire cache, benchmarked on a large zone.
3. **Verify.** `verify-zonemd`, the CLI surface, `dog`.

## 9. Effort estimate

Calibrated against four comparable changes already in this tree, measured by
`git show --stat`:

| Change | Commit | Insertions (prod / test) |
| --- | --- | --- |
| NSEC restitch in the publish path | `0184e538` + 3 follow-ups | ~450 / ~480 |
| Zone-file identity (the ZONEMD detector) | `c622ba2a` | 356 / 211 |
| `on-conflict-*` zone option + behaviour | `4aad47a6` | 178 / 202 |
| Journal operator surface (API + CLI) | `abdfe783` | ~360 for the surface alone |

The NSEC work is the closest analogue to Phase 1 and the most useful number in
the table — including the shape of its cost. It landed at 431 insertions and
finished at ~930 after two review rounds, so **budget roughly 2× the first
cut**. It needed no option, no config and no CLI, all of which ZONEMD does.

### Phase 1 — publish

| Component | Files | Prod | Test |
| --- | --- | ---: | ---: |
| Presence, digest, signing, failure path | `zonemd_publish.go` (new) | 180–240 | |
| Publish-path wiring | `zone_mutation.go` | 25–40 | |
| Working-set digest + reuse at write | `zone_file_state.go`, `zone_utils.go` | 40–60 | |
| Option constant + string maps | `enums.go` | ~8 | |
| Option case + algorithm validation | `parseoptions.go` | 25–35 | |
| `zonemd:` config block | `structs.go`, `parseconfig.go` | 40–60 | |
| Origination normalization | `zone_option_normalize.go` | ~6 | |
| Conditional journal exclusion | `nsec_restitch.go` + callers | 20–30 | |
| Skip ZONEMD in the two sign loops | `sign.go` | 10–15 | |
| DDNS/API gate on the apex ZONEMD | `update_policy_eval.go`, `zone_update_verbs.go` | 30–45 | |
| Removal on option flip | `dynamic_zones.go`, `config.go` | 30–50 | |
| Canonical sort keys (P2) | `zonemd.go`, `zone_mutation.go` | 60–90 | |
| §7 invariant matrix + option-coverage | `zonemd_publish_test.go` + others | | 400–550 |
| **Total** | | **470–680** | **400–550** |

**~900–1,250 insertions**, ~700 of it on a first cut.

### Phase 2 — cost

| Component | Prod | Test |
| --- | ---: | ---: |
| Per-RRset wire cache + invalidation across the staging entry points | 150–250 | |
| Cached-equals-uncached property test + benchmark on a large zone | | 150–250 |
| **Total** | **150–250** | **150–250** |

**~300–500 insertions.** The line count understates the risk: the cache has to
be invalidated at every staging path (`stageRRsetLocked`, `stageNsecLocked`,
`cloneOwner`, the delete variants), and the snapshot immutability invariant
documented at `snapshotMapFromData` means it must not be hung off state shared
between a snapshot and a working set. This is why it sits behind a benchmark
rather than shipping with Phase 1.

### Phase 3 — verify

| Component | Files | Prod | Test |
| --- | --- | ---: | ---: |
| `verify-zonemd` option + fail-closed/warn knob | `enums.go`, `parseoptions.go`, `parseconfig.go` | 50–80 | |
| Verification on load and transfer-in | `zone_utils.go`, `refreshengine.go` | 80–120 | |
| `zone zonemd status|verify` API + CLI | `api_structs.go`, `apihandler_zone.go`, `cli/zone_zonemd_cmds.go` | 200–260 | |
| `dog` client-side verify | `cmdv2/dog` | 80–120 | |
| Tests | | | 200–300 |
| **Total** | | **410–580** | **200–300** |

**~600–880 insertions.**

### Total

**~1,800–2,600 insertions, midpoint ~2,200**, of which roughly 750–1,100 is
test code. Nearly all of it is additive; the only existing code rewritten is
`withoutDerivedRecords`'s signature, the two apex loops in `sign.go`, and the
sort-key change in `canonicalOwnerLess`'s callers.

Phase 1 is the only phase that has to land as a unit — a half-implemented
ZONEMD publishes a wrong digest, which is the one outcome §3.2 rules out.
Phases 2 and 3 are independently shippable and independently skippable.
