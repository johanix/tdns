# NSEC chain correctness

A signed zone's NSEC chain is wrong in several independent ways. This
documents what is wrong, why none of it has been visible, and the plan to
fix it.

## 1. Why this was invisible

Denial of existence is answered by compact denial (`addCDEResponse`), which
synthesises an NSEC per query with `NextDomain = "\000." + qname` and never
reads the stored chain. So on the signing server every query is correct no
matter what the chain says, and the defects below cannot be reproduced by
querying it.

They are not hidden anywhere else. Synthesising a denial means **signing**
it, which requires the private key at the responder. A secondary does not
have the key, so it cannot synthesise: it answers denial from the chain it
received over AXFR. Every defect below is live on every secondary, which is
the ordinary way an authoritative zone is served.

Concretely, a secondary was observed answering an address for a name while
serving a signed NSEC asserting that no name exists in the span containing
it — a valid signature over a false statement. Under RFC 8198 aggressive
use a resolver may cache that span and synthesise NXDOMAIN for the live
names inside it without asking again.

The only way to see any of this is whole-zone analysis (`dig AXFR` +
`dnssec-verify`) or a query against a secondary. **A test that queries the
signing primary proves nothing about the chain.**

## 2. The defects

### 2.1 The chain is in lexicographic order, not canonical order

`workingOwnerNamesLocked` sorted with `sort.Strings`. The NSEC chain is
built by walking that slice and linking each name to the next, so the sort
order *is* the chain order, and it has to be RFC 4034 §6.1 canonical order:
labels compared from the right, each as a case-insensitive octet string.

The two disagree whenever a label boundary falls inside a shared prefix,
which is the common case for a zone whose apex is a prefix of its children.
For a zone holding `clean.example.` plus `alpha`, `bravo`, `charlie` and
`ns` under it, the lexicographic sort produces

    alpha, bravo, charlie, clean.example., ns

so the chain runs `charlie → clean.example. → ns → alpha`, while canonical
order requires the apex first:

    clean.example., alpha, bravo, charlie, ns

The result is a chain that is a permutation of the right names in the wrong
sequence. `dnssec-verify` rejects it with `next name mismatch`.

### 2.2 The chain is not maintained when the zone changes

`GenerateNsecChainWithDak` is reached only from `ResignZone`, `SignZone` and
`GenerateNsecChain` — that is, from the periodic resigner, an explicit sign,
and policy application. The publish path re-signs the SOA and nothing else.

So an update publishes a snapshot whose chain does not describe it: a name
added has no NSEC, a name removed still has one, and the neighbours are not
re-linked. The periodic resigner repairs some of this later, but that is a
second publish at a second serial — secondaries see two changes and serve a
broken chain in between. **The chain has to be correct in the snapshot being
published, not in a later one.**

### 2.3 Deleted names survive as ghosts

Deleting the last real RRset at a name leaves its NSEC and that NSEC's RRSIG
behind. The name therefore still owns RRsets, stays in the working set, and
gets an NSEC generated for it on the next pass — for ever. The chain proves
the existence of a name that has no data.

This does not fail `dnssec-verify`; a chain containing a data-less name is
internally consistent. It is wrong in meaning rather than in form.

### 2.4 NSEC TTL is not the SOA minimum

The NSEC RR is built by string concatenation without a TTL, so `dns.NewRR`
applies its default. RFC 4034 §4 says the NSEC RR SHOULD carry the SOA
minimum. BIND uses the SOA minimum; a zone with `minimum 300` was observed
carrying NSEC records at 3600.

### 2.5 Non-authoritative names are given NSEC records

The generator walks every owner name in the working set. Names below a
delegation — glue, and anything else occluded — are not authoritative data
and must not appear in the chain at all.

Verified against BIND 9.18.50 for a zone with a `child.example.` delegation
and `ns1.child.example.` glue: BIND emits an NSEC at the delegation point
with bitmap `NS RRSIG NSEC`, and **none** for the glue.

`ResignZone` already computes a delegation set for signing, but with
`strings.HasSuffix(name, del)` — a string test, not a label test, so
`notexample.com.` matches `example.com.`. Reusing it requires fixing it to
`dns.IsSubDomain`.

### 2.6 Empty non-terminals: nothing to do

An ENT owns no RRsets, so under NSEC it gets no NSEC record. Verified
against BIND: for a zone containing `deep.sub.example.` and no
`sub.example.`, BIND generates no NSEC at `sub.example.` and the chain skips
straight over it. This matches RFC 4035 §2.3, which requires an NSEC only
for names with authoritative data or a delegation NS RRset.

This is the opposite of NSEC3, where ENTs do get hashed entries. Recorded
here because it is the obvious thing to "fix" and would be wrong.

### 2.7 Not a defect: the dead `hasRRSIG` flag

`GenerateNsecChainWithDak` declares `hasRRSIG` outside its loop and never
resets it, which looks like a bitmap bug. It is not reachable: `SortFunc`
routes parsed RRSIGs into the `.RRSIGs` field of the RRset they cover, never
into an `RRtypes[RRSIG]` key, so the flag can never become true. The RRSIG
bit is decided by the zone-level signing condition instead, which is correct
for a signed zone because every authoritative name carries at least a signed
NSEC. Removed as dead code, not as a fix.

## 3. Where NSEC should live

RRSIGs are not stored as RRsets of their own. They are a field on the RRset
they cover, and every consumer knows to read that field: the parser writes
it, `RRsetToString` serialises it, `diffOwner` diffs it into IXFR, and the
ZONEMD collectors digest it. The one place that does *not* see it is the
delta journal, whose row builder flattens `rrset.RRs` only.

That is exactly the right split, and it is achieved structurally rather than
by a rule anyone has to remember:

> **authored data lives in `RRtypes` and is persisted; derived data lives in
> fields and is emitted only to the wire.**

NSEC is derived data stored as authored data, and the two defects that
follow from that placement are 2.3 and the journal problem. Moving NSEC to
an owner-level property makes both unrepresentable:

- a name whose last RRset is deleted has nothing left to keep it in
  `RRtypes`, so it ceases to exist and its NSEC property goes with it —
  ghosts become impossible rather than pruned;
- `ReplaceZoneJournal` reads `rrset.RRs`, so NSEC changes never reach the
  journal — no filter to apply and none to forget.

The second matters because restitching at publish (2.2) puts NSEC changes
into the publish delta. Without the move, every update would write NSEC rows
into the journal, and the zone-file reconciliation would then report
conflicts on records no operator ever wrote and offer `.rejected` artefacts
full of them.

### The trap

`zoneDigestOfWorkingData` and `ZoneDigestOfPublished` both walk
`RRtypes.Keys()` and append `.RRs` and `.RRSIGs`. Moving NSEC to a property
without teaching them silently drops NSEC from the digest — while the zone
*file* still contains NSEC records, because a secondary loading from disk
needs them. The load-time digest and the write-time digest would then
disagree for byte-identical content, the recorded file identity would never
match, and every load would report the file as CHANGED and merge over a file
nobody edited.

Both collectors must include the property, identically.

## 4. What was done

| Stage | Work | Status |
|---|---|---|
| 1 | Canonical ordering — reuse `canonicalOwnerLess` | done |
| 2 | NSEC as an owner property | done |
| 3 | Chain scope (delegations, glue) and NSEC TTL | done |
| 4 | Restitch and resign at publish, before the snapshot swap | done |
| 5 | Chain invariant check | done |

An empty-non-terminal stage was planned and dropped: §2.6 records why.

### Stage 4, as built

The restitch runs inside `publishSync`, before the delta is computed and
before the snapshot swap:

1. staged changes are already in the working set
2. derive the changed names — from authoritative data only, never from the
   NSEC property, or the restitch responds to its own output
3. restitch NSEC around them: insert, delete, re-link neighbours
4. sign the affected NSEC RRsets
5. bump the serial and set the SOA
6. journal delta, with NSEC filtered out → persist
7. IXFR delta, with NSEC included
8. snapshot swap

Steps 3 and 4 run with `zd.mu` held, so the keys are resolved once with
`zdLocked=true` and passed into `SignRRset`. Without that it reaches
`EnsureActiveDnssecKeys`, re-locks `zd.mu` and hangs the publish — the same
trap the SOA re-sign already had, and now covered by its own test.

Neighbours are found by sorting the chain names per publish. Only the NSECs
that actually change are rebuilt and signed, which is the expensive part; the
sort is not. A maintained ordered index would remove the sort as well and is
the obvious next optimisation, but it is not needed for correctness.

### The journal filter, which stage 4 forced

Step 7 is why `computeZoneDelta` diffs the NSEC property: a secondary must
receive chain changes. But that same function feeds the journal, so NSECs
began being recorded there as authored data — and replayed into an owner's
`RRtypes` on restart, reinstating the ghosts the property model removes. It
showed up as duplicate NSEC records after a restart, one from the property
and one from the replayed journal.

So the journal delta drops NSEC while the IXFR delta keeps it. The journal
answers "what did someone change about this zone", and a regenerated record
is not an answer to it.

## 5. Testing

Two properties, checked against the zone as published rather than through
queries:

- the chain covers exactly the authoritative names, and is one cycle in
  canonical order closing on the apex, every link signed;
- that still holds after a sequence of inserts (middle, end, immediately
  after the apex), deletes (middle, last) and a bitmap change.

Writing that check found two defects that the end-to-end verification had
missed, both recorded in the commit that adds it: an early return that
skipped the "owns data" filter for any zone without a delegation, and an
existence test that counted RRtypes entries rather than records, so a name
whose last record was deleted still counted as present.

The end-to-end check is `dig AXFR` piped into `dnssec-verify`. On the zone
BIND 9.18 was given for comparison, tdns produces the same chain: the same
links, the same TTLs, the delegation point present, its glue and the empty
non-terminal absent.
