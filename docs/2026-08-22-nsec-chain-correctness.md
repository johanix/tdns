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

## 4. Plan

| Stage | Work |
|---|---|
| 1 | Canonical ordering — reuse `canonicalOwnerLess` |
| 2 | NSEC as an owner property |
| 3 | Generator correctness: TTL from SOA minimum, exclude non-authoritative names, delegation bitmaps, drop dead code |
| 4 | Restitch and resign at publish, before the snapshot swap |
| 5 | Verification harness |

Stage 1 is independent and shippable alone. Stage 2 is a pure refactor with
no behavioural change — it is worth doing before stage 4 rather than after,
because the restitch logic is written against wherever NSEC lives.

### Stage 4 in detail

The restitch belongs inside `publishSync`, before the snapshot swap, in this
order:

1. staged changes are already in the working set
2. derive the changed names
3. restitch NSEC around them — insert, delete, re-link neighbours
4. sign the affected NSEC RRsets
5. bump the serial and set the SOA
6. journal delta (NSEC absent by construction) → persist
7. IXFR delta (NSEC included)
8. snapshot swap

Steps 3 and 4 run with `zd.mu` already held, so both chain generation and
signing need `Locked` variants. `GenerateNsecChainWithDak` is currently
reached only from callers that take the lock themselves; calling it from
`publishSync` as it stands deadlocks.

Finding a name's neighbours requires an ordered view of the authoritative
names. The working set is a map, so this is a sorted index maintained
alongside it. The index is keyed by a function rather than by canonical name
directly: NSEC3, if it is ever wanted, differs in the ordering key (hashed)
rather than in the machinery. No other NSEC3 preparation is included —
opt-out and NSEC3PARAM semantics differ enough that guessing now would
likely be wrong.

## 5. Testing

Two properties, checked directly rather than through queries:

- the chain is a single cycle in canonical order, covering exactly the
  authoritative names, closing on the apex;
- after any sequence of adds and deletes, that still holds — including that
  a deleted name is gone from the chain and an added name is in it.

Plus `dnssec-verify` over an AXFR in the integration rig, which is what
would have caught all of this years earlier.
