# Reconciling the Zone File with the Delta Journal

2026-08-17

## 1. What this is about

Phase 2 gave a primary zone a **delta journal**: changes applied through
DDNS or the management API are recorded in the `ZoneDelta` table at
publish time and replayed over the zone file on load, so a restart loses
nothing. The journal is anchored to the zone file — the first delta's
`fromserial` is the serial of the file it was computed against.

That anchoring is what makes the journal meaningful, and it is also its
single point of failure. If the file on disk is no longer the file the
journal was computed against, the chain cannot be replayed, and today the
load refuses it wholesale.

This document specifies what should happen instead.

## 2. What went wrong, concretely

On `cpt-proxy.axfr.net`, `dnslab.` reached this state:

| | |
|---|---|
| zone file | serial `2026081701` |
| journal | `…03 → …04`, `…04 → …05`, `…05 → …06` |
| served after load | `2026081703` |

The journal had been written by a pre-fix binary that anchored deltas to
the *published* serial rather than to the file's. On restart, the current
binary correctly refused the chain:

```
could not replay persisted deltas; the zone is serving its file alone
  and recent changes are NOT present
  deltas start at serial 2026081703, file is at serial 2026081701
```

Detection worked. What followed did not. The zone served the file,
republished to `…03` after load-time signing, and the operator's next
update published `…03 → …04` — a `toserial` the journal already holds.
`UNIQUE (zone, toserial, seq)` rejected the row, the publish was refused,
and **every subsequent update failed identically**. One stale journal
rendered the zone permanently unable to accept a change, reporting a
SQLite constraint rather than the actual problem.

Worse, the remedy the refusal names does not exist:

- `write` / `sync` / `freeze` drop deltas only *through the written
  serial*, so a journal sitting **ahead** of the current serial survives
  the write-out untouched.
- there is no command to clear the journal at all.

So there are two distinct defects: a design gap (no reconciliation path)
and a plain bug (a stale journal occupies serial space and bricks the
zone).

## 3. Position relative to the long-term goal

The agreed long-term direction is that **the database holds the zone**
and the zone file becomes an export of it. That is a larger refactor than
is in scope here, with known unknowns.

The present design is deliberately a compromise: file-authoritative
storage with a journal carrying what the file does not have. But the
reconciliation rule below moves in the agreed direction rather than away
from it — it accepts data in the DB as a potentially *permanent* part of
the served zone, never forced out into the file. That is DB-as-truth
reached inefficiently (replaying a journal rather than storing the truth
directly), but it is the same destination.

## 4. Detection: a canonical content digest

### 4.1 Why not a file hash

A byte-level hash of the zone file answers "did these bytes change",
which is not the question. Reordering records, adding or editing
comments, reflowing whitespace, changing `$TTL` style or `$ORIGIN` usage
— none of these change the zone, and all of them would register as
divergence. The zone file is meant to stay human-authored and
revision-control friendly; a detector that fires on formatting makes it
neither.

### 4.2 ZONEMD

Use the RFC 8976 ZONEMD digest computation: canonical ordering, canonical
wire form, the apex ZONEMD RRset excluded. It is exactly a
content-semantic fingerprint of a zone, it is specified rather than
invented here, and it is immune to every formatting change listed above.

We use the **algorithm**, not necessarily the record: nothing is
published. If we compute it anyway, publishing ZONEMD later becomes
nearly free.

Cost is a canonical sort plus one digest pass over a zone we have just
parsed. A signed zone already pays the canonical-ordering cost for its
NSEC chain.

RRSIGs fall inside the digest, which is harmless here because we only
ever compare **file to file**, never file to in-memory: the in-memory
zone carries freshly minted signatures by construction and would never
match. An externally re-signed file does read as changed, which is
correct.

*Implementation note:* the tree has `dns.TypeZONEMD` but no digest
computation. Either miekg/dns provides one in a version we can pin, or we
write it — a few dozen lines over the canonical iteration we already
have.

### 4.3 What is recorded

Per zone, at every read from and every write to the zone file:

```
ZoneFileState(zone, serial, digest, algorithm, scheme, updated)
```

`serial` is retained alongside the digest because it is what the refusal
messages and the serial floor (§8) are stated in.

### 4.4 The three outcomes at load

| Recorded digest | Verdict |
|---|---|
| matches the file | the file is the one the journal was computed against — replay as today |
| differs | the file changed — reconcile (§5) |
| absent | no basis for comparison — reconcile (§5) |

The third row is the upgrade case, and it wants no special handling: with
a reconciliation path available, "we cannot prove this is the same file"
is no longer fatal. Note that this alone would have carried `dnslab.`
through §2 without a brick.

## 5. The merge rule

When the file has changed, the merge is: **parse the new file, then
replay the journal onto it.** With `on-conflict-db-wins` (§9), the
journal wins every contest.

### 5.1 What a conflict is

The journal's *removes* name specific records. So:

> **A conflict is a record present in the new zone file that the journal
> deletes.**

That is computable from the journal alone. No old-file content, no
per-RRset digests, no extra bookkeeping — the ZONEMD stays purely a
detector.

Adds do not conflict. An add at an owner/type the new file also populates
simply unions, and a `replacerrset` carries its own removes, so genuine
replacements are caught by the rule above.

### 5.2 The mirror case does not exist (corrected)

This section previously claimed a second, symmetric contest — *the
journal adds R and the new file lacks R, so the operator deleted it*.
**That case does not exist**, and implementing it would have flagged
every ordinary journal entry as a conflict.

A journal ADD implies the **old** file lacked that record: the delta was
computed as the difference from that file, so anything it adds was absent
there. Therefore:

- the new file also lacks it → it agrees with the old file, and the
  operator removed nothing;
- the new file has it → the operator added the same record
  independently, which is agreement.

Neither is a conflict and neither needs resolving. The consequence is
that §5.1 is the whole rule, every inverse is an `ADD`, and the artefact
in §6 never contains a `DEL`.

**One conflict does stay invisible**, and no care in the implementation
would surface it: an operator who regenerates the file from the *live
zone* while deliberately omitting a record the journal added. That file
is indistinguishable from one that simply predates the addition, and
telling them apart needs the old file's contents, which is not something
we store. Named here rather than papered over.

### 5.3 Summary

| Situation | Merged result | Reported |
|---|---|---|
| journal deletes R, file has R | R absent | yes |
| journal adds R, file lacks R | R present | no — the old file lacked it too (§5.2) |
| journal adds R, file has R | R present | no — agreement |
| file changed something the journal never touches | file's version | no — uncontested |
| journal touches something the file never had | journal's version | no — uncontested |

## 6. The `.rejected` artefact

Every merge that resolved at least one conflict writes:

```
{zonefile}.{serial}.rejected
```

where `{serial}` is the **new file's** serial — it identifies the file
whose records were overruled.

### 6.1 It is an executable inverse, not a description

The file is not a list of what was rejected. It is *the update that would
undo the merge's decisions in favour of your zone file*:

| Conflict | Instruction |
|---|---|
| journal deleted R, your file had R | `ADD R` |

There is only one row, for the reason given in §5.2, so an artefact
consists entirely of `ADD` lines. The format still carries `DEL` — it is
shared with `journal purge` and `journal list --instructions`, which do
emit both.

So an operator who disagrees with the merge inspects it and feeds it
straight back through `tdns-cli auth zone update`. The descriptive
reading — "here is what was thrown away" — is strictly less useful and
cannot express the mirror case of §5.2 at all.

Format is one instruction per line, `ADD`/`DEL` followed by the record in
presentation format, with comments carrying the zone, the serials
involved and the timestamp.

### 6.2 The artefact is an input format, not just an output

```
tdns-cli auth zone update --from-file {file} --zone <zone> --via <api|ddns>
```

The intended workflow is not "replay the whole thing or nothing". It is:
**open the file, delete the lines you agree with, keep the ones you
don't, replay what's left.** The merge decided in favour of the journal;
this is how an operator selectively overrides that decision, record by
record, having seen exactly what it cost.

That makes the format a first-class *input*, which raises the bar on it:

- comments (`;` and `#`) and blank lines are tolerated everywhere, since
  the file is meant to be edited by hand;
- parse errors name the line number and the offending text — an operator
  editing at 3am gets told which line, not that "the file is invalid";
- the surviving instructions apply as **one** update, atomically. A
  half-applied reconciliation is a third state nobody asked for.

Nothing about the format is specific to `.rejected`. `--from-file` is
simply "apply this list of ADD/DEL instructions to this zone", which is
also what `journal purge` emits (§10.4), what `journal list
--instructions` prints (§10.3), and a reasonable batch-update input for
anything scripted.

## 7. Re-anchoring, not rewriting

After a merge the journal is anchored to a file that no longer exists.
The obvious repair is to write the merged zone out and drop the journal —
and it is the wrong one. It destroys record ordering and comments, breaks
the file's usefulness under revision control, and on a signing zone would
spray out signatures that go stale immediately.

Instead, **re-anchor**:

1. diff the merged zone against the parsed new file — `computeZoneDelta`,
   which already exists and already runs on every publish;
2. replace the journal, in one transaction, with that single delta,
   recorded against the new file's serial and ZONEMD.

The journal once again means exactly "what this file does not have", the
anchor is correct, the serial-collision class disappears by construction,
and **the operator's file is never touched**. The file is rewritten only
on an explicit `write` / `sync` / `freeze` — when the operator asked for
it.

This is also the mechanism by which §3 holds: journal content can remain
in the DB indefinitely, a permanent part of the served zone, without ever
being forced into the file.

## 8. Serial floor

The merged zone must publish at a serial strictly newer (RFC 1982) than
**both**:

- the highest serial this server has previously served for the zone, and
- the new file's serial.

`dnslab.` is the live example of why the second alone is insufficient:
file at `…01`, served at `…03`, journal head at `…06`. Publishing at
`…02` would take the zone backwards for every secondary that already
holds `…03`.

## 9. One path, and the option

**Startup and explicit reload take the same path.** The digest tells us
whether the file changed regardless of who asked; two behaviours for one
situation is how this class of bug returns. A crash-restart with content
in the journal must apply it — that is the entire point of the journal.

Stages 1–3 wired only the startup path, and the sentence above stayed
untrue until Stage 4 (§13, #362): reload went through the serial-gated
refresh instead, which reached neither the digest nor the merge. The
class of bug returned exactly as predicted, in both of the directions a
serial comparison is wrong in.

The per-zone option:

```yaml
options: [ on-conflict-db-wins ]     # or on-conflict-zonefile-wins
```

`on-conflict-db-wins` is the first and initially the only supported
behaviour; `on-conflict-zonefile-wins` is specified here so the option's
shape is not invented later, and implemented in a second step. Under it
the resolution inverts and the `.rejected` artefact describes the
*journal* records that lost.

The option governs conflict resolution only. Detection, merging,
re-anchoring and the serial floor are unconditional.

### 9.1 The default is materialized at parse

`on-conflict-db-wins` is the default. It is not implemented as a
fallback read at each decision point, but **set on the zone during option
parsing** whenever `on-conflict-zonefile-wins` is absent.

The difference matters. A default that lives in the code as "if neither
option is set, assume db-wins" has to be remembered at every site that
asks, and the day one site forgets, a zone silently resolves conflicts
the other way. Materializing it means every zone carries exactly one of
the two options, always, and the merge code asks a question with two
answers rather than three.

It is also what an operator sees: `zone status` and the journal `status`
below report the option the zone is actually running under, not a blank
that has to be interpreted.

Setting **both** options is a contradiction, not a preference order: it
is a hard config error at startup, in line with how the other mutually
exclusive zone options are treated.

## 10. The journal CLI

The journal is durable state that decides what a zone serves, and until
now it has had no operator surface at all — not even a way to see whether
it holds anything. That is the gap `rm zone.jnl` fills in the BIND world,
badly.

```
tdns-cli auth zone journal status  --zone <zone>
tdns-cli auth zone journal list    --zone <zone> [--serial <n>] [--instructions]
tdns-cli auth zone journal truncate --zone <zone> --after <serial>
tdns-cli auth zone journal purge   --zone <zone> [--force]
```

### 10.1 A chain admits only two kinds of edit

The journal is a chain: every delta's `fromserial` is its predecessor's
`toserial`, and replay refuses a chain with a gap (that check is why a
sequence like `A→B, C→D` cannot be applied as though the zone had been
`C`). So the chain-safe operations are exactly:

- **drop a suffix** — `truncate --after <serial>` keeps a valid shorter
  chain;
- **drop everything** — `purge`.

There is deliberately no "remove this record from the journal". It would
either leave a delta claiming a serial transition it no longer performs,
or require recomputing every downstream delta against a base that never
existed. The journal is a log; the way to correct a log is to append a
correction, which here means an ordinary `zone update` that undoes the
record. That is one command, it is auditable, and it cannot invent a
zone.

### 10.2 status

Reports what an operator needs before deciding anything:

- number of deltas, and the serial range they span;
- what the chain is anchored to, and whether the zone file still matches
  that anchor (§4) — the direct answer to "will this replay on restart?";
- when the file was last written, and how far behind it is;
- the conflict option in force (§9.1);
- the outcome of the last load: replayed cleanly, or merged — and if
  merged, where the `.rejected` artefact was written.

### 10.3 list

The deltas themselves. Default output is a per-delta summary; `--serial`
narrows to one; `--instructions` emits the same `ADD`/`DEL` format used
by `.rejected` (§6), so "what is in the journal that my file does not
have" and "give me that as something I can replay" are one command
apart.

### 10.4 purge

The `rm zone.jnl` equivalent — with the property that made `rm` a bad
answer removed. Purge always writes what it discards to

```
{zonefile}.{serial}.purged
```

in the executable-instruction format of §6, before deleting anything. So
purge is recoverable: the material is on disk, in a form that can be fed
straight back through `zone update`.

On a **healthy** journal, purge discards changes that exist nowhere else
and it refuses without `--force`, pointing instead at `sync` — which
folds the same changes into the zone file and loses nothing. `--force`
exists because "I do not want these changes" is a legitimate position;
it should just not be reachable by typo.

Note what purge is *not*, after §7: with re-anchoring, a journal that
cannot be replayed no longer persists as a stuck state, so purge is not
the recovery mechanism it would have had to be under the current design.
It is an expression of operator intent, plus a backstop for the residue
of an older binary — exactly the `dnslab.` case in §2.

## 11. The plain bug

Independent of everything above, and true whatever reconciliation policy
is in force:

- `PersistZoneDelta` must reject a non-advancing serial with a diagnosis
  in English rather than surfacing a SQLite `UNIQUE` constraint.
- A journal that could not be applied must never sit in the serial space
  silently blocking future updates. §7 removes the cause; this is the
  backstop.

## 12. Out of scope, but noted

- **RRSIGs in the zone file.** For an online- or inline-signing zone,
  writing signatures into the file is questionable — they are regenerated
  on load and the journal already omits them for exactly that reason.
  Worth a separate look at `WriteZoneToFile`.
- **Publishing ZONEMD.** Cheap once §4 exists; a feature in its own right.
- **DB-as-truth.** The refactor this design is a step toward, not a
  substitute for.

## 13. Delivery

Four stages, each independently shippable and independently testable.

### Stage 0 — DONE, in #348 (`abdfe78`, `2b6f909`)

The plain bug (§11), the journal CLI (§10) and `--from-file` (§6.2).

It was a merge precondition, not a nice-to-have: #348 introduced durable
state that decides what a zone serves and gave the operator no way to see
it, list it, or clear it — there was no `journal` command in the tree at
all. A journal you cannot inspect is worse than no journal, because when
it misbehaves there is nothing to look at. Stage 0 also converted the §2
failure from a SQLite constraint into a diagnosis with a remedy, which is
what makes shipping the rest as follow-on work acceptable rather than
reckless.

**Estimated ~800 LOC; actual 2341 insertions** across the two commits —
low by about 3×. The overrun was almost entirely the review round, which
found two durability defects in the seam this design depends on:

- `WriteZoneToFile` discarded `bufio.Writer.Flush`'s error and returned
  the nil error from the last `WriteString`; `WriteFileWithSerial` never
  closed the file. `WriteZone` treats that success as licence to delete
  the journal, so a failing disk took the file and the journal together.
  Now flush/sync/close are all checked and the write is staged in a
  temporary file and renamed into place, with the directory synced.
- `JournalPurge` snapshotted the journal and then deleted every row, so
  an update publishing in that window was destroyed and recorded nowhere.
  The delete is now bounded by the row id the snapshot covered.

Both are worth knowing for what follows: §7 re-anchors the journal after
a merge, and that is the same seam.

**Scope that moved forward.** `--from-file` brought the whole instruction
format with it — writer, parser, `writeInstructionFile`, and the
`instructions` verb — which had been budgeted inside Stage 2 at ~410
lines. So `.rejected` is now "compose different comment lines and call
the existing writer", and Stage 2 shrinks accordingly.

### Stages 1–3 — DONE, on `feature/zonefile-journal-reconciliation`

`feature/zonefile-journal-reconciliation`, cut from
`feature/api-zone-updates-phase2` and initially targeting it, so GitHub
retargets the PR to `main` when #348 lands (no rebase).

Not off `main`: this work touches `zone_delta_replay.go`,
`zone_utils.go`, `dnsutils.go` and `refreshengine.go`, all of which #348
has not landed yet. Not stacked under #349/#350 either, which would bind
reconciliation to unrelated DSYNC work. A sibling keeps the review depth
where it is; the one shared file at risk of collision with #349 is
`guide/zone-updates.md`.

| Stage | Content | Estimate | Actual | Commit |
|---|---|---|---|---|
| 1 | ZONEMD + `ZoneFileState` + detection | 450 | ~960 | `5a84937`, `c622ba2` |
| 2 | merge, re-anchor, `.rejected`, serial floor | ~800 | ~890 | `93235ab`, `47f0c62` |
| 3 | the option, defaulted at parse | 150 | ~330 | `4aad47a` |
| 4 | reload takes the same path (#362) | — | ~190 | `feature/reload-reconciliation` |

### Stage 4 — reload takes the same path

Not foreseen as a stage: §9 states the property, and the startup path
was taken to be the only path that reads a zone file. It is not. An
explicit `zone reload` and the refresh ticker both re-read a primary's
file through `Refresh` → `FetchFromFile`, which decided on the SOA
serial and never reached the digest.

Three things had to change, and they are all consequences of the same
mistake:

- **Detection.** The parser short-circuits as soon as it sees an SOA
  whose serial matches the last one read. `FetchFromFile` now parses the
  whole file unconditionally and decides on the digest, falling back to
  the serial only where there is no recorded identity to compare
  against. `--force` re-applies an unchanged file rather than parsing it
  and discarding the result.
- **Reconciliation.** The merge/replay tail of `replayZoneDeltasOnLoad`
  became `ReconcileZoneFileWithJournal`, which both entry points call.
  Not on a first load from `FetchFromFile`, though: that path must
  reconcile after the DNSSEC policy is bound, or replay signs with a nil
  policy and mints five-minute RRSIGs.
- **The serial floor.** A reload adopts the new file as the journal's
  anchor but bumped the served serial by one, so a file whose serial had
  jumped ahead left the anchor above the zone and `PersistZoneDelta`
  refused every subsequent update. The reload now lands strictly newer
  than both, which is what §8 already required of the merge — it just
  has to hold when there is no journal to merge, too.

- **A stat gate in front of the digest.** Deciding on content means
  parsing and digesting the whole zone on every refresh interval, where
  the serial comparison it replaces stopped at the first SOA. Measured on
  a delegation-heavy zone: 133 ms at 22.5k records, 1.6 s at 225k, 9.3 s
  at 1.1M — the digest being some 80% of each — against 21–35 µs for the
  early return. The ticker calls `Refresh` inline in the refresh engine,
  so that is not just CPU but head-of-line blocking for every other zone.
  The file's mtime and size, recorded in memory at every read and every
  write, now decide whether to look at all; the digest still decides what
  looking means. One full parse per zone per process start, 17 µs
  thereafter. §4.1's objection to byte-level comparison does not apply to
  it: that objection is to false POSITIVES from reordering, comments and
  whitespace, and a stat gate can only produce a false negative — a file
  rewritten to the same size with its mtime restored.

  The gate has one coupling that is not obvious and is easy to reintroduce.
  The identity is recorded on success only, so that a load which could not
  deal with the file leaves the previous identity in place and the next load
  sees the file as CHANGED and retries. A cached stat saying "nothing has
  touched it" defeats that retry entirely — the next refresh does not read
  the file at all, and the merge is not attempted again until the process
  restarts. So the two are set together and dropped together: **a cached stat
  is only ever trusted while a recorded identity describes the file it
  names.** Neither branch had this defect on its own; it appeared only when
  the two were merged.

One judgement call beyond the issue: a dirty primary was refused a
reload outright. Since both replay and merge set that flag at every
load, the refusal made `zone reload` permanently unavailable to exactly
the zones this design is about. It now refuses only what it was
protecting — changes the journal is not recording, i.e. no database or
`journal: active: false`.

Stage 1 ran over because the RFC 8976 digest is more than a hash call:
canonical ordering (labels compared right-to-left, case-insensitively)
and RFC 4034 §6.2 RDATA down-casing had to be written, neither existing
in the tree. Validated against all three Appendix A vectors — and A.2
caught a real bug, out-of-zone data not being excluded, that A.1 and A.3
cannot see.

Stage 1 is worth having on its own even if 2 never shipped: it replaces a
serial comparison that lies about reformatted files with a content digest
that doesn't.

**The delegation-backend question — resolved, and it does not affect
§5.** `ChildDelegationData` is not zone content. `DBDelegationBackend`
writes rows and touches neither the served zone nor the zone file (the
`CHILD-UPDATE` branch of the updater dispatches solely to the backend),
so a merge has nothing to reconcile it against. §5 stands unchanged.

That investigation did surface something separate and worth its own
work: nothing validates the *combination* of application role, zone type
and delegation backend. The only rule today is that
`allow-child-updates` requires some backend. Combinations that cannot
work — `direct` on an instance that does not serve the zone, `direct` on
a secondary — are accepted silently. Tracked separately; not part of this
design.

## 14. Verification

1. **No change** — restart with an untouched file; digest matches;
   journal replays; no `.rejected`.
2. **Formatting only** — reorder records, add comments, reflow; digest
   matches; journal replays; no `.rejected`. *(This is the case a byte
   hash would fail.)*
3. **Composable edit** — edit RRsets the journal never touches; digest
   differs; merge keeps both sides; no conflicts reported.
4. **Delete conflict** — the file contains a record the journal deletes;
   record absent after merge; `.rejected` contains `ADD` for it.
5. **Mirror conflict** — the file lacks a record the journal adds; record
   present after merge; `.rejected` contains `DEL` for it.
6. **Feeding `.rejected` back** through `zone update` restores the file's
   version of every contested record.
7. **Serial floor** — file rolled back below the served serial; merged
   zone publishes above the previously served serial.
8. **Re-anchor** — after any merge, the file is byte-identical to before,
   and the journal holds exactly one delta chaining from it.
9. **Restart after merge** — replays cleanly, no refusal, no `.rejected`.
10. **The `dnslab.` case** — the exact §2 state reproduced from scratch
    loads, merges, and accepts the next update.
