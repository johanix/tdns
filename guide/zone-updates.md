# Changing Zone Content: DDNS and the Management API

A primary zone served by tdns-auth can have its content changed
in three ways: by editing the zone file and reloading, by
sending an RFC 2136 DNS UPDATE, or over the management API.
This document covers the last two — the two that change a
running zone without touching the file — and the CLI that
drives both.

Delegation data (a *child's* NS, glue and DS records in a
*parent* zone) is a separate subject with its own machinery;
see [Automatic Delegation Synchronization](special-features.md#1-automatic-delegation-synchronization).

## Contents

1. [The two channels, and how they differ](#1-the-two-channels-and-how-they-differ)
2. [Enabling each channel](#2-enabling-each-channel)
3. [The five statements](#3-the-five-statements)
4. [The CLI](#4-the-cli)
5. [What "applied" means](#5-what-applied-means)
6. [Durability: the zone file, and the delta journal](#6-durability-the-zone-file-and-the-delta-journal)
7. [freeze, thaw and sync](#7-freeze-thaw-and-sync)
8. [Working with the journal](#8-working-with-the-journal)
9. [Replaying an instruction file](#9-replaying-an-instruction-file)
10. [Refusals and what they mean](#10-refusals-and-what-they-mean)


## 1. The two channels, and how they differ

Both channels end in the same place — the `ZoneUpdater`, which
applies the change to the zone's working set and publishes a new
snapshot — and both accept the same five statements. They differ
in exactly one respect, and it is the important one:

| | RFC 2136 UPDATE (`--via ddns`) | Management API (`--via api`) |
|---|---|---|
| Credential | SIG(0) key, per message | `apiserver.apikey`, per connection |
| Authorization | the zone's `updatepolicy` | none beyond holding the key |
| Zone option | `allow-updates` | `allow-api-updates` |
| Who it is for | a zone's own operator, remotely | the operator of the *server* |

The API channel is a **trusted-operator** surface. Holding
`apiserver.apikey` is the authorization: requests are marked
`PreAuthorized` and `updatepolicy` is not consulted. That is
deliberate — it is the same key that can add and remove zones —
but it means the API key must be treated as what it is.

The DDNS channel enforces `updatepolicy` on every record, and a
SIG(0) key names a principal, so it is the channel for delegating
partial authority over a zone to someone else.

The two options are separate on purpose. Opening a zone to SIG(0)
DDNS does not open it to the API, and the reverse likewise. An
operator who wants both sets both.

> If you want granular, per-principal authority over a *child's*
> delegation without SIG(0), that is the DSYNC API scheme — a
> different surface again, with its own listener, its own
> credentials and full `updatepolicy` enforcement. See
> [special-features.md §1.7](special-features.md#17-parent-the-dsync-api-scheme).


## 2. Enabling each channel

Per zone, in the `zones:` block:

```yaml
zones:
   - name:     alpha.dnslab.
     type:     primary
     zonefile: /var/dns/zones/alpha.dnslab
     store:    map
     options:  [ allow-updates, allow-api-updates ]
     updatepolicy:
        zone:
           type:     selfsub
           rrtypes:  [ A, AAAA, MX, TXT, CDS, CSYNC ]
```

`allow-updates` without an `updatepolicy.zone.type` of `self` or
`selfsub` does nothing: an unset or `none` policy forces the
option off, and the server says so at startup rather than
starting a zone that looks open and refuses everything.

`allow-api-updates` needs no policy — there is none on that
channel.

Both require a zone that **originates its own content**. A
secondary's content belongs to its primary; the updater refuses
to mutate one regardless of options.


## 3. The five statements

| Statement | Addresses | RFC 2136 form |
|---|---|---|
| `addrr` | one or more records | add (CLASS=IN) |
| `delrr` | one or more records | delete RR (§2.5.4, CLASS=NONE) |
| `delrrset` | one owner + type | delete RRset (§2.5.2, CLASS=ANY) |
| `delname` | one owner | delete all RRsets (§2.5.3, CLASS=ANY TYPE=ANY) |
| `replacerrset` | one or more records | delete RRset + add, atomically |

A few behaviours worth knowing before you rely on them:

**`delrr` ignores the TTL.** A record's identity is owner, type
and rdata; the TTL is not part of it. You do not have to know the
TTL of the record you are deleting.

**`delname` at the apex retains the zone-management RRsets.**
SOA and NS because RFC 2136 §3.4.2.3 requires it, and DNSKEY,
CDS, CDNSKEY and CSYNC because "delete everything at this name"
is a wholesale statement and nobody issuing it means "and also
dismantle DNSSEC and stop every rollover signal mid-flight".
Deleting the apex DNSKEY of a zone whose DS is published does not
make the zone insecure — it makes it **bogus**, and resolvers
stop answering for the whole zone. This is a deliberate deviation
from a strict reading of the RFC, in the conservative direction:
it deletes less than the RFC permits, never more. An operator who
genuinely means it can still say `delrrset --type DNSKEY`.

**`replacerrset` is atomic, not a delete followed by an add.**
The RRset to replace is inferred from the supplied records, so
they must all share one owner and type; mixed input is refused
rather than guessed at. Both halves travel in one action list,
applied in a single pass and published once, so the empty
intermediate RRset is never visible to a reader and never reaches
a secondary as its own serial.

It works on the apex NS RRset — moving to a new set of
nameservers is exactly what it is for. It refuses the apex SOA:
the serial is the server's to maintain.

`replacerrset` with no records is an error, not a silent
`delrrset`. Say `delrrset` when you mean it.


## 4. The CLI

```bash
tdns-cli auth zone update <statement> --zone <zone> --via <api|ddns> [flags]
```

`--via` is **required and has no default**. The two channels do
not have the same authorization model (§1), and defaulting to
either one would let an operator get a different model than the
one they thought they asked for by omitting a flag.

```bash
# Add two records
tdns-cli auth zone update addrr --zone alpha.dnslab. --via api \
    --rr "foo.alpha.dnslab. 3600 IN A 1.2.3.4" \
    --rr "foo.alpha.dnslab. 3600 IN A 2.3.4.5"

# Delete one specific record (TTL ignored)
tdns-cli auth zone update delrr --zone alpha.dnslab. --via api \
    --rr "foo.alpha.dnslab. IN A 1.2.3.4"

# Delete a whole RRset
tdns-cli auth zone update delrrset --zone alpha.dnslab. --via api \
    --name foo.alpha.dnslab. --type A

# Delete every RRset at a name
tdns-cli auth zone update delname --zone alpha.dnslab. --via api \
    --name foo.alpha.dnslab.

# Replace an RRset atomically
tdns-cli auth zone update replacerrset --zone alpha.dnslab. --via api \
    --rr "foo.alpha.dnslab. 3600 IN A 9.9.9.9"
```

The same statements over DDNS, which additionally take the SIG(0)
signer and the server to send to:

```bash
tdns-cli auth zone update addrr --zone alpha.dnslab. --via ddns \
    --rr "foo.alpha.dnslab. 3600 IN A 1.2.3.4" \
    --signer alpha.dnslab. --server 127.0.0.1:5301
```

On the API path the CLI ships the *statement*, not pre-built
update records: the server runs the same builder the DDNS path
runs locally, so validation happens where it is authoritative
rather than being trusted from the client. The CLI still runs the
builder first, so an obvious input error fails before a round
trip.


## 5. What "applied" means

Both channels answer only after the change has been applied,
persisted and published. RFC 2136 §3.4.2.5 is explicit that a
NOERROR response means the update **has been made**; answering as
soon as the request was queued would make that a statement of
intent rather than of fact, and the client would have no way to
find out later which it had been told.

So:

- **DDNS:** NOERROR means applied and durable. A failure or a
  timeout in the updater is answered SERVFAIL with an EDE
  (`EDEZoneUpdateNotApplied`, `EDEZoneUpdateApplyTimeout`) — never
  NOERROR, because on a timeout the server no longer knows.
- **API:** success means the same. An apply that fails or times
  out is reported as an error, and the message says plainly
  whether the change may still land.

`UpdateApplyTimeout` is 10 seconds. It covers a database write
and, on a signed zone, re-signing the affected RRsets.


## 6. Durability: the zone file, and the delta journal

The **zone file remains the source of truth.** Neither channel
turns the database into the authority for zone content.

What happens to a change after it is applied depends on the zone:

- **API-managed primaries** (created through the API, carrying
  `api-managed-zone`) are written back to their zone file
  immediately after every update, internal ones included. Without
  that, content created through the API would live only in RAM
  until a freeze and be lost on restart.
- **Every zone** additionally has its changes recorded as
  **deltas** in the database at publish time, and replayed over
  the zone file on load. Boot is therefore "parse the file, then
  replay the deltas": the file plus the journal is the current
  state, and a restart loses nothing.

The delta journal is not a second copy of the zone. It stores
only differences, and only until they reach the file — a
`write-zone`, `freeze` or `sync` folds them in and drops them.

Two properties worth knowing:

**RRSIGs are not journalled.** A stored signature has a fixed
inception and expiration; replaying it after a long outage would
republish a signature that expired while the server was down, and
the longer the outage the more certain that becomes. The applier
re-signs on replay instead, which is correct regardless of the
gap. The consequence: replay needs a zone that can sign
(`online-signing` or `inline-signing`).

**Replay is chain-validated.** The first delta must start from
the serial the zone file actually has, and every delta after it
must continue where the previous one ended. If the chain does not
start at the file — someone edited it behind the server's back,
say — the deltas are refused rather than applied to a base they
were not computed against, and the zone serves the file as it
stands. The refusal is logged and recorded in the zone's error
registry; it is not silent. `zone journal status` (§8) answers
the same question on demand, before a restart rather than after.

A refused journal does not block updates. A change that lands
afterwards is journalled from where the zone now is; what it
cannot do is rescue the refused deltas, which stay in the
database until you deal with them deliberately.


## 7. freeze, thaw and sync

```bash
tdns-cli auth zone freeze --zone alpha.dnslab.    # write out, stop accepting updates
tdns-cli auth zone thaw   --zone alpha.dnslab.    # resume accepting updates
tdns-cli auth zone sync   --zone alpha.dnslab.    # write out, keep accepting updates
tdns-cli auth zone write  --zone alpha.dnslab.    # the same operation, other name
```

`freeze` makes the zone file the authority right now: it writes
pending changes out and then refuses updates on **both** channels
until thawed. Accepting changes while frozen would silently
strand them the next time the file was read.

`sync` is `freeze` without the freezing — the same write-out, but
the zone keeps accepting updates. It is the one to use when you simply
want the file brought up to date.

`sync` and `write` are two names for one implementation, not two code
paths that can drift: the server dispatches both to the same handler.
The name `sync` exists because it is what an operator coming from bind9
(`rndc sync`) reaches for.

All three drop the zone's deltas once the file is written — but
only those the written file actually contains, judged by its
serial. A change published *during* the write is a serial ahead
of the file, so its delta stays in the journal and replays
normally.

The write itself is staged and renamed into place, so a reader —
the next startup, above all — never sees a partially written zone
file. If any part of it fails, the deltas are **not** dropped:
the journal is the only other copy of those changes, and a write
that half-succeeded is exactly when you still need it.


## 8. Working with the journal

```bash
tdns-cli auth zone journal status   --zone alpha.dnslab.
tdns-cli auth zone journal list     --zone alpha.dnslab. [--instructions] [--out FILE]
tdns-cli auth zone journal truncate --zone alpha.dnslab. --serial <n>
tdns-cli auth zone journal purge    --zone alpha.dnslab. [--force] [--out FILE]
```

### status

The one to reach for first. It answers *will this journal
survive a restart?* — using the same chain check the load path
runs, so the answer cannot differ from what actually happens.

```
Zone dnslab. journal:
  deltas:        2 (10 records)
  chain:         2026081701 -> 2026081708
  zone file:     /var/dns/zones/dnslab (serial 2026081701)
  serving:       2026081711
  will replay:   yes
```

Two lines are worth reading carefully. **`chain`** must start at
the zone file's serial; when it does not, `will replay` says `NO`
and a `why not` line gives the reason. And the head of the chain
sitting behind `serving` is normal, not a symptom: a serial that
advances without a content change — re-signing, a bump — records
no delta, so the journal only marks serials where something
actually changed.

`applied now: NO` is the line that matters most when it appears.
It means the deltas are in the database but *not* in what the
zone is currently answering with.

### list

The deltas and the records in them. `--instructions` prints the
whole journal in the ADD/DEL form of §9 instead of a summary, so
"what is in the journal that my file does not have" and "give me
that as something I can replay" are one flag apart. `--out`
writes it to a file.

### truncate

Keeps the chain through the delta ending at `--serial` and drops
everything after it.

Only a *suffix* can go, and that is not an arbitrary restriction.
The journal is a chain — each delta continues where the previous
one ended — and replay refuses a chain with a gap, so removing a
delta from the middle would leave a journal that can never be
replayed again. There is deliberately no "delete this one
record": to undo a single record, append a correction with an
ordinary `zone update`. The serial must name a real boundary in
the chain; anything else is refused rather than guessed at.

### purge

Discards the whole journal — the equivalent of deleting a bind9
`.jnl`, without the part that makes deleting a `.jnl` painful.

Everything discarded is first written to
`{zonefile}.{serial}.purged` as replayable instructions, and the
purge fails if that cannot be written. So a purge issued in error
is recoverable: the material is on disk, in the form §9 accepts.

A journal that *would* replay holds changes that exist nowhere
else, so purging one requires `--force`, and the refusal points
at `zone sync` — which folds the same changes into the zone file
and loses nothing. A journal that would *not* replay needs no
flag: its changes are already absent from what the zone serves,
and an obstacle in front of the only remedy helps nobody.

If an update publishes while the purge is running, its delta is
kept rather than deleted — it is not in the artefact, so
discarding it would destroy something saved nowhere at all — and
purge says so. That surviving delta no longer chains from the
file, so follow it with `zone sync` or a second purge.


## 9. Replaying an instruction file

```bash
tdns-cli auth zone update from-file --file <path> --zone <zone> --via <api|ddns>
```

The format is a list of operations rather than a zone:

```
; tdns journal contents for dnslab.
ADD	ns2.romeo.dnslab.	3600	IN	A	172.16.91.18
DEL	ns.romeo.dnslab.	3600	IN	A	172.16.91.17
```

It is what `journal purge` and `journal list --instructions`
produce, and the point is not bulk update — it is **selective
override**. Open what the server wrote, delete the lines you
agree with, keep the ones you do not, and replay what is left.

Accordingly:

- comments (`;` or `#`) and blank lines are ignored, so you can
  annotate as you go. Only a *leading* `;` starts a comment — a
  semicolon inside quoted rdata is part of the record;
- parse errors name the line, not the file:
  `line 4: cannot parse "bogus record here": dns: not a TTL`;
- everything that survives your editing is applied as **one**
  update. There is no half-applied outcome.

It is not a separate authorization path. `--via` means exactly
what it means everywhere else in this document, and the records
go through the same builder, the same admission checks and the
same applier as a typed statement.


## 10. Refusals and what they mean

| Message | Cause |
|---|---|
| `does not allow updates via the management API` | zone lacks `allow-api-updates` |
| `zone is frozen; thaw it before updating` | frozen; applies to both channels |
| `may not originate content` | a secondary — its content belongs to its primary |
| `refusing to delete the apex SOA/NS RRset` | `delrrset` on an RRset the zone cannot be served without |
| `refusing to replace the apex SOA` | the serial is the server's |
| `all RRs must share one owner`/`one type` | `replacerrset` given a mixed set |
| `requires at least one RR` | `replacerrset` with none — use `delrrset` |
| `outside the zone` | an owner name not in bailiwick |

On the DDNS path a policy refusal is REFUSED with an EDE naming
the reason: `EDEZoneUpdateRRtypeNotAllowed` (the type is not in
`updatepolicy.zone.rrtypes`), `EDEZoneUpdateOwnerOutsidePolicy`
(the owner is outside the signer's `self`/`selfsub` tree), or
`EDEZoneUpdatesNotAllowed`.
