# Bootstrapping parent-zone delegation data, with two publication mechanisms

**Date:** 2026-08-26
**Context:** labstuff#392. tdns-auth as parent-zone owner is an **option**, not
a migration: `services.zonemgr.parentupdater.mechanism` selects `bind9-file` or
`tdns-api`, per parent. Anything done here must work on both.
**Question:** what replaces `axfr-cli course init`'s seeding of the delegation
data, given that under `tdns-api` statusd is no longer the source of truth?

---

## 1. The shape of the answer

The per-course delegation template exists because **statusd had to hold the
complete delegation set** to be the source of truth. Under `tdns-api` that
requirement disappears: it is enough that the data is in the zone file *or* in
tdns's persisted journal — which is also just a database table, differing from
`CurrentChildData` only in who owns it.

So nothing about the *material* changes. The templates keep their `ZONE:` block
format, `/etc/domain/master` is untouched, and `course init` keeps copying
templates as it does. **The only thing that forks is where the delegation data
is installed**, and that fork belongs exactly where the publication fork
already lives.

## 2. Verified current flow

Traced 2026-08-26, because the approval gate must not be disturbed.

```
student web form ──"request"──► API "add-pending"        (axfrapiserver.go:237)
                                  └─► AddToPendingChildData
                                      PendingChildData          ── no publish ──

trainer ──"commit"/"reject"──► API "commit"               (axfrapiserver.go:229)
                                  └─► CommitPendingChildDataNG  (db_rrfuncs.go:335)
                                      ├─► REPLACE INTO CurrentChildData  (:472)
                                      └─► ZmgrReqC <- {Cmd: RELOAD, ...}

zonemgr ──► ReloadAuthZones                               (zonemgr.go:295-)
              └─► ParentBackendFor(parent).Publish(...)   (:317-326)
                    reads CurrentChildData only
```

Three facts that matter:

1. **`add-pending` publishes nothing.** It calls `AddToPendingChildData` and
   returns. There is no path from a pending row to a parent zone.
2. **`CommitPendingChildDataNG` is the sole writer of `CurrentChildData`** —
   one `REPLACE INTO`, in one function.
3. **Publication reads `CurrentChildData` and nothing else**, from the single
   call site in `ReloadAuthZones`.

So the gate is structural, not conventional: *nothing reaches a parent zone
that has not been through commit*. Under `tdns-api` the publish **target**
changes; the gate does not move, because `Publish` is downstream of
`CurrentChildData` and `CurrentChildData` has exactly one writer.

**The invariant to write down and not break:** the tdns push stays downstream
of `CurrentChildData`. Wiring it to `add-pending` — which would look like a
harmless shortcut, since under `tdns-api` the `Current` phase is otherwise
uninteresting — would propagate unreviewed student requests straight into the
published zone. Student requests are frequently wrong; that is the point of the
lab.

One nuance worth stating so it is not mistaken for a hole: the **CDS and CSYNC
scanners call `CommitPendingChildDataNG` directly** (`scanner_cds.go:99,135`,
`scanner_csync.go:212`) under `services.scanner.cdscommit: immediate`. Those
changes are auto-committed by design — they are machine-verified, not
human-typed. The trainer gate governs *web-form requests*; it was never
intended to govern the scanners.

## 3. Where the fork goes

`ParentBackend` is currently:

```go
type ParentBackend interface {
    Publish(parent string, changedChildren map[string]bool) error
    Mechanism() string
}
```

Bootstrap is a second method on it — `InstallDelegations(parent, []ZoneRR)`,
meaning *make the parent's delegation set be exactly this*:

- **`bind9-file`** — what happens today: replace the parent's rows, render the
  fragment, reload.
- **`tdns-api`** — one atomic update over the management API, landing in tdns's
  journal. `tdns-cli ... zone update from-file --via api` is the existing
  primitive and applies its whole instruction list "as ONE update — there is no
  half-applied outcome".

The mechanism is already known at the point the data lands: the `add-pending`
and `commit` handlers are statusd API handlers holding `ldb` and viper config,
so `parentMechanismFor` is in reach without moving anything.

**Bootstrap should be its own verb, not `add-pending` + `commit`.** Pending →
commit is the *approval* workflow; course material is not a request and has
nobody to approve it. Reusing it under `tdns-api` would mean populating pending
rows solely to have something to commit, or making commit a no-op for those
parents. A distinct `install-delegations` that dispatches on mechanism says what
it means, leaves the approval path alone, and gives `--keep-delegations` one
clear meaning on both sides: skip the install.

## 4. The `$INCLUDE` question: neither option is needed

The static originals carry `$INCLUDE /var/dns/zones/<zone>..delegations` and
`..child-ds`, and the instinct is that the copy at `/var/dns/zones/<zone>` will
carry them too — so either the copy must be edited or the fragments must be
kept alive as empty stubs. Neither, because **the destination is not a copy**.
`ReloadAuthZones` assembles it:

```
CommitParentDataFile(z, "ds")    -> /var/dns/zones/<z>..child-ds
CommitParentDataFile(z, "del")   -> /var/dns/zones/<z>..delegations
zd.ReadZoneFile(/etc/domain/master/<z>)   <- the $INCLUDEs are resolved HERE
zd.UpdateSerial(); zd.Sync(); zd.Digest()
zd.WriteZoneFile(/var/dns/zones/<z>)      <- flat, complete, no $INCLUDE
```

Hence the `*MUST* ensure that the ..delegations and ..child-ds files are in
place first` comment above it: they are inputs to a flattening step. The
written zone is self-contained.

**tdns never reads the fragments.** They are statusd-internal build material,
so there is no stale-fragment hazard and nothing to stub out. The `$INCLUDE`
mechanism is invisible to tdns in both mechanisms, and no file under
`/etc/domain/master` needs touching.

What is left is one ordering fact, and it is the whole of the bootstrap
question: **whatever `CurrentChildData` holds at the moment of the one-time
generation is what gets baked into the zone tdns then loads.** Empty at that
moment gives a static-only zone, which is what route B below wants.

Two smaller consequences of reading this path:

- **`zd.Digest()` runs over the zone as read from source**, i.e. unsigned —
  the ordering bug in labstuff#135. Under `tdns-api` it should simply be off
  for those zones (`services.zonemgr.zonemd.active`), because tdns computes and
  publishes ZONEMD inside its own signing path.
- **`removejournal` deletes `<dstfile>.jnl`**, which is BIND9's journal. For a
  `tdns-api` zone no such file exists and tdns's delta journal lives in its
  database, so the removal is already a no-op there — which is the conditional
  #392 asks for, arrived at from the other direction.

## 5. Two bootstrap routes, and which to prefer

**A — through the zone file (zero new code).** Put the delegations in
`CurrentChildData` the way `course init` does today; the one-time generation
bakes them into `/var/dns/zones/<zone>`; tdns loads them at startup.

Works immediately and needs nothing built. But it re-creates the parallel truth
at t=0: statusd's `Current` holds a full copy that starts decaying the moment a
student's agent writes to tdns, and the read-back path (#428/tdns#389) then has
to reconcile against data that was never tdns's.

**B — through the journal (preferred).** Leave `Current` empty for `tdns-api`
parents. The one-time generation produces the static zone with empty fragments;
`InstallDelegations` then pushes the course's delegation set as one atomic
update, which lands in the journal.

statusd's tables are empty for those parents from the first moment, so the UI
has nothing stale to render and #389 read-back is the only thing it ever
believes. Bootstrap uses the same channel every later change uses, so there is
one publication path rather than two. Costs the `InstallDelegations`
implementation on the tdns-api backend.

**Route B is the decision** (2026-08-26), with **A** as the fallback if the course arrives first.

## 6. Where arriving changes are persisted

All arrival routes — management API, and the DSYNC receivers (generalised
NOTIFY, signed DNS UPDATE, child-api) — converge on the same publish path, and
**that path already persists to the database**:

```
ApplyChildUpdateToZoneData        (zone_updater.go:631)
  wsPersistDelta = !ur.Replay
  publishLocked -> publishWorkingSetLocked
                     PersistZoneDelta(zone, fromSerial, toSerial, ...)
                                              (zone_mutation.go:533)
                     -> ZoneDelta rows
```

`ZoneDelta`'s own schema comment states the purpose exactly: *"persists
in-flight content changes for zones whose source of truth is still the zone
FILE ... then the deltas are replayed over it in order. On write-zone / sync
..."*. It is the mechanism for **not** rewriting the file per change. Writes are
gated only by the `journal: active` kill-switch.

For CHILD-UPDATE this is deliberate, not incidental — Phase 2 of the journal
work says so: *"delegation records written by a CHILD-UPDATE are zone content
like any other ... published from here. Without this they would be served but
not recorded, and would silently roll back at the next restart."*

### The one thing in the way

`delegationbackend: direct` is nevertheless correct for route B — it is the only
backend that updates the **served zone**. (`db` writes a `ChildDelegationData`
row and never touches zone data, so the parent would hold the delegation and
never publish it; `zonefile` is `db` plus fragment regeneration and a reload,
which is design (c).)

But `DirectDelegationBackend.ApplyChildUpdate` calls `WriteZone` unconditionally
after every accepted update, and `WriteZone`'s contract is *"the file now
contains everything the zone has"* — it rewrites the whole zone file **and
deletes the journal deltas up to that serial**. So on the child-update path the
journal is folded away as fast as it is written, and the file is rewritten per
change.

Its justification is stale:

> Persist to source zonefile so accumulated child updates survive a restart.
> Without this, every CHILD-UPDATE only mutates RAM, gets lost on next start

That was true before the delta journal. Phase 2 made it untrue, and the two
comments now contradict each other.

### What route B wants

The ZONE-UPDATE path already behaves the desired way: its zone-file write is
**gated**, on `Primary && OptApiManagedZone`, and the code calls it "the mirror
of the CHILD-UPDATE 'direct' backend persist". The asymmetry is that the mirror
has no gate.

So the change is to make the two symmetric — gate `direct`'s write-back the same
way, or drop it and let the journal carry durability as it already does for
every other kind of change. Then:

- changes persist as `ZoneDelta` rows, in the database
- the zone file is rewritten on `zone sync` / `write-zone`, when an operator asks
- `/var/dns/zones/dnslab` stays the one-time bootstrap artefact the
  `os.Stat` guard in `ReloadAuthZones` already assumes it is

**There is no configuration that achieves this today.** `direct` is the right
backend and its write-back is unconditional, so this is a small tdns change
rather than a config choice. It is contained: one call site, and the comment
that justifies it is already wrong.

## 7. Status

**Design settled** (2026-08-26): mechanism-selectable per parent; bootstrap via
route B; `InstallDelegations` as a second `ParentBackend` method, forked inside
statusd where the mechanism is already known; a distinct verb rather than
add-pending/commit; `$INCLUDE` a non-issue; the approval gate intact with the
"push stays downstream of CurrentChildData" invariant recorded;
`delegationbackend: direct`; persistence by journal, folded on demand with
`tdns-cli auth zone sync`.

**One tdns change**, contained to one call site: gate or drop
`DirectDelegationBackend`'s `WriteZone`. Verified safe from both directions —
durability is the journal's (Phase 2 publishes and persists the delta for
CHILD-UPDATE explicitly), and `reloadWouldLoseChanges` already treats
dirty-with-an-active-journal as mergeable rather than refusing the reload. A
sync cadence knob is possible later; an operator running `zone sync` covers it
until then.

**Decisions taken** (2026-08-26):

1. **`--keep-delegations` under `tdns-api`** means no install from templates
   happens at all — the same "leave what is there alone" it means today.
2. **Without it, the existing delegations must be deleted before the course's
   set is installed.** So `InstallDelegations` on `tdns-api` may *not* simply
   assume a fresh zone and ADD: a previous course's delegations are persisted
   in tdns's journal, and possibly folded into the zone file if anyone ran
   `zone sync` during the term.

   The reset does not need tdns#389, because existing machinery covers it:
   remove `/var/dns/zones/<zone>`, purge the journal, and let
   `ReloadAuthZones` regenerate the file from `/etc/domain/master/<zone>` —
   its `os.Stat` guard passes once the file is gone, and with
   `CurrentChildData` empty the regenerated zone is static content only.
   Install then runs against a genuinely clean parent, whatever happened
   during the previous course. Read-back (#389) remains the answer for a
   *mid-course* reinstall, where wiping the zone is not acceptable.
3. **ZONEMD moves with the zone**: `services.zonemgr.zonemd.active` off for
   `tdns-api` parents, `publish-zonemd` on in tdns. This is where labstuff#135
   is actually fixed — tdns digests inside the publish, after signing, which is
   the ordering statusd cannot achieve.
4. **All three parents move together.** `dnslab.`, `10.in-addr.arpa.` and
   `e.f.f.3.ip6.arpa.` are one pedagogical unit.

**Filed:** the `direct` write-back change is **johanix/tdns#397**.

**Adjacent, already tracked:** tdns#389 / labstuff#428 for the UI read-back, and
the config corrections (`delegationbackend: direct`, `allow-api-updates` on the
parent templates).
