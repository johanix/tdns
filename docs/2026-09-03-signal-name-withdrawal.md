# Withdrawing records published at the RFC 9615 `_signal` names

**Written 2026-09-03.** Design and what landed. Branch
`feature/signal-name-withdrawal`. Drafted on top of
`feature/use-hsyncparam-option` because case 1 below is about that branch's
`use-hsyncparam` option; PR #489 merged while this was being written, so the
branch is now off `main` and carries `origin/main` merged forward.

`v2/signal_republish.go` publishes a customer zone's apex `KEY` / `CDS`+`CDNSKEY`
at `_sig0key.<child>._signal.<ns>` and `_dsboot.<child>._signal.<ns>` into
whichever local zone this server holds as primary. Nothing has ever withdrawn
them. The gap predates PR #489 -- D-6 (PR #473) recorded it under "Not done" --
and #489 made it visible: an operator who removes `use-hsyncparam` reasonably
expects the records to go away, and they do not. It is written down as a known
gap in `guide/config-tdns-auth.md`, `SUPPORTED-RFCs.md` and
`docs/2026-09-03-use-hsyncparam-option.md` §6, and an external review raised it
as finding A2.

## 1. The four shapes of the gap

| # | The change | Visible as | What should go |
|---|------------|-----------|----------------|
| 1 | `use-hsyncparam` removed from a zone's options | a config edit | every `hsyncparam`-sourced record for that zone |
| 2 | `pubkey` / `pubcds` dropped from the customer's apex HSYNCPARAM | an incoming transfer | that flag's records for that zone |
| 3a | an NS removed from the customer's apex NS RRset | an incoming transfer | that nameserver's signal names |
| 3b | the customer zone removed from this server | a config edit, or an API delete | everything published for that zone |
| 4 | `parentsync` turned off for a zone whose `at-ns` bootstrap published a `_sig0key` | a config edit | that zone's `at-ns` records |

A fifth falls out of the same rule and is handled with them: a flag that stays
set while the apex RRset it mirrors is emptied. The republisher warns and
publishes nothing, and what is already at the signal name would go on
advertising, to a parent verifying via `at-ns`, a key the child no longer
publishes.

Cases 2 and 3a are content changes and the existing post-refresh hook already
runs on them. Cases 1, 3b and 4 are configuration changes with no event of their
own -- and, in every one of them, the config may equally have been edited while
the daemon was stopped, in which case there is no transition to observe at all,
only a state that no longer justifies the records.

## 2. The authority to delete

The publish path already has the mechanism: a delete-RRset (ClassANY) plus adds,
as one `ZONE-UPDATE` on `KeyDB.UpdateQ`. Deleting needs only the first half. The
question is not *how* but *whether we may*.

The target is an ordinary primary zone of this server's. An operator may have put
records at a signal name by hand -- the guide describes `_signal` names as
something a nameserver operator publishes, so a hand-maintained one is a
supported thing to have. Two candidate rules were considered and rejected:

- **Delete anything signal-shaped that we do not currently want.** This deletes
  an operator's hand-published record for a child we happen not to serve. It is
  the rule that cannot be made safe, because the zone data carries no provenance.
- **Delete only if the content still matches what we would publish.** Content is
  not provenance -- it can coincide -- and it fails exactly when the record is
  most stale, because a key rollover is what changes the content in the first
  place.

So: **track what we published, and delete only that.** The ledger is the
authority; content is never consulted for a deletion.

This is deliberately fail-closed. A lost or rebuilt keystore means tdns will
never withdraw records it published under the old database. Leaving a stale
record behind is the failure this work is closing, but deleting somebody else's
record is worse, and a ledger that has forgotten a publication is
indistinguishable from one that never made it.

### Where the state lives

`SignalPublication`, a new table in `v2/db_schema.go`. A new table needs no
`dbMigrateSchema` entry -- `dbSetupTables` runs `CREATE TABLE IF NOT EXISTS` over
`DefaultTables` at every startup, so an existing database picks it up on the
first run of the new binary.

```
target       VARCHAR(255)  the local primary zone the record was written into
owner        VARCHAR(255)  the signal name
zone         VARCHAR(255)  the zone whose bootstrap data this is
ns           VARCHAR(255)  the nameserver whose zone this is
prefix       VARCHAR(16)   _sig0key | _dsboot
source       VARCHAR(16)   hsyncparam | at-ns
published_at DATETIME
UNIQUE (target, owner)
```

One row per *signal name*, not per RRtype: a publication is one spec applied to
one name, and the spec (`signalSpecs`) is what says `_dsboot` means CDS+CDNSKEY.
`ns` and `zone` are derivable from `owner` by parsing, and are stored anyway so
the queries this needs -- "everything for zone Z" and "everything in target T" --
are column reads rather than string surgery.

`source` records which of the two publishers wrote the row, because case 4 asks
about `at-ns` rows specifically. The two sources cannot collide in practice (the
HSYNCPARAM republisher acts on a zone we are *secondary* for, the `at-ns`
bootstrap on our own), so `source` is a plain column and a re-publish from the
other path overwrites it.

No secondary index. The table holds one row per published signal name -- tens,
plausibly hundreds -- and `UNIQUE (target, owner)` already indexes the
target-side query.

## 3. Where withdrawal is driven from

One reconciler, `ReconcileSignalPublications`, registered as the
`OnZonePostRefresh` callback in place of today's `RepublishAtSignalNames`. It
computes what the zone *should* have published right now and settles the
difference in both directions.

Registration is already type-independent on `main`: 7196ea41 (a CodeRabbit
finding on #489) moved it from `zonetype == Secondary && zdp.FirstZoneLoad` to
`zdp.FirstZoneLoad` for every zone, to close a reload gap without mutating
`OnZonePostRefresh` while a refresh ranges it. This branch needs exactly that
placement for its own reason -- case 4's zone is one this server is *primary*
for -- and changes only the callback's body and the note explaining why a
primary registers the hook. That note needed correcting: with withdrawal in the
callback, a primary carrying `parentsync` does real work here, where
before it was a guarded no-op.

**The post-refresh hook is the trigger for a configuration change too**, which
is the observation that makes this small. A config reload enqueues a forced
refresh for every zone at the end of `ParseZones`, and `force` bypasses both the
untouched-file skip in `FetchFromFile` and the unchanged-serial discard in
`FetchFromUpstream` -- so the callbacks run. A restart does the same on first
load. That means cases 1 and 4 need no config-time machinery and no
before/after comparison: the reconciler reads the *current* option and the
*current* ledger, and a zone whose option went away while the daemon was stopped
is settled on the next load exactly like one edited live. `zd.Options` is
replaced wholesale on reload and the hook reads it when it runs, which is the
same property #489 relies on.

The reconciler runs in two roles, both from the same callback:

- **as the published-for zone** (`zone` column): cases 1, 2, 3a and 4.
- **as the target zone** (`target` column): rows whose published-for zone this
  server neither serves nor is configured for -- case 3b, including a removal
  made while the daemon was stopped, and covering the zone-removal paths not
  hooked below.

  "Not in the registry" is deliberately not the test. A zone can be absent
  because it has not been CONSTRUCTED yet: `LoadDynamicZoneFiles` registers
  dynamic primaries itself but only ENQUEUES dynamic secondaries and catalog
  members, whose `ZoneData` the RefreshEngine builds when it drains the channel
  (#500/#501). A dynamic secondary is exactly the zone shape `use-hsyncparam`
  is for, so sweeping on registry-absence alone would withdraw its records at
  startup and watch the next refresh publish them back. The sweep therefore
  consults a set captured from CONFIGURATION -- every zone named in the static
  config or the dynamic config file -- and a zone named there is never an
  orphan, however absent it currently is. A zone genuinely removed while the
  daemon was stopped is in neither.

  The set is rebuilt whenever the configuration changes: `ReloadZoneConfig` and
  `RemoveDynamicZone`. Without that it would be whatever startup saw, and a
  zone dropped from the config would still count as configured -- so a prompt
  withdrawal that had to defer (§4.3, target not loaded) would never be
  finished by the sweep either, and the rows would wait for a restart.

  Capture and refresh fail in OPPOSITE directions, and the asymmetry is the
  point. Capture runs before the sweep is armed, so a failure means not arming.
  Refresh runs when the sweep may already be live, where storing nothing would
  make every row whose zone is not currently in the registry look like an
  orphan -- turning one unreadable file into a mass withdrawal. So a failed
  refresh keeps the previous set: stale only delays a withdrawal, cleared
  performs the wrong ones.

Plus two prompt paths, so a live removal does not wait for the target's next
refresh: `ReloadZoneConfig`'s "zone no longer in config" sweep and
`RemoveDynamicZone` withdraw everything for the zone they are removing.

And a one-shot sweep at the end of startup, because a target that loaded before
the orphan role was armed would otherwise not be revisited until its own refresh
interval. See §5 for the arming.

### What "warranted" means

For a row with `source = hsyncparam`, all of:

- the zone carries `use-hsyncparam`;
- its apex HSYNCPARAM carries the flag matching the row's prefix;
- the apex RRset that flag mirrors is non-empty -- the fifth case in §1, and
  the reason it belongs here rather than beside the others: it is a condition
  on the warrant, not a separate trigger;
- the row's `ns` is still in the zone's apex NS RRset;
- `FindZone(owner)` still resolves to a zone served here as primary.

For a row with `source = at-ns`, all of:

- the zone carries `parentsync` (`OptDelSyncChild`);
- the row's `ns` is still in the zone's apex NS RRset;
- `FindZone(owner)` still resolves to a zone served here as primary.

The last condition is the one that fails without producing a withdrawal. A
signal name whose zone this server no longer holds as primary drops out of the
warrant, but the withdrawal then refuses: we cannot write to a zone we do not
control, and a demoted zone's content is upstream's. The row is kept, because
it is the only thing that would still authorize withdrawing the record if the
zone is promoted back -- see §4.8.

The reconciler never *creates* an `at-ns` row. Publishing a `_sig0key` for our
own zone is the bootstrap ceremony's decision (`publishSig0KeyAtSignalNames`,
called from `BootstrapSig0KeyWithParent`); the reconciler only retains or
withdraws what that ceremony recorded.

### The guard against a broken load withdrawing everything

The reconciler does nothing at all when the zone is not ready (no published
snapshot) or when its apex NS RRset is empty. Both are states from which "which
nameservers does this zone have" has no answer, and answering "none" would
withdraw every record for the zone. Losing *one* NS from a populated RRset is
case 3a and is acted on; losing all of them is a zone that is not a zone.

These read as two guards and are one: `apexNSNames` reads through
`publishedSnapshot`, so an unloaded zone reaches the second check with an empty
list regardless. The snapshot check earns its place in the LOG rather than in
the decision -- "has not loaded yet" is the normal condition of every zone at
startup and says nothing, while "loaded, and no apex NS" is a broken zone and
warrants a warning. Without it every zone with publications would warn once per
boot.

## 4. Decisions taken

1. **Deletion is ledger-gated; publication is not.** The existing publish and
   update paths stay exactly as they are, content-gated against what is already
   at the name. In particular `refreshSig0KeyAtSignalNames`'s `onlyExisting`
   predicate still asks whether an RRset is *present*, not whether the ledger
   claims it: switching it to the ledger would look tidier but would silently
   stop refreshing names populated by a bootstrap that ran before this table
   existed. The asymmetry is the point -- overwriting a record we are asked to
   maintain is the operator's own configuration at work, deleting one is a claim
   about who owns it.

2. **One reconciler on the post-refresh hook, not four triggers.** A
   reload-time before/after comparison (the `zonemdChanged` pattern in
   `ParseZones`) would handle case 1 and case 4 while the daemon runs and miss
   both when the same edit is made while it is stopped. Reading current state
   against the ledger handles the two identically and is less code.

3. **A row is dropped only when its target zone is ready.** The ZONE-UPDATE is
   fire-and-forget from a post-refresh hook, so there is no verdict to wait for;
   an unready target would report "nothing there" and the row would be forgotten
   with the record still on disk. Rows whose target is not ready are left for the
   next pass.

4. **`Applied == false` is not a failure.** The updater treats a ClassANY delete
   of an absent RRset as a no-op: no serial bump, no re-sign, no error. So a
   withdrawal that finds nothing costs nothing, and the presence check before
   enqueueing exists only to keep the log quiet.

5. **The reload path collects and withdraws off `confMu`.** The withdrawal
   enqueues onto `KeyDB.UpdateQ` with a blocking send, and applying a zone
   update reaches `JournalActive()`, which takes `confMu.RLock`. Withdrawing
   inside `ReloadZoneConfig`'s removal loop -- which holds the write lock --
   would therefore deadlock the daemon outright on a full queue rather than
   merely slow it down. The loop collects the dropped zone names and the
   withdrawals run after the unlock.

6. **The two options are read together under `zd.mu`.** `main` already locks
   the publish half's read (9a0b5b45, another #489 review finding). The
   withdrawal half needs `use-hsyncparam` and `parentsync`
   *coherently*, so both now come from one `signalOptions` helper that
   `RepublishAtSignalNames` reads through as well -- the publish and withdrawal
   halves of one pass then agree about the zone. Upstream's
   `TestRepublishAtSignalNamesOptionReadIsSynchronized` still catches an
   unlocked read through the helper (checked by removing the lock).

7. **A crash between the enqueue and the forget loses the withdrawal.** The
   withdrawal is fire-and-forget from a post-refresh hook -- it has to be,
   since blocking on the zone updater there would stall refreshes -- and the
   row is forgotten straight after the enqueue. A crash in that window leaves
   an RRset with no ledger row, which then never gets withdrawn. This is the
   residual of the fire-and-forget choice, and it fails in the same direction
   as everything else here: a record left standing, never somebody else's
   record deleted. Waiting for the verdict instead would trade a rare stale
   record for a routine stalled refresh.

8. **A row whose target is gone, or no longer primary, is kept.** It looks like
   dead weight -- the zone took its records with it. But if that zone comes
   back, from the same zone file, the signal RRsets come back with it, and the
   row is the only thing that would still authorize withdrawing them. Retrying
   a row we cannot act on costs a registry lookup and a Debug line; forgetting
   one costs the ability to undo a publication. The ledger is bounded by the
   number of signal names ever published, so it can afford to remember.

9. **The empty-ledger flag is maintained under a mutex.** A wrong "false"
   costs one query; a wrong "true" makes every reconciler take the fast path
   and skip withdrawal entirely, with nothing in the log. Counting and storing
   without serialising against inserts allows exactly that -- count zero,
   concurrent insert, store "empty" -- so ledger writes and the flag update
   share `signalLedgerMu`. It guards a path that writes a handful of rows per
   refresh at most.

10. **An "is the ledger empty" flag, not a per-zone cache.** The hook now runs on
   every zone rather than every secondary, and the overwhelmingly common
   deployment has published nothing at any signal name. One atomic load makes
   that case free. A deployment that does use the feature has a handful of rows
   and can afford the query.

## 5. What landed

- `v2/db_schema.go` -- the `SignalPublication` table.
- `v2/db_signal_publication.go` -- the ledger accessors plus the empty-ledger
  fast-path flag, refreshed from the table when the KeyDB is opened.
- `v2/signal_republish.go` -- `ReconcileSignalPublications` and the withdrawal
  half; `publishAtSignalNames` records a row for every publication it makes;
  `RepublishAtSignalNames` keeps its name and its job (the publish half) and is
  now called by the reconciler.
- `v2/zone_hooks.go`, `v2/signal_republish.go` -- `main`'s
  `registerStandardRefreshHooks` (#501) now attaches the reconciler rather than
  the publish half alone, and the hook is renamed
  `registerSignalReconcileHook` for what it registers. Both files' comments
  said registering on a primary "costs nothing but a guarded no-op"; with
  withdrawal in the callback that is false -- a primary carrying `parentsync`
  does real work there -- so the claim is corrected in both places.
- `v2/config.go`, `v2/dynamic_zones.go` -- withdraw everything for a zone being
  removed from the running server; on the reload path, after `confMu` is
  released (§4.5).
- `v2/main_initfuncs.go` -- arm the orphan role and run the one-shot sweep at
  the end of `StartAuth` / `StartAgent`, after `loadDynamicZonesIfConfigured`.
  The timing is not what makes it safe (§3): the configured-zone set is, and
  the sweep stays DISARMED if that set cannot be established -- an unreadable
  dynamic config yields no set rather than a partial one, because a partial set
  would make the sweep confidently wrong about exactly the zones it failed to
  read.
- `v2/signal_withdraw_test.go`, `v2/db_signal_publication_test.go` -- see §6.
  (`v2/signal_republish_test.go` changes by one line, for the new `source`
  parameter.)
- `guide/config-tdns-auth.md`, `SUPPORTED-RFCs.md`,
  `docs/2026-09-02-ddns-keystate-d6-at-ns-signal.md`,
  `docs/2026-09-03-use-hsyncparam-option.md` -- the recorded gap is now a
  recorded behaviour.

## 6. Tests

`v2/signal_withdraw_test.go` carries the cases, each set up so the only thing
missing is the warrant: option removed, flag removed (and HSYNCPARAM removed
outright), apex source RRset emptied, NS removed, zone gone, delegation sync
off. Plus the negatives that carry the design -- a signal RRset with no ledger
row is never touched, an unready target keeps its row rather than losing it, an
unready published-for zone withdraws nothing, a target that is no longer
primary is neither written to nor forgotten, a zone with an empty apex NS RRset
withdraws nothing, and an unknown ledger source is left alone.
`v2/db_signal_publication_test.go` covers the ledger round trip, the
`(target, owner)` uniqueness, the guarded upsert, and the empty-ledger flag.

Every guard is mutation-checked: removing it fails a named test. Two do not
isolate, and the tests say so rather than implying otherwise -- the unready
published-for zone is caught by the empty-apex-NS check as well, and the
"target no longer served here" case by the registry lookup rather than by the
primary check.

## 7. Not done

- Nothing has run on a testbed.
- The crash window in §4.7 and the retained dead rows in §4.8 are accepted
  residuals, not open work. Both are recorded there so a later reader can
  reopen the trade rather than rediscover it.
- A `tdns-cli` view of the ledger. The rows are readable with `sqlite3` and
  there is no operator workflow that needs them yet; when one appears it belongs
  next to the other keystore inspection commands.
