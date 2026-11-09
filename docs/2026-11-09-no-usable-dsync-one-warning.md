# A parent with no usable DSYNC: one warning, not an error

2026-11-09. Refs johanix/tdns-mp#391 johanix/tdns-mp#392.

## The ruling

Johan, 2026-11-09:

- Parent sync is wanted wherever the parent announces, through DSYNC, a
  scheme the child can use.
- A parent that publishes no usable DSYNC is still the overwhelmingly common
  case. The child logs a warning and moves on: no ERROR, no flood.

## What tdns did

### A delegation sync

`SyncZoneDelegation` builds the parent sync plan. When the plan had no
candidate it logged WARN ("no usable sync scheme") and returned an error.
Every caller then logged that error at ERROR, on every attempt:

- the SYNC-DELEGATION arm;
- `runExplicitSync`;
- tdns-mp's syncher.

The REFRESH-SYNC-DELEGATION arm went further. It took the error as a failed
send and retried on the proxy's schedule, with an ERROR per retry.

### The SIG(0) bootstrap

`bootstrapSig0KeyWithParent` looks up the parent's UPDATE target with
`LookupDSYNCTarget`. A parent without one failed that lookup, and the setup
logged two ERRORs:

- `finishDelegationSyncSetup`'s "error from BootstrapSig0KeyWithParent";
- the setup arm's "error from DelegationSyncSetup".

tdns-mp's auditor runs tdns's syncher for its identity zone. Its rig run
showed this as the sweep's class L6. The agent showed the same through
tdns-mp's syncher (classes K1 and K3).

## The change

### The sentinel and the notice

**`ErrNoUsableDsync`** marks a sync or a bootstrap that was not attempted
because the parent offers nothing this child can use. The DSYNC discovery
itself answered; a failed discovery is a different error. The sentinel is
made in two places:

- **`planUsable`** (`delsync_no_dsync.go`), from `SyncZoneDelegation`. It
  applies to a plan with no candidate after a discovery that answered. The
  plan's new `discovered` field tells this apart from a plan that could not
  ask (no IMR), which keeps its old WARN and plain error.
- **`LookupDSYNCTarget`**, when the parent publishes no target of the scheme
  and type asked for. The message keeps its text, now naming the parent, and
  wraps the sentinel. Callers that do not look for the sentinel behave as
  before.

**The notice is kept per zone name**, in two books: no usable scheme, and no
UPDATE target. A reload, which replaces the ZoneData, does not warn again.

| What | Level |
|---|---|
| The first time, or a new parent | WARN, naming the parent and what was found (the plan's summary, or the lookup's text) |
| The same again | DEBUG |
| A usable plan, or a bootstrap the parent took, after the warning | INFO, once; the note is cleared |

### Where the sentinel is taken as the common case

| Caller | What it does now |
|---|---|
| The SYNC-DELEGATION arm | DEBUG, nothing more |
| `runExplicitSync` | DEBUG. The answer carries the reason in `Msg`, with no error |
| The REFRESH-SYNC-DELEGATION arm | DEBUG, no retry. The next NS or glue change, or a reload, looks again |
| `finishDelegationSyncSetup` | The bootstrap's warning. The setup is done, with no error, so the setup arm neither retries nor logs |

A failure where a usable scheme exists is reported as before: the parent
refuses or fails the UPDATE, the API call fails, or a send times out. These
fall to the walk of the plan, or to the bootstrap's outcome, and are logged
at ERROR and retried where they were.

### What is not covered

- tdns keeps no periodic look at such a parent. A tdns-auth child looks
  again at its next NS or glue change, its next DS change, or a reload.
- tdns-mp's agent adds its own hourly look (tdns-mp, `parent_offer.go`).
- The KSK rollover's DS push reads the plan for itself and reports to the
  rollover engine. It is unchanged.

## Tests (`delsync_no_dsync_test.go`)

| Test | What it shows |
|---|---|
| `TestANoUsableDsyncPlanIsOneWarning` | Four unusable plans give one WARN naming the parent and what was found, then DEBUG. A usable plan gives INFO once. A new parent gives a new WARN. A plan with no discovery is not the sentinel. No ERROR |
| `TestLookupDSYNCTargetWithoutATargetIsErrNoUsableDsync` | Against a resolver that answers from its cache: no DSYNC, or NOTIFY only when UPDATE is asked for, gives the sentinel. A NOTIFY target that exists is found |
| `TestRefreshSyncToAParentWithNoDsyncIsOneWarning` | The REFRESH-SYNC-DELEGATION arm with its real steps: the analysis against a fake parent, the sync against the cache-only resolver. Three syncs give one WARN, no ERROR and no retry |
| `TestRefreshSyncFailureOnAUsableSchemeIsStillAnError` | The same child with a parent that offers UPDATE and answers NOTAUTH: ERROR, one retry, and no "offers nothing" notice |
| `TestASetupWithNoUpdateTargetIsOneWarning` | `bootstrapSig0KeyWithParent` against the cache-only resolver returns the sentinel, and `finishDelegationSyncSetup` turns it into one WARN and nil over three setups. An accepted bootstrap after that gives INFO once; a refused one is still an error at ERROR |

The lookup, refresh-arm and setup tests that expect the quiet case fail
without the change to `delegation_sync.go`, `delsync_refresh.go` and
`dsync_lookup.go`. The failure test passes either way: it guards behaviour
that stays the same.
