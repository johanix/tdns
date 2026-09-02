# D-6 remainder: `at-ns` publishes the child's KEY at the `_signal` name

**Written 2026-09-02.** Closes item D-6 of
`docs/2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md` and folds
in carry-overs 1, 2 and 9 from the #471 reviews, as the handover
`handovers/2026-09-02-ddns-keystate-alignment-remainder.md` asked. Branch
`feature/ddns-keystate-d6-at-ns-signal`, stacked on the D-7 branch (#472).

## What was actually missing

Less than the handover thought. tdns already had a producer for the RFC 9615
signal names: `signal_republish.go` republishes a customer zone's apex KEY /
CDS at `_sig0key.<child>._signal.<ns>` / `_dsboot.…` into whichever *local
primary* zone owns that name, driven by the child's apex HSYNCPARAM
`pubkey`/`pubcds` flag, as an `OnZonePostRefresh` hook on every tdns-auth
secondary. That is the draft's model: the nameserver's operator publishes the
signal record, the child signals intent. The gap was only the tdns-auth
**child** path: when the bootstrap ceremony selected `at-ns`, nothing put the
KEY at the signal name, so `at-ns` could never succeed against a parent that
verifies via `LookupChildKeyAtSignal`.

So the change reuses that publisher rather than adding a second one.

## What landed

- **One publisher, source-injectable.** `republishOneFlag` now delegates to
  `publishAtSignalNames(what, prefix, rrtypes, srcRRs, nsNames, onlyExisting)`.
  Same target selection (`FindZone` → local `Primary` only), same change
  gate, same delete-RRset+add update shape. `signalOwnerName(prefix, child,
  ns)` is the one spelling of the name; `LookupChildKeyAtSignal` (parent,
  KEY) and `queryCDSAtSignalingNames` (scanner, CDS) now use it too instead of
  three hand-rolled `fmt.Sprintf`s.
- **`at-ns` selected → KEY published at `_signal`** (`bootstrapSig0KeyWithParent`,
  before the self-signed UPDATE is sent, so the parent's verification finds
  it). The source is the **keystore** KEY, not the apex RRset: the apex
  publication is itself an asynchronous zone update and may not have landed.
- **`at-ns` offered only where satisfiable.** `zoneChildBootstrapMethods`
  drops it unless `canPublishSig0KeyAtSignal()`: at least one apex NS whose
  signal name falls in a zone this server is primary for. A proxy never can
  (the `_signal` name is in the nameserver's zone), so it stays filtered on
  every path including BADKEY recovery — carry-over 1 was already fixed on
  `main` (`BootstrapSig0KeyWithParent` → `zoneChildBootstrapMethods`);
  confirmed, not re-done. When `at-ns` is configured but dropped, one Info
  line says why.
- **Omit-default restored to `[at-apex, at-ns]`** (carry-over 2), in the
  same change as the publication, as the handover required. The samples say
  so. Because of the satisfiability filter, a zone that cannot use `at-ns`
  pays nothing for it being in the default.
- **Rollover refresh.** After `RolloverSig0KeyWithParent` publishes the new
  KEY at the apex it also refreshes every `_sig0key` signal name a bootstrap
  once populated (`onlyExisting`), so a parent re-verifying via `at-ns` does
  not find the retired key. Signal names never populated are left alone.
- **Carry-over 9, failed SVCB lookup ≠ absent.** Checked first, as the
  handover insisted: the IMR reports NXDOMAIN and NODATA as a non-error
  response with no RRset and sets `resp.Error` only for resolver failures, so
  the polarity is safe. `advertisedBootstrapMethods` now returns a third
  value; `classifyAdvertisementLookup` maps transport error / nil response /
  `resp.Error` to `errBootstrapAdvertisementLookup` and an empty answer to
  "nothing published". A lookup failure is **retryable, never a verdict**:
  `ParentSyncAfterKeyPublication` retries the bootstrap on it with the same
  backoff instead of treating it as terminal, and `sendUpdateWithRetry`'s
  BADKEY arm leaves its one re-bootstrap unspent and tries again on the next
  attempt. `BootstrapWithParent` wraps with `%w` so the sentinel survives.

## Decisions worth recording

- **Publish for every NS this server can publish for, not only
  out-of-bailiwick ones.** The scanner's CDS consumer skips in-bailiwick NS
  (RFC 9615's model), but the existing KEY publisher does not and the parent's
  `LookupChildKeyAtSignal` queries every NS and takes the union. An
  in-bailiwick signal name in a signed child zone validates fine; in an
  unsigned one it is merely useless, which is the draft's own example. Kept
  the publisher's behaviour.
- **No HSYNCPARAM `pubkey` gate on the bootstrap-driven publish.** The flag
  is the child's instruction to *someone else's* nameserver operator. When
  tdns-auth is both the child and that operator, selecting `at-ns` is the
  intent. The transfer-driven republish stays gated on the flag as before.
- **Failure means retry, not fallback.** Falling back to the configured list
  on a transient failure was the bug (a manual-only parent would receive a
  KEY UPDATE it never advertised accepting). Making it terminal would have
  been worse than the bug, given the callers' retry structure, so the callers
  were taught to retry it instead.

## After the external review (same day)

- **Publication is confirmed, not enqueued (T1).** `publishSignalRRs` was
  fire-and-forget: it put a ZONE-UPDATE on the queue and returned, and the
  bootstrap counted that as "published" and sent the ceremony at once. The
  parent's first verification attempt is immediate and the IMR caches a
  negative answer for its TTL, so an early miss could burn the parent's whole
  verification budget. With a context, `publishAtSignalNames` now attaches
  `UpdateRequest.Resp` and waits for the updater's verdict, the same promise
  the DSYNC API handler makes its clients; only an applied update counts, and
  a refused apply or a timed-out wait makes the `at-ns` bootstrap fail rather
  than send a ceremony the parent cannot verify. The transfer-driven
  republish (a post-refresh hook) keeps fire-and-forget with a nil context.
  A fruitless publish or refresh is now logged at Warn (T4).
- **The zone-load setup retries a failed advertisement lookup (T2).** The
  retry for `errBootstrapAdvertisementLookup` was wired into the KeyState
  poller and the BADKEY arm; the path that runs at zone load,
  `DELEGATION-SYNC-SETUP` in the delegation syncher, logged the error and
  dropped it, leaving the zone loaded and never bootstrapped until a reload.
  It now re-enqueues the setup with the delegation-sync backoff (5, 10, 20,
  40 s) and an attempt count on the request, off the syncher goroutine, and
  gives up after the same five attempts the poller allows.
- **Known limitation, `at-ns` satisfiability is a snapshot (T3).** Whether a
  signal name is publishable is judged when the ceremony runs. If the
  nameserver's zone is loaded as a local primary *after* the child's setup,
  `at-ns` is dropped for that run; a reload or `tdns-cli ... bootstrap`
  recovers. Load nameserver zones first, and know this for the
  `at-ns`-only integration run.

## Not done

- Nothing has run on a live testbed. Plan §8's integration items still
  cover this: an `at-ns`-only parent against a tdns-auth child whose NS is
  in-bailiwick is the scenario to run first.
- Re-offering `at-ns` when a nameserver zone appears after the child's setup
  (T3 above).
- `unpublish` of signal KEYs when delegation sync is turned off for a zone.
  `UnpublishKeyRRs` (apex) has no callers today either; both belong to
  whatever eventually owns "stop syncing this zone".

## Tests

`signal_republish_test.go`: the shared name helper; at-ns publication
(keystore key, in-bailiwick NS satisfied, foreign NS skipped, delete+add
shape); rollover refresh touches populated names only; satisfiability for
local-primary / not-served / local-secondary. `child_bootstrap_test.go`: the
willing-list filter per (proxy, canSignal); `zoneChildBootstrapMethods` on
real zones with and without a local signal target; lookup classification for
every IMR outcome. `delsync_retry_test.go`: a deferred re-bootstrap retries
and is bounded. `delegation_policy_test.go`: the restored default.
