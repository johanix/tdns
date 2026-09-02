# IMR: quarantining a bad forward zone instead of refusing to start

Issue: #475. Follows 2026-08-31-imr-forward-startup-and-status.md, which
removed the husk a dead upstream produced at boot; this removes the one a
*misconfigured* upstream produced.

## 1. The problem

`BuildImrForwards` returned one error for the whole forward table and
`InitImrEngine` turned it into a failure to start, so a single bad forward
zone stopped the resolver — including every other forward zone and the
iterative path, both of which would have worked. The auth side does the
opposite: a zone with a bad ACL, an unknown TSIG key or a missing template
goes to `ERROR` on its own while the server starts and serves everything
else.

## 2. Decisions

**Quarantine, not drop.** A misconfigured upstream stays in the table,
reported, and is never dialled. A zone with no usable upstream left is
quarantined in turn and its names SERVFAIL.

**No fallback to iteration.** A quarantined zone behaves exactly like one
whose upstreams are all down, which is the documented forward-only contract
and something operators already understand. Falling back would silently
change the resolution path, and for a `zone: .` forward it would change it
for everything.

**Drop only what cannot be quarantined.** Quarantine needs a namespace to
apply to. An entry with no usable zone name has none, and a duplicate of an
already-configured zone would only shadow a definition that is already
serving. Both are dropped, loudly; the first definition of a duplicated zone
stands.

**A zone with no upstreams is quarantined, not dropped.** Dropping it would
hand every name under it back to iteration — the one thing a forward-only
zone must never do silently.

**Startup quarantines; reload still refuses whole.** A deliberate asymmetry.
`ReloadZones` has a good running configuration to preserve and rejects any
config that would quarantine anything, changing nothing at all; startup has
no such state and serves what is left. Any build diagnostic maps to a
whole-config refusal on the reload path.

The consequence, stated so it is not discovered: **a leftover quarantine
blocks unrelated reloads.** A daemon that started with `mix.example.` serving
on DoT and its plaintext sibling quarantined is running a config that
`ReloadZones` would refuse. Adding a third, healthy zone by reload therefore
fails until the quarantined upstream is fixed or removed as well — repair
first, then extend, or restart, which accepts both. That is what
"rejects any config that would quarantine anything" costs. It is chosen over
the softer "the same quarantines may stay" rule because that rule needs a
definition of *same* that survives a config rewrite, and the conservative
version is one sentence an operator can hold in their head.

**Quarantine is a config verdict, reachability is a traffic verdict.** They
are disjoint and clear differently: `failing` clears on the next successful
exchange, quarantine only when the table is swapped. A quarantined upstream
is never dialled, so it can never become `failing`, and it is excluded from
the reachability aggregate so the two never report the same upstream twice.

## 3. Where it sits

Per-item state on the objects, one aggregate per class in the server-error
registry — the division of labour 2026-07-21-DONE-server-error-registry-
design.md was written for (§ "Per-instance multiplicity ... is deliberately
*not* a server-registry concern").

- `ForwardUpstream.quarantined` / `quarantineWhy`, under the existing
  `up.mu`. The lock is not decoration: `carryForwardUpstreams` shares one
  upstream object between the outgoing and incoming tables while queries are
  still running on the old one.
- `ForwardZone` stores nothing. `quarantineState()` derives the zone's
  verdict from its upstreams on every call, so it cannot go stale behind a
  reload.
- `liveUpstreams()` is the single filter. Everything that dials, counts or
  probes an upstream goes through it — the query loop, the startup probe,
  `hasEncryptedUpstream` (so the PRIVACY precheck cannot promise a guarantee
  on the strength of an upstream that will never be dialled), and the
  reachability aggregate.
- `Config/ImrForwardZone` and `Config/ImrForwardUpstream` are the two
  aggregates. Separate subtypes because `config status` renders one entry per
  `(Category, Subtype)` and "not serving" must not read like "serving with
  reduced redundancy". `ErrCatConfig`, not `ErrCatUpstream`: the upstream is
  not failing to answer, it was never asked.
- `BuildImrForwards` returns `([]*ForwardZone, []ForwardDiag)`.
  `forwardDiagsError` joins diags into the single error the reload path still
  refuses whole with.

The one non-obvious wiring is in `carryForwardUpstreams`: it swaps the *old*
upstream object into the new table whenever `upstreamKey` matches, and that
key does not include the zone's `TrustAD`. So an upstream quarantined for
trust-ad reasons has an unchanged key after `trust-ad:` is removed, and
carrying it untouched would carry a quarantine the new config no longer
earns — leaving the zone dead after the operator fixed it.
`adoptQuarantineFrom` re-applies the new build's verdict onto the carried
object: reachability carries, the config verdict does not.

## 4. Verification

Unit, in `v2/imr_forward_quarantine_test.go`:
`TestInitImrEngineStartsWithABadForwardZone` (the daemon starts, the bad zone
is in the table and quarantined, the healthy root forward still serves, the
aggregate names the zone), `TestForwardQuarantinedZoneServfailsWithoutDialling`
(SERVFAIL with a nil-Client placeholder upstream, which is what proves nothing
dialled), `TestForwardQuarantineKeepsTheAuthenticatedUpstream` (reduced
redundancy), `TestForwardQuarantineNotCarriedAcrossTrustADRemoval` (the carry
above — it fails with `adoptQuarantineFrom` removed),
`TestForwardQuarantinedUpstreamIsNotAlsoUnreachable`, and
`TestForwardQuarantineAggregateClears`.

The existing `TestBuildImrForwards...` bad-config tables now assert the shape
of the resulting table (dropped vs quarantined, and how many upstreams) rather
than only that an error came back.
`TestReloadZonesRejectedConfigChangesNothing` is unchanged and still passes,
which is the asymmetry holding.

## 5. Left open

- Quarantine is recomputed only when the table is swapped. A config that
  becomes valid without a reload (a `ca-file` that appears on disk) stays
  quarantined until the next reload. Retrying on a timer would need a reason
  to prefer it over `config reload`.
- `placeholderUpstream` synthesizes a label from the configured address, so
  two unparseable upstreams with the same address render identically. They
  both carry their own reason, so nothing is lost but the ordering.
