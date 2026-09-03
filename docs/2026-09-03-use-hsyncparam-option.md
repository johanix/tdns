# `use-hsyncparam`: the HSYNCPARAM republisher becomes opt-in per zone

**Written 2026-09-03.** Scoping, proposal, and what landed. Branch
`feature/use-hsyncparam-option`, off `origin/main` at 1cdc1809.

The option was proposed as `detect-hsyncparam` and renamed before
implementation: the question the option answers is not whether the server
*notices* the HSYNCPARAM -- it always parses and serves it -- but whether it
*acts* on it. `use-hsyncparam` also matches the existing `use-transport-signals`
IMR option.

## 1. HSYNCPARAM, per draft-leon-dnsop-signaling-zone-owner-intent-01

The June 2026 revision splits zone-owner signaling into two RRtypes at the
child's apex:

- **HSYNC** — one record per designated DNS Provider: `Label Identity Upstream`.
  `Label` is an unqualified handle, `Identity` the FQDN under which the
  Provider's Agent publishes its URI/SVCB/KEY discovery records, `Upstream`
  another Label or `.`. HSYNC carries *no* role information; it only enrolls a
  Provider and locates its Agent.
- **HSYNCPARAM** — exactly one record per zone, zone-wide policy as an
  SVCB-shaped key=value list. Eight keys are defined: `servers`(0),
  `signers`(1), `auditors`(2), `nsmgmt`(3), `parentsync`(4), `suffix`(5),
  `pubkey`(6), `pubcds`(7). List keys hold HSYNC Labels; a Label that matches
  no HSYNC record SHOULD be logged and treated as absent. Unknown key numbers
  MUST be preserved on read-back and MUST NOT be acted on.

Whether a Provider is *active* is decided by HSYNCPARAM role-key membership,
not by the HSYNC record — which is how the draft expresses staging (HSYNC
published, no role key yet) and offboarding (HSYNC retained, removed from every
role key).

**`pubkey`** (flag) is the key this proposal is about:

> The `pubkey` flag signals the zone owner's intent that each Provider SHOULD
> publish the child's SIG(0) KEY at the special name
> `_sig0key.{child}._signal.{their-ns-name}.` in their own zone.

Its stated use case is the SIG(0) bootstrap for cross-zone-cut DNS UPDATE in
draft-ietf-dnsop-delegation-mgmt-via-ddns. `pubcds` is the same shape at
`_dsboot.{child}._signal.{their-ns-name}.` per RFC 9615. Both exist so a
Provider need not *scan* customer zones for conventional content — the zone
owner's intent becomes explicit.

Note the wording: **"each Provider"**. `pubkey` is not addressed to a
particular Label. That is what lets tdns act on it without any of tdns-mp's
identity machinery (§2).

### Found while scoping this, fixed separately

`v2/core/rr_hsyncparam.go` assigned the key numbers in the opposite order from
the draft's registry -- `nsmgmt=0, parentsync=1, servers=2, signers=3` where the
draft puts the roles first. Every consumer (tdns and tdns-mp) shares the same
`core`, so nothing misbehaved between them, but the records tdns put on the wire
were not the records the draft describes.

Fixed in `fix/hsyncparam-draft-codepoints` (PR #490), which lands **before**
this branch: the flags this feature acts on, `pubkey` and `pubcds`, are wire
numbers, so turning `use-hsyncparam` on across a mixed pre/post-#490 fleet would
look like a dead option -- the RR fails to unpack rather than reporting
anything. See `docs/2026-09-03-hsyncparam-codepoints-upgrade-note.md`.

## 2. How tdns-mp does it, and which part tdns needs

tdns-mp registers `OnZonePreRefresh`/`OnZonePostRefresh` closures on MP zones
(`RegisterMPRefreshCallbacks`, `v2/config.go`), driven per role
(agent/combiner/signer/auditor).

`MPPreRefresh` (`v2/hsync_utils.go:1257`) runs before the hard flip, so it has
both old and new zone data:

- `HsyncChanged(old, new)` (`hsync_utils.go:32`) reads the apex HSYNC3 and
  HSYNCPARAM RRsets from both copies and diffs them with `core.RRsetDiffer`.
  HSYNC3 yields a per-RR adds/removes delta; HSYNCPARAM yields only a boolean
  `ParamChanged` — a pure HSYNCPARAM edit (moving a label between `signers=`
  and `servers=`) produces no RR delta but must still trigger a recompute,
  because voting membership is derived from HSYNCPARAM.
- `populateMPdata` (`hsync_utils.go:1070`) applies four guards: config option
  `multi-provider` → HSYNC3+HSYNCPARAM both present → *our* identity matches an
  HSYNC3 record → our role read out of HSYNCPARAM via `isServer` / `isSigner` /
  `isAuditor`, each consulting only its own key. Editing rights follow from the
  role.
- Plus: DNSKEY diff, a blocking KEYSTATE inventory RFI on the agent, the
  signer's dynamic inline-signing toggle, and the combiner's allow-edits +
  `CombineWithLocalChanges` on the pre-flip copy.
- Results are stashed in `mpzd.MP.RefreshAnalysis`.

`PostRefresh` (`hsync_utils.go:1412`) then routes off that analysis:
`ApplyHsyncDiff` into the HsyncEngine, provider-group recompute for the auditor,
`parentsync=agent` → turn on `OptDelSyncChild`, DNSKEY sync requests.

The apex reader itself is four lines (`getHSYNCPARAM`, `hsync_utils.go:924`):
get the apex owner, get the `TypeHSYNCPARAM` RRset, cast
`*dns.PrivateRR` → `*core.HSYNCPARAM`.

**tdns needs only that reader plus one flag test.** No HSYNC/HSYNC3 at all, no
identity matching, no adds/removes delta, no engine, no role model, no
pre-refresh pass. The reason is the draft's own wording: `pubkey` asks *each*
Provider to publish, so a secondary that holds the child zone and is primary for
one of the child's nameservers' zones qualifies on those two facts alone.

## 3. What tdns already has

Almost all of it. `v2/signal_republish.go` (D-6, PR #473, merged; see
`docs/2026-09-02-ddns-keystate-d6-at-ns-signal.md`) is already the producer:

- `RepublishAtSignalNames()` is an `OnZonePostRefresh` hook, registered in
  `v2/parseconfig.go:1558` for `Globals.App.Type == AppTypeAuth && zonetype ==
  Secondary && zdp.FirstZoneLoad`.
- `apexHsyncparam()` is the same four-line apex read as tdns-mp's
  `getHSYNCPARAM`; `signalSpecs` pairs `HasPubkey` → apex `KEY` → `_sig0key`
  and `HasPubcds` → apex `CDS`+`CDNSKEY` → `_dsboot`.
- For each apex NS name, `signalOwnerName(prefix, child, ns)` builds
  `<prefix>.<child>._signal.<ns>`, `FindZone` locates the zone that owns it,
  and a non-`Primary` (or absent) target is skipped — the draft's model, where
  the nameserver's operator is the publisher.
- Publication is change-gated against what is already at the signal name
  (`signalRRsEqual`, TTL- and order-insensitive), then a ZONE-UPDATE of
  delete-RRset + adds onto `KeyDB.UpdateQ`, fire-and-forget from the hook.
- Covered by `v2/signal_republish_test.go` (7 republish cases + unit tests).

So **detection, parsing and publication all existed and were tested.** What did
not exist was the gate: the hook was unconditional on every tdns-auth
secondary. That was the whole delta, and it is what §5 changes.

## 4. Decisions taken

1. **`ConfigWarning`, not `ConfigError`, on a primary.** The option is inert
   there, not dangerous, and `ConfigError` is in `serviceImpactingErrors` --
   raising one would take a healthy zone off the air over a setting whose only
   fault is having no effect. Same reasoning as the `request-ixfr` pair.
   A *template-provisioned* primary still refuses outright
   (`dynamicPrimaryDisallowedOptions`), because that path exists so a blessed
   template cannot silently lose an option.
2. **The `AppTypeAuth` clause was dropped from the hook registration.** The
   option is the whole gate: an operator who writes it has stated intent, and
   any app type that can be secondary for a customer zone and primary for a
   nameserver's zone can do the job.
3. **One option gates both flags.** `pubkey` and `pubcds` are two entries in the
   same `signalSpecs` table driving one function, and `pubcds` already shipped.
   Splitting would double the config surface for no behavioural gain; a
   separate `use-hsyncparam-cds` remains cheap to add if the two ever need to
   diverge.

## 5. What landed

- `v2/enums.go` -- `OptUseHsyncparam`, appended at the end of the iota block
  (ZoneOption values are positional), plus both string maps. The tdns sentinel
  moves 30 -> 31 against `TdnsZoneOptionMax = 32`.
- `v2/parseoptions.go` -- a switch case modelled on the `OptRequestIxfr` arm:
  on `type: primary`, log, record a `ConfigWarning`, and drop the option
  without setting the flag or letting it into `zconf.Options`.
- `v2/dynamic_primary.go` -- `OptUseHsyncparam` added to
  `dynamicPrimaryDisallowedOptions`.
- `v2/signal_republish.go` -- `RepublishAtSignalNames` returns immediately
  unless `zd.Options[OptUseHsyncparam]`, read under `zd.mu` (see the race note
  below). The check is at RUN time, not registration time: the hook is
  registered once while `zd.Options` is replaced wholesale on reload, so reading
  the option when the hook runs is what makes `config reload` take effect --
  both enabling and disabling -- instead of requiring a restart. File header
  updated; it claimed the consumer was always-on. Registration lives in the new
  `registerSignalRepublishHookOnce` helper here rather than inline in ParseZones.
- `v2/parseconfig.go` -- registers the hook for every `Secondary`, via
  `registerSignalRepublishHookOnce`; the `AppTypeAuth` clause is gone and the
  comment explains why the option is not checked there.

### After the external review

Two Major findings from the adversarial review, both real, both fixed here
rather than deferred:

- **Reload registration gap.** Registration was gated on `zdp.FirstZoneLoad`,
  but ParseZones reuses the `ZoneData`, so a zone reconfigured from primary to
  secondary on `config reload` (supported at `refreshengine.go`) never got the
  hook -- `FirstZoneLoad` is already false by then. The two OnZone*Refresh
  registrations (this one and `delegation-sync-proxy`, which had the identical
  gate and the identical bug) now use per-hook idempotency guards on `ZoneData`
  -- `signalRepublishHookRegistered`, `proxyDelegationHooksRegistered` -- so
  registration is once-only *and* fires the first time the zone becomes
  eligible, on any reload. Both are extracted into `registerSignalRepublishHookOnce`
  / `registerProxyDelegationHooksOnce`. As a side effect this also makes
  `delegation-sync-proxy` enable-able on reload, which it was not before.
  (Removing that option on reload still does not stop the proxy until a restart:
  its callbacks do not self-gate, so registration is its gate -- unchanged, and
  a separate concern from this finding. `use-hsyncparam` does self-gate, so it
  is honoured in both directions.)
- **Unsynchronized option read.** The callback read `zd.Options` with no lock
  while a reload replaces the map under `zd.mu` -- a data race. The read is now
  under `zd.mu` (the lock `SetOption` already uses), race-free and
  deadlock-free since the callback holds no other lock.

Tests added for both: `TestRegisterSignalRepublishHookOnce` and
`TestRegisterProxyDelegationHooksOnce` (a primary->secondary registration
registers exactly one hook/pair; repeated reloads do not duplicate;
mutation-checked by removing the guard) and
`TestRepublishAtSignalNamesOptionReadIsSynchronized` (passes under `-race`,
mutation-checked by dropping the lock).
- `v2/signal_republish_test.go` -- a `newOptedInChild` helper enables the
  option for the seven existing republish tests, and
  `TestRepublish_WithoutUseHsyncparamIsNoOp` is the gate: everything the
  republish needs is present and only the option is missing, so nothing may be
  written; the same zone with the option on then publishes both flags, so the
  no-op is the gate and not a broken fixture. Mutation-checked (removing the
  gate fails it).
- `v2/use_hsyncparam_test.go` -- map round trip, accepted on a secondary and
  present in `zconf.Options`, dropped-with-a-ConfigWarning-and-no-ConfigError
  on a primary, and disallowed for dynamic primaries.
- `guide/config-tdns-auth.md` -- a **Zone-owner signaling** option table and a
  `### use-hsyncparam` section.
- `guide/special-features.md` -- new §1.8, the nameserver-operator end of RFC
  9615 bootstrapping, with the Contents entry and the HSYNCPARAM record-type
  entry updated (it credited tdns-mp for the whole record).

Verified with `go build ./...` and `go test ./...` from `v2/`, `v2/cli/` and
`v2/cache/`.

### Deliberately not gated

- `publishSig0KeyAtSignalNames` (from `bootstrapSig0KeyWithParent`) and
  `refreshSig0KeyAtSignalNames` -- the child path, where the zone published for
  is our own and selecting `at-ns` is the intent. D-6 recorded that decision.
- `canPublishSig0KeyAtSignal`, which `zoneChildBootstrapMethods` consults to
  decide whether to offer `at-ns` at all. Gating it would silently drop `at-ns`
  from the offered methods on every zone without the option.

## 6. Still open

- Nothing has run on a testbed. The scenario to run is a tdns-auth secondary
  for a customer zone carrying `HSYNCPARAM pubkey`, which is also primary for
  the zone holding that customer's NS name.
- Removing the option stops future republishes but does not withdraw records
  already published at the signal names -- the same `unpublish` gap D-6 left
  open.
