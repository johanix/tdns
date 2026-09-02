# Implementation plan — unify the delegation-sync child paths and config

**Status:** implemented on `feature/delegation-sync-unification` (U-0 through
U-6). Design settled and reviewed 2026-09-02
(`reviews/2026-09-02-delegation-sync-unification-plan-review.md`, *request changes* —
both holds closed; `…-rereview.md`; `…-rereview-2.md`, *approve*).
**Base:** `main` (PR #312). Work in the **`v2/` tree only**.
**Relationship to other plans:** this is a prerequisite refactor for the remaining Phase 2
items of `2026-07-16-ddns-delegation-keystate-draft-alignment-plan.md` (D-6, D-7, D-3b).
Doing those first means implementing each of them twice — see §6.

---

## 1. What this fixes

Delegation sync grew a second child-side implementation (the tdns-agent
delegation-sync proxy, `v2/delsync_proxy_update.go`, PR #343) alongside the
original tdns-auth child path. The two do substantially the same thing and
already share their transport, but they diverged at the edges, and the
divergence is now producing real bugs rather than just duplication.

**Evidence it is already costing correctness:** commit `0c2c13b3` (2026-08-23)
added an explicit `dsKnown` parameter to replace-mode UPDATE construction, so
that a zone which stops being signed has its stale DS removed from the parent
rather than left to make every validating resolver declare the child bogus.
The fix reached the auth-child path (`v2/delegation_sync.go:480`) and not the
proxy path (`v2/delsync_proxy_update.go:410`), which still calls the inferring
wrapper. Filed as [#468](https://github.com/johanix/tdns/issues/468). That is one
fix, on one of the two paths, ten days apart — the pattern will repeat for
every future fix until the paths are one.

**The same split exists in config**, three times over on the parent side (§3),
and not at all on the child side, where D-6 needs a field that has nowhere to go.

### 1.1 How far apart the two senders actually are

| step | auth child (`SyncZoneDelegationViaUpdate`) | proxy (`ProxyUpdateParent`) |
|---|---|---|
| UPDATE gate | none needed | §10.8 state machine — **already shared** via `updateGateBlocked(kdb, role)` (`v2/delegation_sync_plan.go:233`) |
| mode default | delta | replace |
| payload source | `DelegationSyncStatus` passed in by caller | recomputed locally (`AnalyseZoneDelegation` / `proxyCurrentDelegationRRs`) |
| DS-known | explicit `syncstate.NewDSKnown` | inferred — **bug #468** |
| build message | `CreateChildReplaceUpdateWithDS` / `CreateChildUpdate` | same functions |
| fetch key | `kdb.GetSig0Keys(zone, Sig0StateActive)` | identical |
| sign | `SignMsg(*m, zone, sak)` | identical |
| send | `SendUpdateWithRetry(ctx, smsg, parent, addrs)` | identical |

Three of the five real steps are the same logic written twice; the plan layer
(`BuildParentSyncPlan` → `SyncWithParent` → `walkSyncPlan`) and the message
builders are already common. The genuine differences are the payload source and
the mode default.

### 1.2 The one irreducible role difference

**Who writes the KEY RR into the child zone.** tdns-auth calls `PublishKeyRRs`;
tdns-agent is a secondary, cannot author the zone, so the operator publishes the
KEY at the primary and it arrives by AXFR (the §10.8 WAITING state).

Everything downstream of "a KEY is at the apex" is identical for both roles.
In particular `BootstrapSig0KeyWithParent` (`v2/ops_key.go:154`) **never publishes
a KEY into the zone** — it gets-or-generates the key in the keystore, looks up
the DSYNC target, builds the self-signed `DEL ANY KEY` + `ADD KEY` ceremony,
signs and sends. It is directly reusable by the proxy, which simply does not
call it today.

**Correcting a mistaken assumption that shaped the earlier plan:** the proxy is
*not* restricted to the draft's `manual` bootstrap method. The "manual" in the
§10.8 state machine is manual *publication of the KEY into the child zone* — a
child-side operational step — not the draft's parent-side `manual` method. Once
the KEY is at the apex the parent validates it by `at-apex`/`at-ns`/`unsigned`
exactly as for any other child, and cannot tell who put it there. The proxy is
compatible with `at-apex`, `unsigned` and `manual`. The operator re-enters only
for the initial publication and for key rollover, both being the same step.

**One caveat on that, added after review:** `at-ns` is the exception. The live
`at-ns` is RFC 9615 signalling — the KEY is looked up at
`_sig0key.<child>._signal.<ns>`, which lives in the *nameserver's* zone, not the
child's. A secondary proxying for a clueless primary generally does not control
those names, so it cannot make itself verifiable that way. `at-apex` remains
fully available to it, so this narrows the claim rather than undermining the
unification.

---

## 2. Non-goals

- No change to the NOTIFY or API schemes beyond what falls out of sharing the plan layer.
- No change to `updatepolicy.zone.*` (the self/sub RRtype policy) — only the
  `child.keybootstrap` member moves, because it is delegation-bootstrap policy.
- No IANA codepoint changes (still Phase 3 of the alignment plan).
- Not implementing D-6/D-7/D-3b here. This plan makes them small; it does not do them.
- **`scanner.options` / `scanner.at-apex.*` stay exactly where they are**
  (`cmdv2/auth/tdns-auth.sample.yaml:265-273`). They reuse the words
  `at-apex`/`at-ns` for RFC 8078 opportunistic onboarding and RFC 9615 CDS
  signalling — DS bootstrap, not SIG(0) key trust. Same words, different domain.
  Do not fold them into `delegationpolicy` while "unifying the vocabulary".
- The root-zone `{ZONENAME}` vs `"root"` expansion bug (`v2/zone_utils.go:1678`
  vs `v2/ops_dsync.go:377-381`) is a D-7 rider, not unification work — but U-4
  must not add a third expansion site. See U-4.

---

## 3. The config problem

Three parent-side settings govern overlapping parts of one question, at two
different scopes, with three vocabularies:

| setting | scope | governs | read at |
|---|---|---|---|
| `updatepolicy.child.keybootstrap: [manual\|dnssec-validated\|consistent-lookup]` | **per-zone** | how this parent bootstraps a child key | `v2/keystate.go:266` |
| `delegationsync.parent.update.key-verification.{mechanisms,require-dnssec,max-attempts,retry-interval}` | **global** | how an uploaded key is verified before trust | `v2/truststore_verify.go:86` |
| `delegationsync.parent.bootstrap.methods` (free string) | **global** | what the SVCB advertises | `v2/ops_dsync.go:297` |

Three defects follow:

1. **The advertisement is disconnected from the policy it advertises.**
   `bootstrap.methods` is independently settable, so a zone can advertise
   `at-apex` while its policy is manual-only. Worse, `PublishDsyncRRs` is a
   *per-zone* method reading a *global* string, so a parent serving zones with
   different `keybootstrap` policies can only advertise one answer for all of
   them. The advertisement must be **derived**, not configured.

2. **Two axes are modelled as one, inconsistently.** The draft's `bootstrap`
   values conflate *where to find the key* with *how strongly to trust it*:
   `at-apex`/`at-ns` are implicitly DNSSEC-validated, `unsigned` is the
   unvalidated variant, `manual` is out of band. tdns splits these correctly
   into `mechanisms` (where) and `require-dnssec` (how strongly) — strictly more
   expressive — while `updatepolicy.child.keybootstrap` uses a third vocabulary
   mixing both (`dnssec-validated`, `consistent-lookup`, `manual`). Normalising
   is therefore not a rename; it is deciding to keep two internal axes and
   define a total mapping onto the four wire tokens.

3. **One live verification engine and one dead one — and half the vocabulary is inert.**
   Established 2026-09-02 by tracing reachability, and it is more clear-cut than
   "two engines that should merge":

   - **Live:** `TriggerChildKeyVerification` (`v2/truststore_verify.go:185`) →
     `VerifyChildKey` (`:85`), which implements **both** configured mechanisms
     itself: `at-apex` via `LookupChildKeyAtApex`, and `at-ns` via
     `LookupChildKeyAtSignal` (RFC 9615 `_signal` names). Typed config, DNSSEC-aware.
   - **Dead:** `KeyBootstrapper`/`VerifyKey` (`v2/keybootstrapper.go:25,198`) is a
     *different* mechanism — query every nameserver directly, require the KEY
     identical on all of them, no DNSSEC — and it is **unreachable**. Nothing
     outside `keybootstrapper.go` ever constructs a `KeyBootstrapperRequest`; the
     three sends at `:204,246,248` are internal re-queues from `VerifyKey`, which
     runs only from the engine loop at `:41,103`, which only runs on a request that
     never arrives. The engine starts (`v2/main_initfuncs.go:305`), blocks on an
     empty channel, and its `viper.GetInt("verifyengine.*")` reads at `:88,141,158`
     never execute.
   - **Inert vocabulary:** of the four `updatepolicy.child.keybootstrap` values,
     only `manual` and `strict-manual` are read anywhere — `manual|strict-manual`
     at `v2/keystate.go:267` (choose KeyState 10 vs 9) and `strict-manual` at
     `v2/updateresponder.go:582,762` (prohibit unvalidated upload).
     **`dnssec-validated` and `consistent-lookup` are read nowhere.**
     `consistent-lookup`'s only plausible implementation was the dead engine.

Plus a documentation defect: `cmdv2/auth/tdns-auth.sample.yaml:275-281` tells
operators the real knobs are `keystate.require_manual_bootstrap` and
`keystate.allow_auto_bootstrap`. Neither string is read anywhere in `v2/` or
`cmdv2/`.

On the child side there is **no** bootstrap-method setting at all, which is where
D-6's needed field has to go.

---

## 4. Config

Two established patterns exist in this codebase for per-zone variation: a
**named policy referenced by name** (`dnssecpolicy: <name>` → `dnssec.policies.*`)
and an **inline per-zone struct gap-filled by zone templates** (today's
`updatepolicy:`).

**Decided 2026-09-02: named policies**, for the parent side. Bootstrap policy is
security policy: a small set of named, reviewable policies audits better than
per-zone hand-rolled ones, and it decouples the policy from the zone list while
still reaching zones through templates (a template can set the reference).

Per the project's no-backwards-compatibility rule, this is a clean config break:
no aliasing of the old key names, no dual-format parsing.

```yaml
delegationsync:

   # ---- PARENT SIDE: named policies, referenced per-zone --------------------
   # A zone selects one with `delegationpolicy: <name>`. The REFERENCE looks
   # like `dnssecpolicy: <name>`, but the two omission cases differ -- see
   # §4.3. Omitted binds `default`; a name that does not resolve quarantines.
   policies:
      default:
         bootstrap:
            # WHERE to look for the child's KEY, in try order.
            #   at-apex — the child's apex KEY RRset
            #   at-ns   — RFC 9615 signalling: _sig0key.<child>._signal.<ns>
            #             (NOT "all nameservers agree" -- that is the dead
            #             engine's mechanism, deleted in U-5 and not ported)
            # Empty means no automatic bootstrap at all.
            mechanisms:      [ at-apex, at-ns ]
            # HOW strongly to trust what is found. true: the lookup must be
            # DNSSEC-validated. false is what the draft calls "unsigned".
            require-dnssec:  true
            # Whether an operator may install trust out of band. Independent of
            # the above: a policy may allow both automatic and manual.
            manual:          false
            # Whether an untrusted signer may upload a KEY at all -- i.e.
            # whether the self-signed bootstrap UPDATE is admitted. This is the
            # entry condition to the ceremony, which is why it belongs here and
            # not in updatepolicy (§4.2). Was `updatepolicy.child.keyupload`.
            # false matches today's behaviour: the old field had to be set to
            # the literal "unvalidated" to permit it, so absent meant refuse.
            allow-unvalidated-upload: false
            retry:
               max-attempts: 5      # today's defaults, from
               interval:     10s    # keyVerificationRetrySettings()

      permissive:
         bootstrap:
            mechanisms:      [ at-apex, at-ns ]
            require-dnssec:  false          # advertises "unsigned"
            manual:          true
            allow-unvalidated-upload: true
            retry: { max-attempts: 5, interval: 30s }

      locked-down:
         bootstrap:
            mechanisms:      [ ]            # nothing automatic
            manual:          true           # advertises "manual" only
            allow-unvalidated-upload: false # the old `strict-manual`

   # ---- PARENT SIDE: transport and publication only -------------------------
   # No policy lives here any more. In particular there is no
   # `bootstrap.methods:` — the SVCB advertisement is DERIVED from the zone's
   # bound delegationpolicy (§4.1), so it cannot contradict it.
   parent:
      schemes: [ notify, update ]
      notify:
         types:     [ CDS, CSYNC ]
         port:      5354
         target:    notifications.{ZONENAME}
         addresses: [ 127.0.0.1, '::1' ]
      update:
         types:     [ ANY ]
         port:      5354
         target:    updates.{ZONENAME}
         addresses: [ 127.0.0.1, '::1' ]
         keygen:
            algorithm: ED25519
      # api: ... unchanged

   # ---- CHILD SIDE: one construct, shared by tdns-auth and tdns-agent -------
   # Not per-parent: D-6's whole point is that the method is negotiated with
   # each parent from its advertised SVCB. The child declares only what it is
   # willing to rely on; the intersection is computed per parent at run time.
   child:
      schemes: [ notify, update ]
      update:
         keygen:
            generator: /opt/local/bin/dnssec-keygen
            algorithm: ED25519
         bootstrap:
            # Methods this child will accept a parent using, in preference
            # order. Intersected with the parent's advertised set; the first
            # surviving preference wins. Empty intersection => refuse and log,
            # never silently degrade.
            # Default when absent: [ at-apex ] — `at-ns` is valid to opt into
            # but the child cannot yet publish RFC 9615 `_signal`. `unsigned`
            # must be opted into, because this decides how strongly the parent
            # will have checked the key that authorises everything else.
            methods: [ at-apex ]
      # api.credentials stay per-parent — they are per-parent secrets.
```

On a zone (or a zone template), alongside `dnssecpolicy:`:

```yaml
zones:
   - name:             example.
     type:             primary
     dnssecpolicy:     default
     delegationpolicy: locked-down     # NEW
```

### 4.1 Deriving the SVCB advertisement

At `PublishDsyncRRs` time, from the zone's bound policy — one total function,
the single source of what a parent claims:

| policy | advertised token(s) |
|---|---|
| `mechanisms` contains `at-apex`, `require-dnssec: true` | `at-apex` |
| `mechanisms` contains `at-ns`, `require-dnssec: true` | `at-ns` |
| `mechanisms` non-empty, `require-dnssec: false` | `unsigned` |
| `manual: true` | `manual` |
| `mechanisms` empty and `manual: false` | *(no SVCB published)* |

As a function, so an implementer does not re-derive it from the table:

```
if require-dnssec {
    emit at-apex / at-ns, per mechanisms      // WHERE is on the wire
} else if len(mechanisms) > 0 {
    emit unsigned                             // WHERE is not; that is the draft
}
if manual { emit manual }
if nothing emitted { publish no SVCB }
```

A parent therefore cannot advertise what it will not do, and a zone with a
stricter policy than its siblings advertises accordingly.

**Two intersections that must refuse, spelled out because "first surviving
preference wins" makes them look like oversights:**

- Parent `permissive` (`require-dnssec: false`) advertises `unsigned` + `manual`.
  The child default `[at-apex, at-ns]` intersects to nothing and **refuses**.
  That is the opt-in working as intended, not a bug to smooth over — D-6 must not
  "helpfully" read `unsigned` as satisfying `at-apex`.
- Parent `locked-down` advertises `manual` only. Same outcome. A child willing to
  be bootstrapped out of band must list `manual` explicitly.

### 4.2 The boundary between `updatepolicy` and `delegationpolicy`

**Decided 2026-09-02: `keybootstrap` and `keyupload` both move into the
delegation policy.** The line between the two blocks is authentication versus
authorization:

- **`delegationpolicy`** — how a child's SIG(0) key becomes *trusted*. Do I
  believe this signer is who it claims to be?
- **`updatepolicy`** — given that I believe them, what are they allowed to
  change: `type` (selfsub|self|sub|none), `rrtypes`, `ttl`.

A new setting belongs wherever it falls on that line.

`keyupload` moves because it is not merely adjacent to `keybootstrap` — the two
are read in the *same conditional* (`v2/updateresponder.go:580-587`, mirrored at
`:760-767`): `keyupload: unvalidated` is honoured only if `keybootstrap` is not
`strict-manual`. One decision expressed across two fields, so moving one without
the other would split a single `if` across two config blocks and leave exactly
the confusion this move exists to remove.

**`strict-manual` disappears as a value.** The old `keybootstrap` enum
(`manual | dnssec-validated | consistent-lookup | strict-manual`) bundled
orthogonal questions into one list, which is why `strict-manual` had to exist as
a separate value at all — it was "manual, and also refuse unvalidated upload".
On the axes above it is just `mechanisms: []` + `manual: true` +
`allow-unvalidated-upload: false`, which is the `locked-down` policy in §4.

**Only two of the four values have behaviour to preserve.** `manual` →
`manual: true`; `strict-manual` → as above. **`dnssec-validated` and
`consistent-lookup` are read nowhere in the tree** (§3 defect 3) and carry no
behaviour to migrate — they are deleted, not mapped. `require-dnssec: true` is
already the live default in `VerifyChildKey`, so the setting `dnssec-validated`
appeared to request is what everyone already gets.

### 4.3 Binding semantics — where `dnssecpolicy` stops being the model

Copy the **reference + quarantine** shape only. The two omission cases are not
the same as `dnssecpolicy`'s, and the rest of its machinery is not wanted:

| case | behaviour |
|---|---|
| `delegationpolicy:` omitted / empty | bind `default` (automatic, `require-dnssec: true`) |
| names a policy that does not resolve | **quarantine** the zone (the `updatepolicy` failure model, `activateUpdatePolicy`) |

`dnssecpolicy` omitted means *the zone is not signed* — it only resolves a
non-empty name (`v2/parseconfig.go:1219`). Leaving delegation verification
unconfigured is not an acceptable analogue, hence `default`.

Also not copied: `dnssecpolicy`'s DB override (`EffectiveDnssecPolicyName`),
last-applied persistence, and transactional apply (`v2/zone_policy_apply.go`). A
CLI override that silently changes how strictly child keys are verified is a new
product decision, not a freebie of "bind it the same way".

**Migration hazard for U-6:** the shipped templates
(`cmdv2/auth/auth-templates.yaml:13,28`) set
`keybootstrap: [ manual, dnssec-validated, consistent-lookup ]`. Only `manual` is
live there, so those zones report KeyState 10 today. They must come out
referencing a policy with `manual: true` — **not** fall through to `default`,
which would silently convert the sample parent to automatic bootstrap. "Every
other `keybootstrap` setting simply disappears" is true of the inert values, not
of `manual`.

### 4.4 Removed keys

`delegationsync.parent.bootstrap.methods`; `delegationsync.parent.update.key-verification.*`
(folded into the named policy); `updatepolicy.child.keybootstrap`;
`updatepolicy.child.keyupload`; `verifyengine.attempts`; `verifyengine.retry_interval`;
and the stale sample-config note naming `keystate.require_manual_bootstrap` /
`keystate.allow_auto_bootstrap`.

`updatepolicy.child` retains `type`, `rrtypes` and `ttl` — the authorization
scope, per §4.2.

---

## 5. Work items

Sliced so each is separately reviewable and separately revertable. Ordered by
dependency; U-1 and U-2 are independent of the config work and can go first.

### U-0. Fix the `dsKnown` inference bug — [#468](https://github.com/johanix/tdns/issues/468)
Independent of everything below and already filed. Do it first, on its own, so
the correctness fix is reviewable against today's code rather than buried in a
refactor.

**Corrected 2026-09-02 after review.** An earlier draft of this item said "derive
`dsKnown` from `zoneLooksSigned(zd)`". That does not fix the bug:
`zoneLooksSigned` (`v2/zone_delta_replay.go:299`) is true iff the apex has
DNSKEYs, so for a zone that has dropped DNSSEC it is **false** — the DS is left
alone and the stale record survives. It is also all but the same boolean as the
`len(newDS) > 0` inference it was meant to replace, since `newDS` derives from
those same DNSKEYs.

- **Change, part 1 — the flag.** This path always has a DS opinion: it has just
  derived DS from the served zone. A class-ANY delete of a DS RRset the parent
  does not have is a no-op, so "never had a DS" and "has a stale DS" are one
  call, not two parameters. Pass `true`:

  ```go
  newNS, newA, newAAAA, newDS := zd.proxyCurrentDelegationRRs()
  m, berr = CreateChildReplaceUpdateWithDS(zd.Parent, zd.ZoneName, newNS, newA, newAAAA, newDS, true)
  ```

- **Change, part 2 — the derivation, which must land in the same PR.**
  `proxyCurrentDelegationRRs` (`v2/delsync_proxy_update.go:276-277`) derives DS
  only from SEP-flagged DNSKEYs, so a zone signed with a single flags-256 CSK
  yields an empty `newDS` while being properly signed. With `dsKnown=true` that
  **deletes a live child's DS** — strictly worse than the stale DS being fixed,
  and today masked only by `dsKnown=false`. Shipping part 1 alone is a
  regression; this is not a separate concern but the rest of the same fix.

  **Corrected again after re-review.** An earlier draft of this bullet said the
  fix was to treat "every apex DNSKEY as DS-eligible, not SEP-only", and claimed
  the auth path had stopped using SEP. Both are wrong. `DSIntentForZone` still
  queries `int(dns.SEP)` (`v2/ds_intent.go:87`) and `TestDSIntentIgnoresNonSEPKeys`
  pins a flags-256 row contributing **no** DS; what `computeNewDS` actually fixed
  was gating on whether the update mentioned DNSKEYs at all
  (`v2/zone_updater.go:1671-1678`), not the SEP question. Hashing every published
  DNSKEY would mint a DS for every **ZSK** in an ordinary KSK/ZSK child — a worse
  error than the one it was meant to correct.

  **Use the predicate this tree already has.** `hasDnskeyRRset()`
  (`v2/delsync_proxy_api.go:202-209`) answers exactly this question on the other
  proxy transport, and its comment makes the argument verbatim: the SEP bit is
  advisory, validators ignore it, and reading "no SEP key" as "not signed" is how
  a working child loses its DS. It returns `true` on a failed lookup, so a
  transient read cannot withdraw a DS. `proxyApiRRsets` (`:165-191`) and
  `unmanagedZoneNeedsDSRepair` (`v2/delegation_utils.go:159-171`) already follow
  the same rule. Do not invent a third DS derivation:

  ```go
  newNS, newA, newAAAA, newDS := zd.proxyCurrentDelegationRRs()
  dsKnown := !zd.hasDnskeyRRset() || len(newDS) > 0
  m, berr = CreateChildReplaceUpdateWithDS(zd.Parent, zd.ZoneName, newNS, newA, newAAAA, newDS, dsKnown)
  ```

  | served zone | `hasDnskeyRRset` | SEP-derived `newDS` | `dsKnown` | parent DS |
  |---|---|---|---|---|
  | unsigned (no DNSKEY RRset) | false | empty | **true** | deleted — fixes #468 |
  | flags-256 CSK | true | empty | **false** | left alone — no live-DS delete |
  | SEP KSK (+ any ZSKs) | true | non-empty | **true** | restated from SEP keys only |

  **Known limitation, deliberate:** a proxied zone signed only with flags-256
  keys never has its DS maintained by the proxy — the middle row declines to have
  an opinion rather than guessing which key to hash. That is the safe direction.
  Record it here so it is not later "fixed" by hashing non-SEP keys, which is the
  ZSK error above.
- **Acceptance:** a proxied zone that drops its DNSKEYs removes the parent's DS;
  a flags-256 CSK zone **retains** it; **a KSK+ZSK zone does not grow a DS for the
  ZSK** (the last one is what stops the wrong heuristic hiding behind the CSK
  case). `TestProxyApiDSStatementDependsOnTheDnskeyRRsetNotTheSEPBit`
  (`v2/delsync_proxy_api_test.go:344`) already pins the same three shapes on the
  API path and is the model to copy.
- **Est.** ~60-120 LOC.

### U-1. One UPDATE sender
- **Change:** collapse `SyncZoneDelegationViaUpdate` and `ProxyUpdateParent` into a
  single sender taking `(ctx, kdb, syncstate DelegationSyncStatus, target *DsyncTarget, mode string)`.
  No `imr`: once callers produce the `syncstate`, the sender has no use for it —
  the proxy needs `imr` only to *build* that state via `AnalyseZoneDelegation`.
  Callers produce the `syncstate`; the role supplies the mode default (child delta,
  proxy replace). The §10.8 gate stays where it already is, in `updateGateBlocked`.
- **Note:** `ProxyStartupReconcile` already computes an `AnalyseZoneDelegation` and
  then lets `ProxyUpdateParent` recompute it in delta mode; threading the
  `syncstate` through removes that second analysis.
- **Acceptance:** one sender; both roles' existing tests pass unchanged; the
  redundant analysis is gone.
- **Est.** ~200-350 LOC (mostly deletion).

### U-2. One bootstrap state machine
- **Change:** give the proxy the real bootstrap path. `BootstrapSig0KeyWithParent`
  is already role-agnostic (§1.2) — factor the single role-dependent step,
  "ensure the KEY is published at the apex", behind an interface with two
  implementations: `PublishKeyRRs()` for auth, generate-instruct-wait (§10.8)
  for the proxy. Re-bootstrap on BADKEY then works for both, since it needs
  only the private key the agent already holds.
- **When the ceremony runs — specify this, not just the interface.**
  `SendUpdateWithRetry` (`v2/delsync_retry.go:138-153`) already calls
  `BootstrapSig0KeyWithParent` on BADKEY, for both roles. So "give the proxy the
  bootstrap path" could be read as "it already has one" — but relying on the
  BADKEY arm means the first proxied UPDATE is a guaranteed failure plus an
  alarming log, and against a parent with `allow-unvalidated-upload: false` it
  never recovers. Required behaviour:
  1. On the `WAITING` → `READY` transition (the KEY has appeared at the apex),
     call `BootstrapSig0KeyWithParent` **before** the first delegation UPDATE.
  2. BADKEY recovery stays in `SendUpdateWithRetry`, already shared. Do not add a
     second re-bootstrap path.
  3. The role interface covers only "ensure the KEY RR is at the apex"
     (`PublishKeyRRs` vs generate-instruct-wait). The ceremony stays role-agnostic.
- **Rename** `proxyUpdateKeyState()` (`v2/delsync_proxy_update.go:121`) — it is the
  state of the agent's SIG(0) key, unrelated to the draft's KeyState option, and
  in this codebase that collision is a trap.
- **Acceptance:** a proxy zone whose KEY is at the apex completes a self-signed
  bootstrap and re-bootstraps on BADKEY without operator action.
- **Est.** ~250-400 LOC.

### U-3. Named parent-side delegation policies
- **Change:** add `delegationsync.policies.*` and the per-zone `delegationpolicy:`
  reference; **bind it per §4.3** — the reference shape is `dnssecpolicy`-like but
  the omission and failure cases are not, which is what §4.3 exists to stop
  anyone copying. Move
  `key-verification.*`, `updatepolicy.child.keybootstrap` and
  `updatepolicy.child.keyupload` into it and delete all three (§4.2).
- **Note:** the two `updatepolicy` fields are read in one conditional
  (`v2/updateresponder.go:580-587`, mirrored `:760-767`), so they move together
  and that conditional collapses onto the orthogonal policy axes. The
  `strict-manual` enum value ceases to exist — it becomes `mechanisms: []` +
  `manual: true` + `allow-unvalidated-upload: false`.
- **Pattern to follow, and the one place not to follow it.** Key the policies as
  `delegationsync.policies.<name>`, parallel to `dnssec.policies.<name>`, and
  reuse `resolveZonePolicyRef` (`v2/parseconfig.go:1221`) for the reference
  lookup. But **fail like `updatepolicy`, not like `dnssecpolicy`**: an
  unresolvable `dnssecpolicy` *degrades* (zone served unsigned, error recorded on
  the zone, `parseconfig.go:1219-1230`), whereas `activateUpdatePolicy` returns a
  hard error and quarantines the zone. Delegation policy governs how strictly a
  child's key is verified, so silently substituting a default for a name the
  operator got wrong is the wrong failure mode. Quarantine. This is worth stating
  because "named policy" invites copying `dnssecpolicy` wholesale, and its
  failure model is the one that does not transfer.
- **No policy templates.** `dnssec` has `policies` *and* `templates` (partial
  policies to inherit from) because a DNSSEC policy is large. A delegation policy
  is five fields; template inheritance would be machinery for nothing. Do not add
  it by analogy.
- **Migration:** only `manual` and `strict-manual` have behaviour to carry over
  (§3 defect 3). The *inert* values (`dnssec-validated`, `consistent-lookup`)
  disappear; `manual` does **not** — see the shipped-template hazard in §4.3,
  which those templates do set.
- **Child field:** U-3 adds and *parses* `child.update.bootstrap.methods`;
  bootstrap intersects that list with the parent SVCB advertisement (T4).
- **Acceptance:** two zones on one parent with different policies bootstrap
  differently; config naming an unknown policy fails at parse (fail closed); each
  old `keybootstrap` value's behaviour is reproduced by its §4.2 mapping, pinned
  by tests written against the *current* code before the move.
- **Est.** ~300-500 LOC.

### U-4. Derive the SVCB advertisement from policy
- **Change:** implement the §4.1 mapping; `PublishDsyncRRs` uses the zone's bound
  policy. Delete `parent.bootstrap.methods`. Extend `UnpublishDsyncRRs`
  (`v2/ops_dsync.go:387-431`) to remove the bootstrap SVCB and receiver KEY, which
  it does not do today — **at the DSYNC UPDATE target**, named via
  `DsyncUpdateTargetName`, the same expansion `PublishDsyncRRs` uses. Not at the
  apex: the apex KEY is the parent's own SIG(0) identity and deleting it would
  remove the thing the whole scheme authenticates with. Use the one helper rather
  than open-coding a third `{ZONENAME}` / `"." → "root"` expansion — there are
  already two, and they disagree (the D-7 rider at `v2/zone_utils.go:1678`).
- **Acceptance:** advertisement matches policy for every row of the §4.1 table;
  unpublish removes what publish added.
- **Est.** ~150-250 LOC.

### U-5. Delete the dead verification engine
Scope changed 2026-09-02 from "merge two engines" to "delete the unreachable
one" — see §3 defect 3. This is pure deletion, not a migration.
- **Change:** remove the `KeyBootstrapper` engine loop, `VerifyKey`,
  `KeyBootstrapperRequest`/`KeyBootstrapperQ` (`v2/db.go:367`,
  `v2/structs.go:1215`), the `kbCmd*` constants, the startup registration
  (`v2/main_initfuncs.go:305`), and with them the last `viper.GetInt("verifyengine.*")`
  reads in this area. Nothing sends to the queue, so nothing loses a capability
  that is currently working.
- **Verify before deleting:** re-confirm no external `KeyBootstrapperRequest`
  construction exists **in `v2/`** at the time the work is done. Note the legacy
  `tdns/` tree still constructs one (`tdns/keystate.go`); a tree-wide grep will
  show hits that do not contradict the v2 reachability finding.
- **Not ported:** the all-nameservers-agree mechanism the dead engine implemented.
  It is a weaker, non-standard cousin of the live `at-ns` (RFC 9615 `_signal`)
  and has never been reachable, so nobody depends on it. If it is wanted later it
  should be added as a third value of `mechanisms` inside `VerifyChildKey`, where
  it inherits the shared retry/DNSSEC handling — not resurrected as a parallel
  engine. See §7 decision 2.
- **Acceptance:** no viper read remains under `delegationsync`/`verifyengine`;
  one engine; build/vet/test green.
- **Est.** ~150-250 LOC, almost entirely removed.

### U-6. Sample config and docs
- **Change:** rewrite the `delegationsync:` block per §4; delete the stale
  key-bootstrap note at `tdns-auth.sample.yaml:275-281`; document
  `delegationpolicy:` in the templates sample.
- **Est.** ~100-150 LOC.

**Total: ~1180-1960 LOC**, a large fraction of it deletion.

---

## 6. What this unblocks

With one child path and one config, the remaining alignment-plan items shrink
to roughly what their original estimates assumed:

- **D-6** becomes "add `child.update.bootstrap.methods` (U-3 already built the
  child block), look up the SVCB at the DSYNC target, intersect, pick" — one
  site, not two. The scope question about the proxy role dissolves: both roles
  read the same field.
- **D-7** gets smaller, but **not to one call site** — corrected after review.
  The inquiry is consumed at three places today (`QueryParentKeyState`,
  `QueryParentKeyStateDetailed`, `KeyDB.UpdateKeyState`), none verifying. U-5
  deletes the third; U-1/U-2 unify the *UPDATE send* path, which is not the
  inquiry path, so **two inquiry functions remain**, both still unsigned-UDP
  (`dns.Client{}` with no `Net`, `v2/parentsync_bootstrap.go:169,219`). Do not
  discount the D-7 estimate on the strength of U-1. It remains the
  highest-value remaining item.
- **D-3b**'s NS/glue acceptance check lands on one UPDATE path rather than two.

Done in the other order, each of the three is implemented twice and the #468
pattern repeats.

---

## 7. Decisions

**Settled 2026-09-02.**

1. **`keybootstrap` and `keyupload` both move into the delegation policy.**
   Rationale and the resulting authn/authz boundary: §4.2.

2. **The dead verification engine is deleted, not merged.** The reachability
   trace in §3 defect 3 turned this from a design question into a cleanup:
   there is one live engine, and it already implements both configured
   mechanisms. The all-nameservers-agree mechanism is dropped rather than
   ported; if wanted, it returns as a third `mechanisms` value inside
   `VerifyChildKey`, never as a second engine. U-5.

3. **`manual` stays an independent flag, not a `mechanisms` value.** It is not a
   lookup mechanism — it means "no automatic verification; an operator installs
   trust" — and a policy may sensibly permit automatic *and* manual, which
   folding it into the list would make inexpressible. Its only live effect today
   is selecting KeyState 10 over 9 (`v2/keystate.go:267`).

4a. **Empty `mechanisms` means *do not verify*, and must not inherit today's
   default-fill.** An implementation invariant, not a preference — the two rules
   otherwise collide. `VerifyChildKey` treats an empty list as
   `[at-apex, at-ns]` (`v2/truststore_verify.go:87-89`), and
   `TriggerChildKeyVerification` is **not gated on `keybootstrap`** — every newly
   stored untrusted child KEY starts it unconditionally
   (`v2/zone_updater.go:552-556`), which is why a zone with
   `keybootstrap: [manual]` still auto-verifies today and `manual` only changes
   the reported KeyState code. If U-3 reuses that empty-list fill, or adds a
   `WithDefaults()` that supplies `[at-apex, at-ns]`, then `locked-down`
   auto-verifies while advertising `manual` only — the advertisement lies, which
   is the very defect §3.1 exists to close. So:
   - **policy with `mechanisms: []`** — do not look up, do not start
     `TriggerChildKeyVerification`, do not fill a default list.
   - **the `default` policy** — carries `[at-apex, at-ns]` *written out
     explicitly* (as §4 does). That is how today's unset value is reproduced;
     not by treating empty as unset.

4. **The default policy reproduces today's effective behaviour exactly**, so
   that adopting named policies is not also a silent behaviour change. Today's
   defaults, from the live code: `mechanisms` empty → `[at-apex, at-ns]`
   (`v2/truststore_verify.go:87-89`); `require-dnssec` absent → `true`
   (`:216-219`); `max-attempts` → 5 and `retry-interval` → 10s
   (`keyVerificationRetrySettings`, `:166-176`); `keyupload` absent → refuse
   unvalidated upload; `keybootstrap` absent → automatic, not manual
   (`zoneRequiresManualBootstrap` returns false for an unset list). The
   `default` policy in §4 is written to those values.

5. **Named policies, not inline+templates** (§4). Bootstrap policy is security
   policy: a small set of named, reviewable policies audits better than per-zone
   hand-rolling, while still reaching zones through templates. Keyed
   `delegationsync.policies.<name>`, parallel to `dnssec.policies.<name>`, with
   the failure-model caveat in U-3 — quarantine on an unresolvable reference, as
   `updatepolicy` does, not degrade as `dnssecpolicy` does.

**All decisions settled. No blockers to starting U-0.**

---

## 8. Test plan

- **Unit:** the §4.1 derivation table, every row; child/parent method
  intersection including the empty case (must refuse, not degrade); policy
  binding per zone; unknown policy name fails at parse.
- **Regression:** both roles' existing sender tests pass against the unified
  sender unchanged; `dsKnown` behaviour for signed→unsigned on both roles, **and
  a flags-256 CSK zone whose DS must be retained** (U-0 part 2).
- **Invariants from the review holds:** `locked-down` never calls
  `LookupChildKeyAtApex`/`LookupChildKeyAtSignal` and never starts
  `TriggerChildKeyVerification`; the default child methods refuse against a
  parent advertising only `unsigned`, and again against one advertising only
  `manual`; omitting `delegationpolicy:` binds `default` rather than leaving
  verification unconfigured.
- **Integration (parentsync testbed):** two child zones under one parent with
  different policies; proxy zone completes bootstrap after operator publishes the
  KEY at the primary, then re-bootstraps on BADKEY without operator action; SVCB
  advertisement matches policy; unpublish removes SVCB + KEY.

---

## 9. Working rules

- GPG-sign every commit; no `Co-Authored-By`/AI byline.
- `build` + `vet` + `-race` green in `v2`, `v2/cli`, `v2/cache`, `v2/edns0`,
  `v2/core`, `v2/debug` before each commit (`GOROOT=/opt/local/lib/go CGO_ENABLED=1`).
- One PR per work item. Implement → commit → push → open PR → **stop**.
- No backwards compatibility, no key aliasing, no dual-format parsing.
