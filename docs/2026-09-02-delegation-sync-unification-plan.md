# Implementation plan — unify the delegation-sync child paths and config

**Status:** ready for review. Design proposal + sliced work items; no code written yet.
**Base:** branch off `main`. Work in the **`v2/` tree only**.
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
compatible with every bootstrap method. The operator re-enters only for the
initial publication and for key rollover, both being the same step.

---

## 2. Non-goals

- No change to the NOTIFY or API schemes beyond what falls out of sharing the plan layer.
- No change to `updatepolicy.zone.*` (the self/sub RRtype policy) — only the
  `child.keybootstrap` member moves, because it is delegation-bootstrap policy.
- No IANA codepoint changes (still Phase 3 of the alignment plan).
- Not implementing D-6/D-7/D-3b here. This plan makes them small; it does not do them.

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

3. **Two verification engines with separate retry configs.**
   `TriggerChildKeyVerification` (`v2/truststore_verify.go:185`) reads the typed
   `key-verification.*`; `KeyBootstrapper`/`VerifyKey` (`v2/keybootstrapper.go`)
   still reads raw `viper.GetInt("verifyengine.attempts")` at `:88,158` and
   `verifyengine.retry_interval` at `:141` — the last viper readers in this area,
   contradicting the "single typed reader, no viper" contract that
   `DelegationSyncConf` documents for itself (`v2/config_delegationsync.go:16-36`).

Plus a documentation defect: `cmdv2/auth/tdns-auth.sample.yaml:275-281` tells
operators the real knobs are `keystate.require_manual_bootstrap` and
`keystate.allow_auto_bootstrap`. Neither string is read anywhere in `v2/` or
`cmdv2/`.

On the child side there is **no** bootstrap-method setting at all, which is where
D-6's needed field has to go.

---

## 4. Proposed config

Two established patterns exist in this codebase for per-zone variation: a
**named policy referenced by name** (`dnssecpolicy: <name>` → `dnssec.policies.*`)
and an **inline per-zone struct gap-filled by zone templates** (today's
`updatepolicy:`). This proposal uses the named-policy pattern for the parent
side, because bootstrap policy is security policy: a small set of named,
reviewable policies is easier to audit than per-zone hand-rolled ones, and it
decouples the policy from the zone list while still working through templates
(a template can set the reference). The inline+templates alternative is viable
and needs no new machinery — noted in §7 as the decision to confirm.

Per the project's no-backwards-compatibility rule, this is a clean config break:
no aliasing of the old key names, no dual-format parsing.

```yaml
delegationsync:

   # ---- PARENT SIDE: named policies, referenced per-zone --------------------
   # A zone selects one with `delegationpolicy: <name>`, exactly as it selects
   # a DNSSEC policy with `dnssecpolicy: <name>`. A zone that names none gets
   # `default`.
   policies:
      default:
         bootstrap:
            # WHERE to look for the child's KEY, in try order.
            #   at-apex — the child's apex KEY RRset
            #   at-ns   — consistent across the child's NS set
            # Empty means no automatic bootstrap at all.
            mechanisms:      [ at-apex, at-ns ]
            # HOW strongly to trust what is found. true: the lookup must be
            # DNSSEC-validated. false is what the draft calls "unsigned".
            require-dnssec:  true
            # Whether an operator may install trust out of band. Independent of
            # the above: a policy may allow both automatic and manual.
            manual:          false
            retry:
               max-attempts: 3
               interval:     60s

      permissive:
         bootstrap:
            mechanisms:      [ at-apex, at-ns ]
            require-dnssec:  false          # advertises "unsigned"
            manual:          true
            retry: { max-attempts: 5, interval: 30s }

      locked-down:
         bootstrap:
            mechanisms:      [ ]            # nothing automatic
            manual:          true           # advertises "manual" only

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
            # Default when absent: [ at-apex, at-ns ] — `unsigned` must be
            # opted into, because this decides how strongly the parent will
            # have checked the key that authorises everything else.
            methods: [ at-apex, at-ns ]
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

A parent therefore cannot advertise what it will not do, and a zone with a
stricter policy than its siblings advertises accordingly.

### 4.2 Removed keys

`delegationsync.parent.bootstrap.methods`; `delegationsync.parent.update.key-verification.*`
(folded into the named policy); `updatepolicy.child.keybootstrap`;
`verifyengine.attempts`; `verifyengine.retry_interval`; and the stale sample-config
note naming `keystate.require_manual_bootstrap` / `keystate.allow_auto_bootstrap`.

---

## 5. Work items

Sliced so each is separately reviewable and separately revertable. Ordered by
dependency; U-1 and U-2 are independent of the config work and can go first.

### U-0. Fix the `dsKnown` inference bug — [#468](https://github.com/johanix/tdns/issues/468)
Independent of everything below and already filed. Do it first, on its own, so
the correctness fix is reviewable against today's code rather than buried in a
refactor.
- **Change:** `ProxyUpdateParent` calls `CreateChildReplaceUpdateWithDS` with
  `dsKnown` derived from `zoneLooksSigned(zd)` (`v2/zone_delta_replay.go:299`).
- **Acceptance:** a proxied zone that drops its DNSKEYs removes the parent's DS.
- **Est.** ~30-60 LOC.

### U-1. One UPDATE sender
- **Change:** collapse `SyncZoneDelegationViaUpdate` and `ProxyUpdateParent` into a
  single sender taking `(ctx, kdb, imr, syncstate DelegationSyncStatus, target *DsyncTarget, mode string)`.
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
- **Rename** `proxyUpdateKeyState()` (`v2/delsync_proxy_update.go:121`) — it is the
  state of the agent's SIG(0) key, unrelated to the draft's KeyState option, and
  in this codebase that collision is a trap.
- **Acceptance:** a proxy zone whose KEY is at the apex completes a self-signed
  bootstrap and re-bootstraps on BADKEY without operator action.
- **Est.** ~250-400 LOC.

### U-3. Named parent-side delegation policies
- **Change:** add `delegationsync.policies.*` and the per-zone `delegationpolicy:`
  reference; bind it on the zone the way `dnssecpolicy` binds. Move
  `key-verification.*` and `updatepolicy.child.keybootstrap` into it and delete both.
- **Acceptance:** two zones on one parent with different policies bootstrap
  differently; config naming an unknown policy fails at parse (fail closed).
- **Est.** ~300-500 LOC.

### U-4. Derive the SVCB advertisement from policy
- **Change:** implement the §4.1 mapping; `PublishDsyncRRs` uses the zone's bound
  policy. Delete `parent.bootstrap.methods`. Extend `UnpublishDsyncRRs`
  (`v2/ops_dsync.go:387-431`) to remove the bootstrap SVCB and receiver KEY, which
  it does not do today.
- **Acceptance:** advertisement matches policy for every row of the §4.1 table;
  unpublish removes what publish added.
- **Est.** ~150-250 LOC.

### U-5. One verification engine config
- **Change:** migrate `keybootstrapper.go` off viper onto the typed policy
  (`verifyengine.attempts` / `retry_interval` → `policy.bootstrap.retry.*`),
  removing the last viper readers in this block. Decide whether the two engines
  merge or keep two engines on one config — see §7.
- **Acceptance:** no viper read remains under `delegationsync`/`verifyengine`;
  one retry config governs both.
- **Est.** ~200-350 LOC.

### U-6. Sample config and docs
- **Change:** rewrite the `delegationsync:` block per §4; delete the stale
  key-bootstrap note at `tdns-auth.sample.yaml:275-281`; document
  `delegationpolicy:` in the templates sample.
- **Est.** ~100-150 LOC.

**Total: ~1230-2060 LOC**, a large fraction of it deletion.

---

## 6. What this unblocks

With one child path and one config, the remaining alignment-plan items shrink
to roughly what their original estimates assumed:

- **D-6** becomes "add `child.update.bootstrap.methods` (U-3 already built the
  child block), look up the SVCB at the DSYNC target, intersect, pick" — one
  site, not two. The scope question about the proxy role dissolves: both roles
  read the same field.
- **D-7** becomes "verify the receiver's signature at one call site." Today the
  KeyState inquiry is consumed at three (`QueryParentKeyState`,
  `QueryParentKeyStateDetailed`, `KeyDB.UpdateKeyState`) with no verification at
  any; done after U-1/U-2 there is one path to harden. Note the inquiry travels
  over plain UDP (`dns.Client{}` with no `Net`, `v2/parentsync_bootstrap.go:169,219`),
  so this remains the highest-value remaining item.
- **D-3b**'s NS/glue acceptance check lands on one UPDATE path rather than two.

Done in the other order, each of the three is implemented twice and the #468
pattern repeats.

---

## 7. Decisions to confirm before coding

1. **Named policies vs inline+templates** (§4). Named is proposed; inline needs no
   new machinery. This is the one structural choice in the plan.
2. **Do the two verification engines merge, or share one config?** (U-5). Merging is
   cleaner but larger; sharing config is the minimum that removes the contradiction.
3. **`manual` as an independent flag vs a mechanism** (§4). Proposed as a separate
   boolean, since a policy may sensibly allow automatic *and* manual; folding it
   into `mechanisms` would make that inexpressible.
4. **Default policy name and contents** — proposed `default` with
   `[at-apex, at-ns] + require-dnssec: true`, i.e. strict by default.

---

## 8. Test plan

- **Unit:** the §4.1 derivation table, every row; child/parent method
  intersection including the empty case (must refuse, not degrade); policy
  binding per zone; unknown policy name fails at parse.
- **Regression:** both roles' existing sender tests pass against the unified
  sender unchanged; `dsKnown` behaviour for signed→unsigned on both roles.
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
