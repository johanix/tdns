# PR-F4 — Move config-reload zone signing off `confMu`

**Status:** implementation-ready (one mechanism decision to confirm).
**Sequence:** lands **after PR-CLI**, **before** the transactional-policy-reload
project (`2026-07-15-transactional-policy-reload-plan.md`). This PR is the
"slightly-advanced baseline" that project builds on: once the refresh/resigner
path is the *sole* signer, the policy-reload work never has to touch the
synchronous reload sign.

This closes the code half of **Finding 4** (confMu held across signing) in
`2026-07-14-snapshot-branch-signing-findings.md`. It is orthogonal to persisting
DNSSEC policy — correct on its own merits — and is deliberately shipped and
live-verified in isolation because it is a timing/ordering change on the reload
path (dangerous to get wrong).

---

## 1. The wart

`ReloadZoneConfig` (the `config reload-zones` command) holds the global
`confMu` write lock across the entire zone parse:

- `v2/config.go:600` — `confMu.Lock()`
- `v2/config.go:622` — `conf.ParseZones(ctx, true)` runs **under that lock**
- `v2/config.go:662` — `confMu.Unlock()` (before the post-parse hook)

Inside `ParseZones`, for every zone with signing enabled, on the **reload**
branch:

- `v2/parseconfig.go:995` — `zdp.SetupZoneSigning(conf.Internal.ResignQ)`

`SetupZoneSigning` (`v2/zone_utils.go:1088`) does a **synchronous full
`SignZone`** (`v2/zone_utils.go:1102`, `SignZone(kdb, false)`) and only then
enqueues the zone onto `ResignQ` for the periodic ticker. So a `reload-zones`
serially runs every signed zone's full re-sign **while holding `confMu`**.

Queries are unaffected (they read the lock-free published snapshot), but
everything that takes `confMu` is stalled for the whole reload: the zone API
handlers and policy resolution (`v2/apihandler_zone.go:372`, `:473`,
`:221`), TSIG reconcile, etc. On a server with many signed zones — the PQ
testbed direction is 10^4–10^5 zones — a reload becomes a long global stall
proportional to *total* signing work.

### …and the synchronous sign is entirely redundant

`ParseZones` **also** enqueues every zone to `RefreshZoneCh` with `Force: true`
and `ConfigUpdate: true` (`v2/parseconfig.go:1111-1128`), *after* the synchronous
sign, and the RefreshEngine already re-signs on reload through **two** off-lock
paths:

1. **Policy / config change — `triggerResign` (`v2/refreshengine.go:442-453`).**
   When it processes a config-bearing refresher it rebinds the DNSSEC policy via
   `applyReloadedPolicyLocked`, which returns `true` for **every** non-alg-
   changing rebind (`refreshengine.go:200`), setting `reapplyPolicy` and calling
   `triggerResign(conf, zone)` → `ResignQ` → a full `SignZone`. Because a signed
   zone **must** have a policy (a signing option without a policy is dropped and
   the zone goes to ERROR — `v2/sample_config_test.go:116`), this fires for
   **every signed zone on every reload**. It also carries the alg-refuse guard:
   an incompatible algorithm change returns `false`, so the zone correctly does
   **not** re-sign and keeps its existing valid signatures.
2. **Zone-data change — the post-refresh sign (`refreshengine.go:512`), inside
   `if updated`.** `updated == serialChanged` even under force
   (`v2/dnsutils.go:538-541`), so this covers a changed zonefile.

So on reload a signed zone is currently signed by **:995 (synchronous, under
`confMu`) *plus* `triggerResign` (452) *plus*, if the serial changed, 512** — up
to a triple sign. The synchronous :995 sign is pure redundancy on top of the
refresh path. The fix (§4) is therefore simply to **delete :995**; 452 (policy
changes) and 512 (data changes) already own every reload re-sign, off `confMu`.

### Scope is narrow

- Only `config reload-zones` (`ReloadZoneConfig` → `ParseZones`) hits the sign
  loop. `config reload` (`ReloadConfig` → `ParseConfig`, `v2/config.go:561`)
  does **not** call `ParseZones` — confirmed — so it is out of scope.
- **Initial load** signs via the deferred `OnFirstLoad` hook
  (`v2/parseconfig.go:988-993`), a different path. **Keep it unchanged.**
- Only the **reload** branch (`v2/parseconfig.go:994-998`) is the target.

---

## 2. Why this is safe *now* (post-snapshot merge)

This is the key argument, and the reason the removal is safe today in a way it
might not have been before #279:

**Snapshot atomicity already covers the window.** On reload of an *existing*
signed zone, the previously-published (validly-signed) `zoneSnapshot` keeps
serving every query until the async re-sign completes and atomically swaps in
the new snapshot. No query ever observes a torn or unsigned state — even though
the sign no longer happens synchronously under the reload lock. Brand-new zones
added at reload still go through `OnFirstLoad` (kept), so their first sign is
unchanged.

That is the specific thing the live test must confirm (§6): reload under query
load produces **no** SERVFAIL / bogus window.

---

## 3. What must NOT regress — every reload re-sign is still covered

The re-sign must still happen on reload; deleting :995 is safe only because the
refresh path already covers every case. Walking the scenarios for a signed zone
(all have a policy):

| reload scenario | still re-signs? | via |
|---|---|---|
| nothing changed | yes | `triggerResign` (452) — `applyReloadedPolicyLocked` returns true on any non-alg rebind |
| policy internals changed (same alg) | yes | `triggerResign` (452) |
| policy algorithm changed | **no — correct** | `applyReloadedPolicyLocked` returns false; old policy + valid sigs kept (alg rollover not built) |
| zonefile serial changed | yes | post-refresh sign (512, `updated == true`) |
| signing newly enabled | yes | `triggerResign` (452) — the policy binds (nil→policy) |

Guards are preserved because the surviving paths still funnel through
`SetupZoneSigning` / `resignNow`, which keep the agent no-op and the
online/inline gate.

---

## 4. Mechanism — delete the synchronous reload sign

**Delete the reload branch at `v2/parseconfig.go:994-998`** (the
`else { zdp.SetupZoneSigning(...) }`), keeping the `OnFirstLoad` branch
(`:988-993`) unchanged. That is the entire code change. The refresh engine's
`triggerResign` (452, policy/config changes) and post-refresh sign (512, data
changes) already re-sign every reloaded signed zone, asynchronously and off
`confMu` (§1, §3).

Net effect: reload signing drops from up to **triple** (995 + 452 + 512 on a
serial change) to at most double, and from double to single on a config-only
change — while removing the one sign that ran under `confMu`.

### Caveat — timing (sync → async)

For every reload case, signing moves from synchronous-before-return to
async-in-the-refresh-path. That async path already existed (452/512); snapshot
atomicity (§2) keeps serving valid signatures until the new sign lands, so there
is no query-correctness window — only "signed-on-return" is lost. §7 confirms
nothing depends on it.

### Residual (pre-existing, out of scope)

On a serial-changed reload, 452 (`triggerResign`) **and** 512 (`updated`) both
fire — a double sign. This exists today independent of this change, so PR-F4 does
not address it; deduping the two refresh-path triggers belongs with the deferred
pipeline cleanup (§5).

### Considered and rejected

- **Widen the `if updated` gate at 512 to also fire on `ConfigUpdate`** (an
  earlier draft of this plan). Unnecessary and wrong: `triggerResign` (452)
  already re-signs the config-only case, so widening 512 would *add* a redundant
  sign, not remove one.
- **Collect during the locked parse, sign serially after `confMu.Unlock`.**
  Keeps signing serial and keeps the redundant refresh-path sign — fixes neither
  problem.
- **Replace :995 with `triggerResign(conf, zname)` in `ParseZones`.** Works, but
  duplicates the `triggerResign` the refresh engine already issues at 452 for the
  same zone — a self-inflicted double enqueue. Deleting is cleaner.

---

## 5. Companion (DEFERRED — do not drop)

With :995 gone, the reload re-sign for a policy/config change flows through
`triggerResign` → `ResignQ` → the **`ResignerEngine`**, which drains the queue
**serially** and whose buffer is only **10** (`main_initfuncs.go:199`); a full
queue drops the request with a warning (`key_state_worker.go:420`), deferring
that zone to the periodic ticker. So over 10^4–10^5 signed zones a `reload-zones`
is bounded by one serial signer and a tiny queue — the real remaining scaling
limit (it is pre-existing: `triggerResign` at 452 already behaves this way; this
PR just stops *also* signing synchronously under `confMu`).

The "companion to Finding 4" therefore reframes to **"give the reload re-sign a
real parallel signer"**:

- a **worker pool** draining a larger resign queue (per-zone `zd.mu` already
  makes cross-zone signing safe to run concurrently),
- a per-`zd` **key cache** removing the per-sign keystore DB hit, invalidated by
  any key-set mutation,
- a **same-zone ordering** guarantee (no two sign ops for one zone in flight;
  preserve order),
- and, while there, dedupe the 452/512 double-trigger (§4 Residual).

This is **P2 / deferred per Johan**, tracked in
`2026-07-14-snapshot-branch-signing-findings.md`. It is **not** in PR-F4, but
PR-F4 leaves the `ResignerEngine`/`ResignQ` as the single seam that companion
later replaces with a pool.

---

## 6. Test plan

**Static:** `GOROOT=/opt/local/lib/go` build of `v2` + `v2/cli`; full `v2` test
suite; `-race` green.

**Live** (axfr.net testbed / local auth with signed zones):

1. **No stall / no bogus window (the core win):** drive a sustained UDP+TCP
   query flood at a signed zone, issue `config reload-zones`, and confirm (a)
   zero SERVFAIL / bogus answers throughout, (b) query latency does **not** spike
   for the reload duration (contrast: today it stalls on `confMu`).
2. **Newly-enabled signing:** add `online-signing` to a previously-unsigned zone
   in config → `config reload` + `config reload-zones` → zone is now signed
   (DNSKEY + RRSIGs present, `dog +sigchase` validates).
3. **Policy edit on reload:** change a zone's `dnssec_policy` in config →
   reload → zone re-signed under the new policy (RRSIG algorithm/params change).
4. **Scale:** hundreds–thousands of signed zones → `reload-zones` → server stays
   responsive to queries for the entire reload (measure; this is the regression
   this PR exists to fix).

**Two-step reload reminder:** verification requires both `auth config reload`
**and** `auth config reload-zones`.

---

## 7. Homework (Finding-4 checklist)

Signing moves sync → async for the config-only case, so this **must** be audited
(it is not free-by-construction anymore):

- `ReloadZoneConfig`'s response string (`v2/config.go:668`) — make no claim that
  contradicts async signing.
- grep tests for `reload`/`reload-zones` followed by an immediate RRSIG assertion
  that assumes the zone is signed the instant the command returns. Any such test
  must poll/wait for the async sign (`triggerResign` → `ResignerEngine`) instead.
  The serial-changed path was already async, so most reload tests should already
  tolerate this; the config-only tests are the ones to check.

---

## 8. Risk / rollback

Minimal blast radius: **one edit site** — delete the reload branch at
`parseconfig.go:994-998`. No refresh-engine change (`triggerResign`/512 already
own the reload re-sign). Behavioral change: reload signing becomes async, and
the redundant confMu-held sign is gone. Rollback = restore the synchronous
`SetupZoneSigning` at `parseconfig.go:995`. The `-race` suite plus the §6 live
matrix (esp. the config-only cases 2 & 3 — a policy edit / newly-enabled signing
on an unchanged serial, which now rely entirely on `triggerResign` at 452) are
the gate.

## 9. PR slicing

Single PR (**PR-F4**). Order: **PR-CLI → PR-F4 → transactional-policy-reload**.
