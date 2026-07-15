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

### …and the synchronous sign is also redundant (a double-sign)

`ParseZones` **also** enqueues every zone to `RefreshZoneCh` with `Force: true`
and `ConfigUpdate: true` (`v2/parseconfig.go:1111-1128`), *after* the synchronous
sign. The refresh engine handles each zone in its **own goroutine**
(`v2/refreshengine.go:481`, `go func(...)`) and re-signs there
(`refreshengine.go:512`) — but only inside `if updated` (`refreshengine.go:508`),
and `updated == serialChanged` **even under force** (`v2/dnsutils.go:538-541`:
"If force=true but serial unchanged, return false").

So on reload:

- **Zonefile serial changed** → the refresh path re-signs **and** :995 already
  signed → the zone is signed **twice**.
- **Config-only change** (policy edit / newly-enabled signing, unchanged serial)
  → the refresh path does **not** re-sign (`updated == false`) → only :995 signs.
  So :995 is load-bearing *for the config-only case only*.

That is why the fix (§4) is neither "keep the serial sign off `confMu`" nor "just
delete :995": it is **delete :995 and make the already-async, already-per-zone-
goroutine refresh path do the single re-sign, including the config-only case.**

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

## 3. What must NOT regress

This is **not** a bare delete of `parseconfig.go:995`. The re-sign must still
happen, because a `reload-zones` is exactly how these take effect:

1. **Newly-enabled signing** — `online-signing`/`inline-signing` flipped on in
   config for a previously-unsigned zone → the zone must become signed.
2. **Policy edits picked up on reload** — an edited `dnssec_policy`/KASP block
   must cause a re-sign under the new parameters.

And `SetupZoneSigning`'s guards must be preserved:

- agent no-op (`Globals.App.Type == AppTypeAgent` → return, `zone_utils.go:1089`),
- online/inline gate (`zone_utils.go:1093`),
- `ZoneType != Primary && !OptInlineSigning` → skip (`zone_utils.go:1097`).

So the transformation is **delete the redundant synchronous sign, and let the
single re-sign happen in the refresh path** — which already runs async, per-zone,
off `confMu`.

---

## 4. Mechanism

The refresh path already exists, already runs each zone in its own goroutine
(`v2/refreshengine.go:481`), and is already enqueued for every zone on reload
(`parseconfig.go:1128`). The only reason it does not fully cover reload signing
today is the `if updated` gate. Fix that, drop the synchronous sign.

**Step 1 — delete the synchronous reload sign.** Remove the reload-branch
`zdp.SetupZoneSigning(...)` at `v2/parseconfig.go:994-998`. Keep the
`OnFirstLoad` branch (`:988-993`) unchanged. This alone removes the double-sign
and the confMu-held sign.

**Step 2 — make the refresh path sign on config-reload regardless of serial.**
In the refresh goroutine, the re-sign (`v2/refreshengine.go:512`) currently sits
inside `if updated` (`:508`). Change the sign condition to

```
updated || (zr.ConfigUpdate && (zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]))
```

so a config-bearing reload re-signs even when the SOA serial is unchanged (the
config-only case: policy edit, newly-enabled signing). Keep the **zone-file
write** logic gated on `updated` (do not rewrite an unchanged file). This is the
**same idiom the code already uses two lines below**, where NOTIFY fires on
`updated || force` because "Force typically means config reload-zones"
(`refreshengine.go:549-551`), and catalog re-parse runs "after EVERY successful
refresh (updated or not)" (`:564-566`). Signing is simply the one action that was
left gated on `updated`.

Implementation note: pull the `SetupZoneSigning` call out of the `if updated`
block into its own `if <sign-condition>` so it is invoked **once** (when both
`updated` and `ConfigUpdate` are true, do not sign twice). `zr.ConfigUpdate` is
already carried on the `ZoneRefresher` and captured by the goroutine
(`parseconfig.go:1121`).

**Result:** exactly **one** sign per reloaded signed zone, in the per-zone
refresh goroutine — async, concurrent (not serial), off `confMu`, and strictly
*fewer* signs than today (the serial-changed double-sign is gone too). Guards are
preserved because we still call `SetupZoneSigning` (its agent/Primary/inline
checks are intact).

### Caveats

- **Timing (sync → async).** For the config-only case, signing moves from
  synchronous-before-return to async-in-the-refresh-goroutine. The async path
  already existed for the serial-changed case, and snapshot atomicity (§2) keeps
  serving valid signatures until the new sign lands — so no query-correctness
  issue, only "signed-on-return" is lost. Homework in §7 confirms nothing depends
  on it.
- **Idempotence of the extra sign.** A config reload that changed nothing now
  routes through the refresh-path sign too. That is behavior-preserving vs today
  (the old :995 also signed unconditionally on every reload) — and still only
  *one* sign, vs today's one-or-two.

### Considered and rejected

- **Collect during the locked parse, sign serially after `confMu.Unlock`.**
  Moves the sign off `confMu` but keeps it **serial** and keeps the redundant
  extra sign the refresh path already does — both of the things this PR should
  fix. Rejected.
- **Direct enqueue to `ResignQ` instead of using the refresh path.** `ResignQ`'s
  consumer does a full sign (`resigner.go:50`), but the buffer is 10
  (`main_initfuncs.go:199`) and it bypasses `SetupZoneSigning`'s guards. The
  refresh path is already the right vehicle; no need for a second one.

---

## 5. Companion (DEFERRED — do not drop)

The refresh path forks a goroutine **per zone** (`refreshengine.go:481`) with no
bound — so with this fix, a `reload-zones` over 10^4–10^5 signed zones spawns that
many concurrent `SignZone` calls, each hitting the keystore DB. The
"companion to Finding 4" therefore reframes from *"add parallelism"* to
**"bound and optimize the parallelism the refresh path already has"**:

- a **worker pool** capping concurrent signers (per-zone `zd.mu` already makes
  cross-zone signing safe),
- a per-`zd` **key cache** removing the per-sign keystore DB hit, invalidated by
  any key-set mutation,
- a **same-zone ordering** guarantee (no two sign ops for one zone in flight;
  preserve order).

This is **P2 / deferred per Johan**, tracked in
`2026-07-14-snapshot-branch-signing-findings.md`. It is **not** in PR-F4, but
PR-F4 makes the refresh-engine sign site (`refreshengine.go:481/512`) the single
seam that companion later wraps in a pool.

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
  must poll/wait for the async sign (the refresh goroutine) instead. The
  serial-changed path was already async, so most reload tests should already
  tolerate this; the config-only tests are the ones to check.

---

## 8. Risk / rollback

Small blast radius: two edit sites — delete `parseconfig.go:994-998`, widen the
sign condition at `refreshengine.go:508-512`. Behavioral change: reload signing
becomes async + deduplicated. Rollback = restore the synchronous
`SetupZoneSigning` at `parseconfig.go:995` and revert the refresh-engine
condition. The `-race` suite plus the §6 live matrix (esp. the config-only cases
2 & 3, which are the ones the new refresh condition must cover) are the gate.

## 9. PR slicing

Single PR (**PR-F4**). Order: **PR-CLI → PR-F4 → transactional-policy-reload**.
