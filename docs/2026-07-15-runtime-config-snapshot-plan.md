# Runtime config snapshot — copy-on-write for reloadable config

**Status:** design for sign-off (no code yet).
**Branch:** own PR off `main` (pre-existing bug; blocks #286).
**Origin:** load-testing #286 surfaced `fatal error: concurrent map read and map
write` crashes. Two hit so far — `NeedsResigning`→viper, and RefreshEngine→
`conf.Internal.DnssecPolicies` — both the same class.

## 1. Problem

`config reload` rewrites shared config (the `conf.Internal.*` maps, and viper's
map via `viper.ReadConfig`) while long-running reader goroutines — the
RefreshEngine and the signer — read it **without synchronization**. Any such
concurrent read vs the reload write is a Go runtime `fatal error` (unrecoverable).

Guarding the *reads* is the wrong model here:
- **Fragile:** every reader must remember to lock; the RefreshEngine forgot, and
  so will the next one.
- **Deadlock hazard:** the RefreshEngine reads these maps *inside* its
  `zd.mu.Lock()` block (refreshengine.go:358–440), while reload takes
  `confMu.Lock()` → `zdp.mu.Lock()`. Adding `confMu.RLock()` under `zd.mu` is a
  lock-order inversion (`zd.mu→confMu` vs `confMu→zd.mu`) → deadlock.

## 2. Principle — guard the write, not the reads

Everything in scope is **written once per reload, read constantly otherwise.**
That is the textbook copy-on-write case: build a new immutable config at reload,
**atomically publish** it (one pointer swap); readers `Load()` and go, lock-free.
Same model as the zone snapshot (#279). `confMu` shrinks to serializing reloads
against each other — it stops gating readers, so the deadlock hazard disappears.

## 3. Design

```go
// RuntimeConfig is an immutable snapshot of all config that is read at RUNTIME
// and can change on reload. Never mutated after publish; reload builds a fresh
// one and swaps the pointer.
type RuntimeConfig struct {
    DnssecPolicies map[string]DnssecPolicy      // copy of conf.Internal.DnssecPolicies
    MultiSigner    map[string]MultiSignerConf   // copy of conf.MultiSigner

    // Scalars currently read from viper at runtime (phase 1 = the racy/hot set):
    MaxRefresh       uint32
    MinRefresh       uint32
    ResignerInterval int    // seconds; replaces the temporary atomic in #286
    PeriodicResign   bool
    ServiceDebug     bool
    // …phase 2 folds in the long-tail viper runtime reads (see §6).
}

// Published pointer + accessor.
var liveConfig atomic.Pointer[RuntimeConfig]

// ConfLive returns the current snapshot, never nil (see §5 first-publish).
func ConfLive() *RuntimeConfig { return liveConfig.Load() }
```

**Build + publish** — a single helper, called under `confMu` at the end of every
reload path:

```go
// buildRuntimeConfig snapshots the just-parsed config into a fresh immutable
// RuntimeConfig. Copies the maps (small) so the snapshot is independent of the
// parse-scratch conf.Internal fields. Must run single-threaded (holds confMu).
func (conf *Config) buildRuntimeConfig() *RuntimeConfig { … }

func (conf *Config) publishRuntimeConfig() { liveConfig.Store(conf.buildRuntimeConfig()) }
```

Note: `conf.Internal.DnssecPolicies` / `conf.MultiSigner` **stay** as parse
scratch (written during parse, read only by `buildRuntimeConfig`, both under
`confMu`). Nothing at runtime reads the plain fields anymore — that keeps the
parse code untouched and the change to readers only. (A later cleanup can delete
the plain fields once no one references them.)

## 4. Publish points

All three reload entry points, plus startup, call `publishRuntimeConfig()` as the
**last** step, under `confMu`:

- **startup** — after the initial `ParseConfig(false)` + `parseDnssecConfig`,
  **before** any engine goroutine starts (so `ConfLive()` is never nil).
- `ReloadConfig` (config.go:564) — after `ParseConfig(true)`.
- `ReloadZoneConfig` (config.go:602) — after `reloadDnssecFromFile` + `ParseZones`,
  before the `confMu.Unlock()` at :662.
- `ReloadZone` (zone_utils.go:1122) — after its `reloadDnssecFromFile`.

Each publishes a fresh, fully-consistent snapshot (all fields from the same
reload epoch — no cross-field skew).

## 5. First-publish / nil-safety

`ConfLive()` must never return nil. Publish an initial snapshot at startup before
engines start. Belt-and-suspenders: a package `init` (or the accessor) seeds
`liveConfig` with a zero-value `&RuntimeConfig{}` so an early reader gets safe
defaults (empty maps, 0 scalars → existing clamps/fallbacks apply) rather than a
nil deref.

## 6. Reader migration

### Phase 1 — crash-critical + hot (this PR)

| Read today | → |
|---|---|
| `conf.Internal.DnssecPolicies[…]` — refreshengine `:274,:276,:414,:618,:621` | `ConfLive().DnssecPolicies[…]` |
| `conf.Internal.DnssecPolicies[…]` — apihandler_zone `:373,:474` (drop `confMu.RLock`) | `ConfLive().DnssecPolicies[…]` |
| `conf.MultiSigner[…]` — refreshengine `:283,:434,:628` | `ConfLive().MultiSigner[…]` |
| `viper.GetInt("service.maxrefresh"/"minrefresh")` — refreshengine `:883,:891` | `ConfLive().MaxRefresh/MinRefresh` |
| `viper.GetBool("service.debug")` — zone_utils `:331` | `ConfLive().ServiceDebug` |
| `viper.GetInt("resignerengine.interval")` — sign.go `NeedsResigning` | `ConfLive().ResignerInterval` (removes the temp atomic from #286 23022bf) |
| `viper.GetInt/GetBool` — resigner.go `:18,:35` | `ConfLive().ResignerInterval/PeriodicResign` |

That set covers both confirmed crashes and the next-in-line (`FindSoaRefresh`).

### Phase 2 — long tail (follow-up, same snapshot)

The remaining runtime viper reads — `delegationsync.*` (`ops_dsync`,
`delegation_utils`, `delegation_sync`, `childsync_utils`, `sig0_utils`,
`zone_utils:793/813`), `keystate.*`, `verifyengine.*`, `scanner.*`,
`validator.*`, `imrengine server.*`, `dnslookup dns.resolvers`,
`dnsutils external.*` — fold into `RuntimeConfig` fields incrementally. They race
too, but fire only during their specific operations, so they can land after the
hot set. **Out of scope permanently:** `v2/cli/*` (separate process) and
startup-only listener/cert reads (`do53/dot/doh/doq`, trust-anchor files).

## 7. confMu

Still serializes reloads and protects the parse. Readers of the snapshotted
values **no longer take it** — which is what removes the RefreshEngine
`zd.mu`↔`confMu` deadlock hazard entirely. API handlers drop their
`confMu.RLock` around `DnssecPolicies` in favour of `ConfLive()`.

## 8. Testing

- **Race regression:** generalise the existing `-race` test — spawn readers doing
  `ConfLive().DnssecPolicies[…]` / `.MaxRefresh` while a writer loops
  `publishRuntimeConfig()`; must be clean under `-race`. (The current
  viper-specific test folds in.)
- **Live:** the exact combined stress that crashed twice (query flood +
  reload-zones storm + config-reload storm, 60s) must **survive**, and a paced
  reload must still advance RRSIG inception.

## 9. Scope / sequencing

One PR off `main` (**runtime-config-snapshot**, phase 1). It **subsumes** the
earlier PR-A (viper sweep) + PR-B (map snapshot) split and folds in the temporary
`NeedsResigning` atomic from #286 (23022bf). Phase-2 long-tail is follow-up PRs
into the same snapshot — and each one deletes a live viper read, i.e. real
progress toward removing viper. #286 waits for phase 1, then rebuilds and re-runs
the load test.

## 10. Open questions

- **Map copy vs move:** phase 1 copies the maps into the snapshot (simple, keeps
  parse code untouched). If the copy ever matters (it won't at these sizes), move
  the freshly-built map straight into the snapshot and drop the plain field.
- **`ReloadTsigConfig`** rewrites TSIG keys, not `RuntimeConfig` fields — no
  publish needed there (confirm nothing runtime-read moved into scope).
- Confirm `SplitAlgorithms`/other `conf.Internal` maps really are parse-only (grep
  showed no engine reads) before relying on that.
