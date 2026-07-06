# First-class TSIG keystore — punch-list (open issues) (2026-06-30)

Actionable follow-ups from the full-project evaluation
([…-plan-eval.md](./2026-06-29-first-class-tsig-keystore-plan-eval.md)) of branch
`feat/tsig-first-class` @ `19e1aa7`. The feature is complete, builds, and passes tests
with `-race`; these are **hardening + test-pinning** items, none blocking.

IDs match the eval. Check items off as they land; keep one commit per item (or per
small cluster) on `feat/tsig-first-class`, GPG-signed.

## Code — High / Medium (do in this order)

- [x] **H1 (High) — add `--secret-file` to `keystore tsig add`.**
  _Where:_ `v2/cli/keystore_cmds.go:74,78`.
  _Action:_ add a `--secret-file` flag that reads a base64 secret from a file (reuse
  `resolveTsigSecret`, `v2/cli/zone_cmds.go:446`); keep `--secret`; drop the
  unconditional `MarkFlagRequired("secret")` and instead require **exactly one** of
  `--secret` / `--secret-file`; add the "visible in shell history / process list;
  prefer --secret-file" WARNING to `--secret`'s help (as `zone_cmds.go:176` does).
  _Done when:_ `add --secret-file f` works, `--secret` still works, both-or-neither
  errors clearly, and the secret is no longer forced onto the process arg list.
  (Satisfies the additive-hardening rule: add the secure path, don't remove the flag.)

- [x] **M1 (Med) — add a TTY guard to every interactive path.**
  _Where:_ `v2/cli/keystore_cmds.go:242,298` (import/purge), `v2/cli/config_cmds.go`
  (`reload-tsig --interactive`).
  _Action:_ before any prompt loop, check `term.IsTerminal(int(os.Stdin.Fd()))`
  (already imported at `v2/cli/interactive.go:129`); if not a TTY, error
  ("`--interactive` requires a terminal"). For `purge --force` without `-y` in a
  non-TTY, require `-y` (error, don't fall into `fmt.Scanln`-on-EOF).
  _Done when:_ `--interactive` over a pipe errors clearly (no silent no-op); non-TTY
  `purge --force` without `-y` errors; with `-y` it proceeds.

- [x] **M2 (Med) — import extractor: ignore comments.** (pair with **TC-H3**)
  _Where:_ `v2/tsig_import.go:16-18` (BIND regexes), `:69-97` (NSD line loop).
  _Action:_ strip comments before/within extraction — BIND `//`→EOL, `#`→EOL,
  `/* … */` blocks; NSD `#`→EOL incl. trailing. A commented-out `key {…}`/`key:` block
  must be ignored, and a commented `algorithm`/`secret` line must not shadow the real
  one (today first-match wins). Consider case-insensitive `key` keyword (BIND).
  _Done when:_ commented input is ignored in both formats; the "wrong algorithm from a
  comment" case is fixed; the `tsig-keygen` happy path still passes.

- [x] **M3 (Med) — `config reload-tsig` (CLI) exits non-zero when items are withheld.**
  _Where:_ `v2/cli/config_cmds.go` (CLI-side only).
  _Action:_ when the response carries withheld items (`resp.TsigConflicts` /
  `TsigWithheldRemovals` non-empty), make the CLI exit non-zero even with no Go-level
  error; print a clear "N withheld" summary. The HTTP API returning **200 + conflict
  arrays** is acceptable REST and need not change; optionally set `resp.Error`/a non-2xx
  for withhold-only outcomes if preferred.
  _Done when:_ a default `config reload-tsig` that withholds anything exits non-zero;
  a clean reload exits 0.

- [x] **M5 (Med) — interactive import: separate a hard error from a conflict-withhold.**
  _Where:_ `v2/cli/keystore_cmds.go:229`.
  _Action:_ enter the prompt loop only when the probe indicates conflicts
  (`Error && len(conflict dispositions) > 0`); on a transport/parse error, print the
  real `resp.ErrorMsg` and exit non-zero.
  _Done when:_ a malformed/unreadable import file shows the actual error, not
  "No keys overwritten."

- [x] **M4 (Med) — align the `APIkeystore` lock order with the reconcile discipline (or document).**
  _Where:_ `v2/apihandler_funcs.go:36→97`. Note: §4 does **not** literally mandate
  handler lock order — this is alignment/polish, **not** a plan violation.
  _Action (preferred):_ acquire `confMu` **before** `kdb.Begin` on the `tsig-mgmt`
  (and `reload-tsig`) path, keeping the tx short, so it matches the reconcile path's
  `confMu`→`Begin` order. _Or:_ keep the order and document the accepted divergence
  + that a concurrent reload may get a retryable "transaction already in progress."
  Consider guarding the pre-existing `db.Ctx` race (`v2/db.go:65`).
  _Done when:_ concurrent reload + `tsig-mgmt` no longer produces spurious errors, or
  the accepted divergence is written down.

- [x] **M6 (Med) — thread the open `tx` into `list`/`purge` reads.**
  _Where:_ `v2/tsig_keystore_mgmt.go:53,291`.
  _Action:_ pass the handler `tx` to `listTsigKeystore` (it already accepts the querier
  interface) for both `list` and `purge`, so the candidate read shares the tx snapshot;
  enumerate-and-delete `purge` candidates within the one tx.
  _Done when:_ neither path queries `kdb.DB` while the handler tx is open.

## Code — Low / optional

- [ ] **L — reject too-short HMAC secrets** in `validateTsigKeySpec`
  (`v2/tsig_keys.go:238`): enforce a minimum decoded length per algorithm on
  `add`/`import` (generate is already correctly sized). *Deferred: test fixtures use
  16-byte secrets throughout.*
- [x] **L — unify effective-owner resolution:** make `tsigConfigEffectiveOwner`
  (`v2/tsig_keys.go:127`) derive its default from origin rather than the literal
  `"config"`, so it can't diverge from `tsigKeystoreEffectiveOwner`
  (`v2/tsig_keystore.go:101`).
- [x] **L — `ParseTsigKeys` should warn on dropped keys** (`v2/tsig_utils.go:14`):
  surface (log) the discarded `firstErr` so an operator learns a `tdns-cli.yaml` key
  was skipped as invalid.
- [x] **Nits:** ignored error in inline rollback closure (`v2/dynamic_zones.go:666` —
  add a comment or log); `purge -y` without `--force` is a silent no-op (usage hint);
  `setowner`/`delete` accept a legacy `Keyname` fallback the CLI never sends; misnamed
  `TestTsigKeyMgmtImport_ForceAndUnchanged`.

## Tests — High (pin the safety invariants)

- [x] **TC-H1 — case-2 "no `--force` escape".** Assert that a config key removed from
  YAML but still referenced is withheld **even with** `TsigReconcileOptions{Force:true}`
  (`v2/tsig_reconcile.go:126` ignores `Force` in the removal branch — lock it in).
- [x] **TC-H2 — refcount breadth + dedup.** Add tests for `Upstreams`, `Notify`,
  `AllowNotify` references (currently only `PrimariesConf`/`Downstreams`/catalog), and a
  test that the **same key in `Upstreams` and `PrimariesConf` of one zone counts once**
  (guards `zoneDataReferencesTsigKey`'s per-zone semantics).
- [x] **TC-H3 — import comment handling** (pairs with **M2**): feed `//`/`#`/`/* */`-
  commented BIND blocks and `#`-commented NSD lines; assert they're ignored and the real
  key's algorithm/secret win. (Write the test first — it should fail until M2 lands.)
- [x] **TC-H4 — CLI/TTY layer** (`v2/cli/` currently has no `_test.go`): cover
  `--force`/`--interactive` mutual exclusion, exit codes (incl. M3), and non-TTY
  behaviour (M1). Needs minimal CLI test scaffolding.

## Tests — Medium / Low

- [x] **TC-M1** — assert identical-secret `api`→`config` promote-on-reload (quiet
  ownership takeover) and that an identical config key yields an empty cache delta.
- [x] **TC-M2** — inline rollback should assert the **DB row** is gone
  (`getTsigKeystoreByName` → `ErrNoRows`), not just the cache.
- [x] **TC-M3** — reserved-name (`NOKEY`/`BLOCKED`) rejection on the `generate` /
  `import` / `migration` paths.
- [x] **TC-M4** — migration: read back the row metadata (`origin=api, owner=api,
  creator=dynamic-config-migration`); optionally a post-commit rewrite-failure test.
- [x] **TC-M5** — `--force`/`--interactive` mutual-exclusion guard.
- [x] **Nits:** make the migration keys-block assertion robust (don't rely on a leading
  `\n` in `strings.Contains(data, "\nkeys:")`); note that `GenerateTsigSecret`'s test
  checks length only (can't catch a low-entropy RNG regression).

## Explicitly out of scope (deferred per plan §16 — not punch-list items)
mTLS for the CLI; plaintext secrets at rest in SQLite (consistent with SIG(0)/DNSSEC);
the `--comment` flag; the documented low-severity refcount delete TOCTOU.
