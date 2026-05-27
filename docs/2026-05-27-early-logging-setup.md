# Early logging setup

Date: 2026-05-27
Status: PLAN — implementation in branch `early-logging-setup`.

## Motivation

`tdns.SetupLogging` currently runs *after* `conf.ParseConfig`, which
means every `lg.Info` / `lg.Warn` / `lg.Error` call issued from
inside `ParseConfig` (or any hook it fires —
`PostParseConfigHook`, `PostValidateConfigHook`) goes to slog's
default handler. The file handler is not yet wired, so on NetBSD
daemons (where stderr is typically discarded) those log lines are
**lost**.

Workarounds for this have leaked into the codebase. The clearest
example is `RegisterShadowMpConfigParser` in
`tdns-mp/v2/shadow_mp_config.go`, which deliberately stashes its
result on the config and defers all logging to a separate
`EmitShadowMpComparison` that runs *after* `SetupLogging`. Other
parse-time errors are silently downgraded to `fmt.Errorf` returns or
disappear into stderr.

This is a real cost: every parse-time validation, hook, or
sanity-check has to navigate the chicken-and-egg of "I'd like to
log this, but I can't yet."

## The chicken-and-egg

- `SetupLogging` needs the `log:` section of the config file.
- `log:` is parsed by `ParseConfig`.
- `ParseConfig` (today) calls `lg.Debug`/`lg.Warn` internally, plus
  fires hooks that want to log.

The dependency cycle is only apparent. `log:` is a leaf section
with three fields (`file`, `level`, `subsystems`). Nothing else in
the config file influences how logging is set up. So we can parse
just the `log:` subtree of the config file *first*, set up
logging, then run the full `ParseConfig` with logging live.

## Design

### New ordering inside `MainInit`

```
flag.Parse()                                  # already there: sets conf.Internal.CfgFile
SetupLogging(conf.Internal.CfgFile)           # NEW: reads only log: section
err := conf.ParseConfig(false)                # now runs with logging live
... rest of MainInit ...
```

### `SetupLogging` signature change

Before:

```go
func SetupLogging(logfile string, logConf LogConf) error
```

After:

```go
func SetupLogging(cfgfile string) (LogConf, error)
```

It now reads the config file itself, extracts the `log:` subtree,
applies it, and returns the parsed `LogConf` so callers can stash
it if they wish. (For the single caller in `MainInit`, the later
full `ParseConfig` will re-populate `Conf.Log` from the same input,
so no explicit stashing is needed.)

### Focused parser

```go
type rawLogConfig struct {
    Log *LogConf `yaml:"log"`
}

func parseLogConfFromFile(cfgfile string) (LogConf, error) {
    data, err := os.ReadFile(cfgfile)
    if err != nil {
        return LogConf{}, fmt.Errorf("read config %q: %w", cfgfile, err)
    }
    var raw rawLogConfig
    if err := yaml.Unmarshal(data, &raw); err != nil {
        return LogConf{}, fmt.Errorf("parse log section of %q: %w", cfgfile, err)
    }
    if raw.Log == nil {
        return LogConf{}, fmt.Errorf(
            "no log: section found at the top level of %q\n\n"+
                "  The log: block is REQUIRED and MUST live at the top level\n"+
                "  of the main config file. It cannot be hidden inside an\n"+
                "  included file — SetupLogging runs before include\n"+
                "  resolution, so an included log: block would be invisible\n"+
                "  and logging would silently fall back to defaults.\n\n"+
                "  Move the log: block into %q and retry.",
            cfgfile, cfgfile)
    }
    if raw.Log.File == "" {
        return LogConf{}, fmt.Errorf(
            "log.file is empty in %q (log: section was found but log.file is required)",
            cfgfile)
    }
    return *raw.Log, nil
}
```

This parser does **not** call `processConfigFile` — it does not
resolve `!include` directives or templates. The `log:` block MUST
live at the top level of the main config file; if the early parse
doesn't find it there, startup fails with the explicit error above.

Rationale: silently falling back to defaults when the `log:` block
hides in an include would mean a misconfiguration produces no
logging *and* no error — exactly the failure mode we are trying to
eliminate. The hard-fail is loud, the message tells the operator
exactly what's wrong, and the constraint matches existing
operational convention.

The `LogConf` field is `*LogConf` (pointer) specifically so we can
distinguish "no `log:` section at all" from "`log:` section present
but with zero-valued fields." A non-pointer field would yaml-decode
to a zero `LogConf{}` in either case, hiding the difference.

### Viper removal in this path

The current code reads `log.file` from viper:

```go
logfile := viper.GetString("log.file")
err = SetupLogging(logfile, Conf.Log)
```

`viper.GetString` is the only viper call in the `MainInit` startup
path that we can remove cheaply. The new `SetupLogging` reads
directly from the YAML file via `yaml.Unmarshal`, so the path no
longer depends on viper at all. This is a small but concrete step
toward the broader viper-removal direction
(see `tdns-mp/docs/2026-05-26-viper-removal-analysis.md`).

The `viper.ReadConfig` call inside `ParseConfig` itself is
unaffected by this change — it remains for non-log keys until the
broader viper-removal work tackles it.

## Error visibility

There are exactly three error paths during early startup, all
surfaced to stderr+exit because logging is not yet live:

1. **Config file missing / unreadable / not valid YAML.** Print to
   stderr and exit non-zero.
2. **`log:` block missing from top level of config file** (the case
   the focused parser explicitly handles). Print the multi-line
   "log: is mandatory" message to stderr and exit non-zero. No
   silent fallback to defaults.
3. **`log:` block present but `log.file` empty.** Print to stderr
   and exit non-zero.

```go
if err != nil {
    fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
    os.Exit(1)
}
```

All three are irreducible edges — logging cannot exist yet, so
stderr is the only output channel. But they are *concrete and
loud*: every one of them tells the operator exactly which thing to
fix. Compared to today, where a misconfigured `log:` block can
silently produce a daemon with no logging, this is a strict
improvement.

Everything after these three pre-conditions has logging live.
Errors during `ParseConfig`, validation, hooks all land in the
logfile as normal `lg.Error` / `lg.Warn` calls. The stash-and-defer
pattern in `RegisterShadowMpConfigParser` can be deleted; hooks can
log freely.

## Reload path

`conf.ParseConfig(true)` is called from `Shutdowner` / SIGHUP. The
proposal does not change reload semantics — `SetupLogging` is not
re-invoked on reload today, and this change preserves that. If a
future change wants `log:` modifications to take effect on reload,
it can call `parseLogConfFromFile` from the reload path too. Out
of scope here.

## CLI tools

CLI binaries that go through `SetupCliLogging` (writes to stderr)
are unaffected — this design only touches the `SetupLogging`
codepath used by daemons.

CLI binaries that use `MainInit` are affected positively: they get
the same earlier-logging behavior.

## Migration risks

- **Single caller in tdns/v2** (`main_initfuncs.go:138`). Easy to
  update.
- **No callers in tdns-mp.** tdns-mp's `MainInit` delegates to
  `tdns.MainInit` for logging setup, so the change is transparent
  to tdns-mp.
- **Sibling repos that vendor or duplicate `SetupLogging`**
  (`tdns-fast-roller-mldsa44/v2/logging.go`). Out of scope for
  this branch — those repos handle their own logging-setup
  refactor when they catch up.
- **Behavior change: `lg.Debug("MainInit starting", ...)` now
  appears in the logfile** instead of being lost. That's the whole
  point, but it does mean operators may see one new debug line
  per startup. Not a regression.

## Knock-on benefits

After this lands:

- The MP config cutover's Bite 8 can simply return errors from the
  `PostParseConfigHook` instead of the stash-and-defer dance. The
  `EmitShadowMpComparison`/`MpConfigParseErr` machinery becomes
  pure cleanup.
- `Shutdowner` no longer needs to double-output (`lgConfig.Info` +
  `fmt.Printf`) during early errors — `lgConfig.Info` works.
- Any future parse-time hook in tdns or downstream packages can
  log normally.

## Scope

- New: `parseLogConfFromFile` in `logging.go`.
- Changed: `SetupLogging` signature + body.
- Changed: `MainInit` in `main_initfuncs.go` — reorder, drop viper
  call.
- Removed: nothing yet. (Bite 8 of the MP cutover removes the
  stash-and-defer in tdns-mp once this lands.)

Estimated diff: ~50-80 lines.

## Verification

1. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — all tdns
   binaries build clean.
2. `cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make` — tdns-mp
   builds clean against the new signature (the call chain goes
   through `tdns.MainInit`, so tdns-mp doesn't see the signature
   directly).
3. Operator test: start a daemon, confirm `log:` section is honored
   identically to before, confirm a deliberately-broken config
   reports the error to stderr (instead of failing silently).
