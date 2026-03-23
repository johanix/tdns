# Option Handler Registration for Zone Config

**Date:** 2026-03-23
**Status:** Plan

## Problem

The SDE startup hydration loop iterates `Zones.IterBuffered()`
and checks `zd.Options[OptMultiProvider]`. But for secondary
zones, the RefreshEngine may not have processed the zone yet,
so the option is not set on the ZoneData stub. This causes a
race condition where some MP zones are skipped during hydration.

Fixing this by copying options onto stubs earlier would
increase coupling between zone parsing (future tdns repo) and
MP logic (future tdns-mp repo), working against the planned
three-repo split.

## Solution: Option Handler Registration

Extend the zone config parsing to support registered
callbacks for specific zone options. When the parser
encounters a zone option, it calls any registered handler
for that option. This allows tdns-mp to react to
`multi-provider` at parse time without tdns knowing anything
about MP logic.

This follows the same pattern as:
- OnFirstLoad callbacks (zone loading events)
- DNSMessageRouter handlers (message type events)
- Query handler registration (query events)

## Design

### Registry

A global registry of option handlers, keyed by ZoneOption:

```go
// In tdns (e.g., parseconfig.go or a new file option_handlers.go)

type ZoneOptionHandler func(zname string, zconf ZoneConf,
    options map[ZoneOption]bool)

var optionHandlers = make(map[ZoneOption][]ZoneOptionHandler)

func RegisterZoneOptionHandler(opt ZoneOption,
    handler ZoneOptionHandler) {
    optionHandlers[opt] = append(optionHandlers[opt], handler)
}
```

Multiple handlers can be registered for the same option
(append, not replace). Handlers are called synchronously
during ParseZones, in registration order.

### Call Site

In ParseZones, after options are parsed for a zone but
before the ZoneRefresher is sent to RefreshZoneCh:

```go
// After parseZoneOptions returns 'options' for zname:
for opt, val := range options {
    if val {
        if handlers, ok := optionHandlers[opt]; ok {
            for _, handler := range handlers {
                handler(zname, zconf, options)
            }
        }
    }
}
```

This fires synchronously during ParseZones. All registered
handlers complete before the next zone is parsed. No race
with RefreshEngine.

### ZoneConf Parameter

The handler receives the full ZoneConf (zone name, type,
primary, zonefile, options, etc.) so it can make decisions
based on the zone's configuration. This is read-only --
handlers should not modify the ZoneConf.

### tdns-mp Registration

In tdns-mp's init code (before ParseZones is called), the
MP layer registers its handler:

```go
// In tdns-mp init (e.g., main_initfuncs.go StartAgent)
RegisterZoneOptionHandler(OptMultiProvider,
    func(zname string, zconf ZoneConf,
        options map[ZoneOption]bool) {
        // Add to the list of zones needing SDE hydration
        mpZoneList = append(mpZoneList, zname)
    })
```

The `mpZoneList` is then consumed by the SDE hydration
loop instead of `Zones.IterBuffered()`.

## Implementation Plan

### Phase 1: Option Handler Registry

**Goal:** Create the registry mechanism in tdns.

**Changes:**

1. **New file `option_handlers.go`** (in v2/):
   - `ZoneOptionHandler` type
   - `optionHandlers` map
   - `RegisterZoneOptionHandler()` function
   - Keep it minimal -- just the registry and call mechanism

2. **parseconfig.go**: After `parseZoneOptions()` returns
   and after the zone stub is created/retrieved, iterate
   the parsed options and invoke registered handlers.
   Insert the handler invocation loop before the
   OnFirstLoad callback setup (the handler fires once per
   config parse, not once per zone load).

**Files:** v2/option_handlers.go (new), v2/parseconfig.go

### Phase 2: MP Zone List via Handler

**Goal:** tdns-mp registers a handler that collects MP zone
names. SDE hydration uses this list.

**Changes:**

1. **main_initfuncs.go**: In StartAgent (and StartCombiner,
   StartAuth), before ParseZones is called, register a
   handler for OptMultiProvider that appends the zone name
   to a list stored in `conf.Internal`.

   But note: ParseZones is called inside MainInit which
   runs before StartAgent. So the handler must be
   registered BEFORE MainInit calls ParseZones. This means
   registration happens in the role-specific setup that
   runs before MainInit, or in a pre-parse hook.

   Alternative: register the handler at package init time
   using a well-known variable, or register it in the
   early part of MainInit before the ParseZones call.

2. **config.go**: Add `MPZoneNames []string` to
   InternalConf (or a new MPConf struct). The handler
   populates this list.

3. **syncheddataengine.go**: Change the hydration loop
   from:
   ```go
   for item := range Zones.IterBuffered() {
       if !zd.Options[OptMultiProvider] { continue }
   ```
   to:
   ```go
   for _, zname := range conf.Internal.MPZoneNames {
       zd, ok := Zones.Get(zname)
       if !ok { continue }
   ```

   The zone stub IS in the Zones map (ParseZones creates
   it). It just might not have Options set yet. But we
   don't check Options anymore -- we trust the list.

**Files:** v2/main_initfuncs.go, v2/config.go,
v2/syncheddataengine.go

### Phase 3: Verify and Clean Up

**Goal:** Ensure the hydration works for all MP zones and
the old code path is removed.

**Changes:**

1. Remove the `zd.Options[OptMultiProvider]` check from
   the hydration loop (replaced by list iteration).

2. Add logging: log the MP zone list after ParseZones
   completes, before hydration starts. This makes it
   easy to verify all zones were registered.

3. Test with 4+ MP zones on agent.alpha to confirm all
   are hydrated on restart.

**Files:** v2/syncheddataengine.go

## Registration Timing

The critical question is: when is the handler registered
relative to when ParseZones runs?

Current startup sequence in MainInit:
```
1. Basic config loading (viper)
2. ParseZones(ctx, false)  -- line 234
3. Role-specific setup (StartAgent/StartCombiner/etc.)
4. Engine goroutines launched
```

The handler must be registered BEFORE step 2. Options:

**(a) Register in MainInit before ParseZones:**
Insert handler registration between steps 1 and 2.
MainInit already knows the role from config. Simple.

**(b) Register in package init():**
The handler function would append to a package-level
slice. Less explicit but guaranteed to run before
ParseZones.

**(c) Register via a pre-parse callback on Config:**
Config gets a `PreParseHooks []func()` that MainInit
calls before ParseZones. Role-specific setup registers
the hook.

**Recommended: (a).** It's explicit, the code is already
in MainInit, and the role is known. No new abstraction
needed for the registration timing.

```go
// In MainInit, before ParseZones:
var mpZoneNames []string
RegisterZoneOptionHandler(OptMultiProvider,
    func(zname string, zconf ZoneConf,
        options map[ZoneOption]bool) {
        mpZoneNames = append(mpZoneNames, zname)
    })

all_zones, err := conf.ParseZones(ctx, false)

// Store for later use by SDE:
conf.Internal.MPZoneNames = mpZoneNames
```

## Unknown Option Detection

With static option handling, ParseZones knows every valid
option and warns about unknown ones. With dynamic handler
registration, ParseZones no longer has complete knowledge
-- some options are handled by registered callbacks from
other packages.

To preserve the ability to detect faulty configs, the
option processing must track which options were "claimed"
(either handled locally by ParseZones or by a registered
handler). Any option that is neither locally handled nor
has a registered handler is reported as unknown.

Implementation:

```go
// In the option processing loop:
for opt, val := range options {
    if !val { continue }
    handled := false

    // Check if locally handled (existing switch cases)
    if isLocallyHandledOption(opt) {
        handled = true
    }

    // Check if a handler is registered
    if handlers, ok := optionHandlers[opt]; ok && len(handlers) > 0 {
        for _, handler := range handlers {
            handler(zname, zconf, options)
        }
        handled = true
    }

    if !handled {
        lg.Warn("unknown zone option with no handler",
            "zone", zname, "option", ZoneOptionToString[opt])
    }
}
```

This ensures that:
- Options handled by tdns (ParseZones switch) are fine
- Options handled by tdns-mp (registered handlers) are fine
- Options with neither are flagged as likely config errors

The `isLocallyHandledOption` check can be a simple set of
the options that ParseZones processes directly (the ones in
its switch statement). Everything else must have a handler.

## Future Extensions

The option handler pattern is general-purpose. Other uses:

- **delegation-sync-child**: Register a handler that sets
  up delegation sync infrastructure per zone at parse time.
- **catalog-zone**: Register a handler that initializes
  catalog zone processing.
- **online-signing**: Register a handler that validates
  DNSSEC policy availability at parse time.

Each of these currently has ad-hoc code scattered through
parseconfig.go and main_initfuncs.go. Option handlers
would consolidate them and make the extension points
explicit.

## Relationship to Three-Repo Split

This design keeps the dependency direction clean:

- **tdns** defines `RegisterZoneOptionHandler` and calls
  handlers during ParseZones
- **tdns-mp** calls `RegisterZoneOptionHandler` at init
  time to register its MP handler
- **tdns** has no import of tdns-mp; the coupling is via
  the handler registry (inversion of control)

The handler registry stays in tdns. The handler
implementations move to tdns-mp. No circular dependencies.
