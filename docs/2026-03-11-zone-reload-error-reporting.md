# Zone Reload Error Reporting & Cleanup

Date: 2026-03-11

## Context

When developing new RR types (like HSYNCPARAM), zone parse errors are hard to diagnose:
1. **Errors don't reach the CLI** — `zone reload -z {zone}` returns "refreshing" immediately; actual parse errors are only in server logs
2. **Error messages are unhelpful** — `dns: : "\n" at line: 6:76` doesn't include the filename or the offending line content
3. **RR type syntax is undocumented** — no quick reference for the zone file format of custom RR types
4. **Primary zones are unnecessarily rewritten** — the server rewrites zone files even for static zones that haven't been modified

## Part 1: `--error` flag for `zone reload`

### Problem
For existing (already-loaded) zones, RefreshEngine launches refresh in a background goroutine (`refreshengine.go:350`) and sends the response immediately (`refreshengine.go:492-497`) *before* the goroutine finishes. The CLI gets "refreshing..." and never sees parse errors.

### Approach
Add `--error` and `--timeout` CLI flags. When `--error` is set, the refresh goroutine itself sends the actual result (success or error) through the response channel when it finishes. The engine loop stays fully async — it just skips the immediate "refreshing..." response for `--error` requests.

The response channel is buffered (size 1), so the goroutine won't block even if the caller times out.

### Data flow
```
CLI --error --timeout 10s
  → ZonePost{Wait: true, Timeout: "10s"}
    → API handler
      → ReloadZone(refreshq, force, wait=true, timeout="10s")
        → ZoneRefresher{Wait: true} sent to RefreshEngine
          → RefreshEngine: skip immediate response (Wait=true)
          → goroutine: runs Refresh(), sends result via Response channel
        ← ReloadZone: waits up to 10s on Response channel
      ← API handler: returns result or timeout
    ← CLI: displays error or success
```

### Expected CLI behavior
```
# Normal reload (unchanged behavior):
$ tdns-cli zone reload -z whisky.dnslab.
RefreshEngine: primary zone whisky.dnslab. refreshing (force=false)

# With --error (waits up to 10s for result):
$ tdns-cli zone reload -z whisky.dnslab. --error
zone whisky.dnslab.: refresh failed:
  /etc/tdns/zones/whisky.dnslab: dns: bad HSYNCPARAM ... at line: 6:76
  line 6: foo.whisky.dnslab.  3600  IN  HSYNCPARAM  1 0 "alpn=dot"

# With custom timeout for large zones:
$ tdns-cli zone reload -z se. --error --timeout 120s
```

**Status**: DONE

## Part 2: Better zone parse error messages

### Problem
`dns.NewZoneParser(r, "", "")` was called without a filename. Error messages showed `dns: : "\n" at line: 6:76` — no filename, no offending line content.

### Fix
1. Pass filename to `NewZoneParser` (3rd arg) so it's included in error messages
2. `formatZoneParseError` helper extracts line number from error string, reads that line from the zone file, and appends it

**Status**: DONE

## Part 3: RR type syntax documentation

Added zone file syntax comment blocks to all 13 custom RR type files in `v2/core/rr_*.go`.

**Status**: DONE

## Part 4: Stop rewriting primary zone files unnecessarily

### Problem
When a primary zone's serial changes (user edited the zone file), `FetchFromFile` returns `updated=true`. The RefreshEngine goroutine then writes the zone file back to disk — but for primary zones loaded from file, this just overwrites the source with what was just read. Only secondary zones (transferred from upstream) and zones with dynamic updates need file writes.

Additionally, `FetchFromFile` had a `service.debug` conditional write (lines 304-316) that wrote every updated zone unconditionally.

### Fix
1. In `refreshengine.go`: gate zone file writes on `zd.ZoneType != Primary || zd.Options[OptDirty]` (both goroutine path and ticker path)
2. In `zone_utils.go`: remove the `service.debug` write block in `FetchFromFile`

**Status**: DONE

## Files modified

| File | Part | Change |
|------|------|--------|
| `v2/cli/commands.go` | 1 | `showError` and `errorTimeout` variables |
| `v2/cli/zone_cmds.go` | 1 | `--error`/`--timeout` flags, pass to ZonePost |
| `v2/api_structs.go` | 1 | `Wait bool` + `Timeout string` in ZonePost |
| `v2/apihandler_zone.go` | 1 | Pass Wait+Timeout to ReloadZone |
| `v2/zone_utils.go` | 1,4 | Parse timeout in ReloadZone; remove debug write in FetchFromFile |
| `v2/structs.go` | 1 | `Wait bool` in ZoneRefresher |
| `v2/refreshengine.go` | 1,4 | Goroutine sends result when Wait; gate immediate response; gate file write on zone type |
| `v2/dnsutils.go` | 2 | `filename` param to ParseZoneFromReader, `formatZoneParseError` helper |
| `v2/core/rr_*.go` (13 files) | 3 | Syntax documentation comments |
