# Config schema: the `listeners:` block and the `authengine:` rename

**Date:** 2026-08-31
**Status:** IN PROGRESS (branch `feature/config-listeners`)
**Implements:** #446 (design agreed there 2026-08-31)
**Downstream:** every deployed tdns config must migrate in lockstep with the
binary upgrade (the old keys are hard startup errors, by design).

## 1. The problem

`dnsengine:` fuses two unrelated things: listener configuration (addresses,
certfile/keyfile, transports — plus per-transport ports that never made it
into the struct at all, so the shared transport engines read
`dnsengine.ports.*` straight from viper regardless of which app called them,
#444) and authoritative-serving behavior (`options` typed as `AuthOption`,
`outbound-soa-serial`, `transfer-src`). The name is wrong for both halves,
and the imr — which runs the same shared transport engines — gets
second-class listener config as a result.

## 2. The shape

Identical `listeners:` schema in every app's config file (unambiguous
because each app has its own file), passed into the shared transport engines
**as a struct** — no viper reach-through:

```yaml
listeners:
   addresses:  [ 127.0.0.1:53, '[::1]:53' ]    # do53; port in the address, as today
   transports: [ do53, dot, doh, doq ]
   certfile:   /etc/tdns/certs/server.crt
   keyfile:    /etc/tdns/certs/server.key
   ports:                                       # per encrypted transport; real,
      dot: [ "853" ]                            # validated struct fields
      doh: [ "443" ]
      doq: [ "853" ]
   # Apps whose imr is internal (tdns-auth, tdns-agent) may open a
   # loopback-only DNS window straight into the embedded resolver:
   # imr-debug-address: 127.0.0.1:5959

authengine:   # tdns-auth and tdns-agent (both serve authoritatively):
   ...        # auth options, outbound-soa-serial, transfer-src, ...

imrengine:    # resolver behavior only: options, stubs, forward, trust
   ...        # anchors, tuning, logging — the listener keys are GONE
```

**No fallbacks, no aliasing.** Every moved key (`dnsengine.*` entirely,
`imrengine.addresses/transports/certfile/keyfile`, `dnsengine.ports.*`) is a
hard startup error with exact migration text ("dnsengine.addresses has moved
to listeners.addresses"). A stale config fails loudly, never half-works.

## 3. imr-debug-address

The embedded resolver in tdns-auth/tdns-agent intentionally exposes no
service; this key opens a cache window in the tool already in hand
(`dog @127.0.0.1:5959 foo.bar. A +norec` — cache hits served, misses
REFUSED, no outbound queries; RD=1 drives the internal resolver by hand).

- **Loopback-enforced, hard error otherwise** (127/8 or ::1): a non-loopback
  value must refuse to start.
- **`ANY +norec` enumerates the owner's cached RRsets** — debug listener
  only; ANY stays minimal elsewhere (RFC 8482).
- **Indirect (Referral/Glue/Hint) entries are served on RD=0** — debug
  listener only; the default path falls through to REFUSED as today.
- Served TTLs on the debug listener should reflect remaining lifetime.

## 4. Migration

Coordinated with labconfig#76 (private repo): master configs and templated
labgroup machine configs migrate together with the binary. The daemon's
error messages carry the key-for-key mapping, so migration is mechanical:

| Old key | New key |
|---|---|
| `dnsengine.addresses` | `listeners.addresses` |
| `dnsengine.transports` | `listeners.transports` |
| `dnsengine.certfile` / `.keyfile` | `listeners.certfile` / `.keyfile` |
| `dnsengine.ports.{dot,doh,doq}` | `listeners.ports.{dot,doh,doq}` |
| `dnsengine.options` | `authengine.options` |
| `dnsengine.outbound-soa-serial` | `authengine.outbound-soa-serial` |
| `dnsengine.transfer-src` | `authengine.transfer-src` |
| (every other `dnsengine.*` behavior key) | `authengine.*`, same name |
| `imrengine.addresses` | `listeners.addresses` |
| `imrengine.transports` | `listeners.transports` |
| `imrengine.certfile` / `.keyfile` | `listeners.certfile` / `.keyfile` |

The `/config status` API response changes accordingly (`DnsEngine` →
`Listeners` + `AuthEngine`); tdns-cli and daemons upgrade in lockstep, as
everywhere else in this project.

## 5. As-built notes

- The hard-error scan (`rejectMovedConfigKeys`) lives INSIDE
  `decodeConfigMap`, so every decode path — daemon, `config check`, both
  ValidateConfig arms — inherits it and the checker cannot pass what the
  daemon refuses.
- `listeners.ports.*` are `[]uint16`: ports are numbers, and the strict
  decoder (no weak typing) now says so. The two XoT rigs' quoted `"5401"`
  became `5401`. `portStrings` converts at the transport-engine boundary
  (`net.JoinHostPort` wants strings).
- The transport engines take `ports []string` as a parameter; every
  `viper.GetStringSlice("dnsengine.ports.*")` and
  `viper.GetString("dnsengine.certfile"/"keyfile")` reach-through is gone
  (the #444 ports half).
- `StartImrEngineListeners` is app-gated: only `AppTypeImr` binds the
  `listeners:` block. An embedded resolver (auth/agent) binds nothing but
  the debug window — previously `imrengine.addresses` in an auth config
  would have raced the auth listeners for the same sockets.
- The debug window (v2/imr_debug_listener.go) serves cache entries with
  TTLs adjusted to remaining lifetime and each entry's metadata (type,
  context, validation state, expires-in) as a CH TXT in Additional — so
  `dog` output carries the "why", not just the RRs. RD=1 delegates to the
  normal handler (drives the internal resolver); cache misses fall back to
  the normal REFUSED + explanatory TXT.
- `validateListenerCerts` (né validateDnsEngineCerts) and the auth SVCB
  ALPN derivation follow `listeners:`. `FindDnsEngineAddrs` keeps its name
  (tdns-mp calls it) but reads `listeners:`.
- ConfigResponse: `DnsEngine` → `Listeners` + `AuthEngine`; CLI and daemon
  ship together, as everywhere in this project.
- Verified live: an old-schema config fails with the key-for-key migration
  text; a new-schema tdns-imr resolves; a tdns-auth with
  `imr-debug-address: 127.0.0.1:5959` answers RD=1 drives, `+norec` cache
  peeks with remaining TTLs, `ANY +norec` enumeration with metadata TXTs,
  and REFUSED+TXT on misses.
