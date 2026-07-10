# tdns-imr configuration

`tdns-imr` is the TDNS iterative/recursive resolver. For how to run it — daemon
mode versus the interactive shell — see [tdns-imr](app-tdns-imr.md).

Read [Configuration Guide](configuration.md) first for the conventions common to
every TDNS application.

## The block is named `imrengine:`

Almost all of the resolver's configuration lives under a top-level block called
**`imrengine:`**, not `imr:`. The only `imr.`-prefixed key is
`imr.localconfig`, described at the end of this page.

> **`tdns-imr --config <path>` does not select the config file.** The named
> file *is* read — it is validated, and its values are loaded — but the main
> config decode then reads `/etc/tdns/tdns-imr.yaml` **on top of it**. The two
> files are merged, and the default file wins:
>
> - any key `/etc/tdns/tdns-imr.yaml` defines **overrides** your file;
> - a key only your file defines **survives**;
> - the `log:` block always comes from the default file, because logging is set
>   up before the parse;
> - validation runs against *your* file, so a valid `--config` does not mean the
>   file that actually gets parsed is valid.
>
> Concretely: `--config` with `imrengine.addresses: [127.0.0.1:15353]` still
> binds the default file's addresses, while `imrengine.active: false` — a key
> the default file happens not to set — does take effect.
>
> Until this is fixed, put the config you want at `/etc/tdns/tdns-imr.yaml` and
> do not pass `--config`. Other TDNS applications honour `--config` normally.

## Minimal working example

Three keys are validated as required (`imrengine.addresses`,
`imrengine.transports`, `log.file`), and one more is required in practice:
`apiserver.apikey`. The API router refuses to build without an API key, and
that error aborts startup — even though the resolver would otherwise not need
the API at all.

```yaml
imrengine:
   addresses:   [ 127.0.0.1:53, '[::1]:53' ]   # required
   transports:  [ do53 ]                       # required

apiserver:
   apikey:  "a-long-random-string"             # required in practice

log:
   file:   /var/log/tdns/tdns-imr.log          # required
   level:  info
```

Everything else defaults. Two caveats:

**`apiserver.addresses` is optional.** Omit it and the management API simply
does not listen, while the resolver runs normally. If you do set it, note that
`apiserver.usetls` defaults to **true**, which then requires `certfile` and
`keyfile`; otherwise the API listener fails to start (the resolver keeps
running).

**No trust anchor is configured by default.** DNSSEC validation is on —
`require_dnssec_validation` defaults to true — but the daemon seeds no root
anchor unless you configure one. The compiled-in root anchor is wired into
`dog`, not into `tdns-imr`. A resolver with no anchor cannot build a chain of
trust. See below.

## Trust anchors

Exactly three forms exist. Note that two use underscores and the third uses
hyphens.

```yaml
imrengine:
   # inline DS record (preferred)
   trust_anchor_ds:      ". IN DS 20326 8 2 E06D44B8...EC8D"

   # or inline DNSKEY
   trust_anchor_dnskey:  ". IN DNSKEY 257 3 8 AwEAAaz/tAm8y..."

   # or an unbound-style file, one DS/DNSKEY per line
   trust-anchor-file:    /etc/tdns/root.key
```

Inspect what the running resolver actually loaded with `show config` in the
interactive shell.

## Transports and listeners

| Key | Default | Meaning |
|-----|---------|---------|
| `addresses` | — | **required**. `addr:port` sockets to listen on |
| `transports` | — | **required**. Any of `do53`, `dot`, `doh`, `doq` |
| `certfile` / `keyfile` | — | required for `dot`/`doh`/`doq` |
| `active` | `true` | set `false` to disable the resolver entirely |
| `root-hints` | compiled-in | path to a root hints file |
| `require_dnssec_validation` | `true` | — |

`imrengine.options:` accepts `query-for-transport`,
`always-query-for-transport`, `query-for-transport-tlsa` and
`transport-signal-type`. Transport-signal *processing* is always on: signals
that arrive in the Additional section are applied whether or not these options
are set; the options control whether the resolver goes looking for them.

## Stub zones

Answer a zone from named servers instead of iterating from the root.

```yaml
imrengine:
   stubs:
      - zone:     internal.example.
        servers:  [ 192.0.2.53, 2001:db8::53 ]
```

Both `zone` and `servers` are required in each entry.

## Debug logging

Separate from `log.file`, and off by default.

```yaml
imrengine:
   logging:
      enabled:  true
      file:     /var/log/tdns/imr-debug.log   # this is the default when enabled
```

## Tuning

Every key under `imrengine.tuning:` is optional. The values below **are** the
defaults, so this block is only worth writing when you want to change one.
Inspect the effective values on a running resolver with `dump tuning` in the
interactive shell, or `tdns-cli agent imr dump-tuning` against an agent.

```yaml
imrengine:
   tuning:
      backoff:
         first_failure:     15s   # first backoff after a server failure
         max_failure:       1h    # ceiling; raised to first_failure if set lower
         multiplier:        3.0   # exponential growth factor
         jitter_fraction:   0.25  # must be in [0,1), else reset to the default
         routing_failure:   1h    # backoff after an unreachable-network error
         lame_delegation:   1h    # backoff after a lame delegation
      address_family:
         window_duration:   10m   # observation window for per-family failures
         failure_threshold: 5     # distinct failures before a family is suspect
         suspect_duration:  10m   # how long a family stays suspect
         probe_interval:    30s   # how often a suspect family is re-probed
      discovery:
         retry_after_failure: 30s # transport-signal discovery retry
         max_failures:        3   # give up discovery after this many
      query_budget:              8s     # total wall-clock budget for one query
      upgrade_indirect_cache_hits: true # left unset in code; treated as true
```

The `address_family` group is what demotes a broken IPv6 (or IPv4) path: once
`failure_threshold` distinct failures are seen inside `window_duration`, that
family is treated as suspect for `suspect_duration` and re-probed every
`probe_interval`.

## large_algorithms

Not part of `imrengine:` — it lives in the shared top-level `dnssec:` block.

```yaml
dnssec:
   large_algorithms: [ RSASHA512 ]
```

When a referral's DS RRset names one of these algorithms, the resolver fetches
the child's DNSKEY over TCP from the outset rather than trying UDP and retrying
on truncation.

Entries are algorithm **names**, not codepoints — `[ 10, 8, 5 ]` is a decode
error (`expected type 'string', got unconvertible type 'int'`) that prevents
startup. A name this binary does not know is likewise a hard config error. See
[DNSSEC policies](config-tdns-auth.md#large_algorithms) for the full list of
accepted spellings, and inspect the counters with
`tdns-cli imr stats large-ksk`.

## imr.localconfig

The one `imr.`-prefixed key. It names a second config file that is merged on
top of the main one; a missing file is skipped silently.

```yaml
imr:
   localconfig:  /etc/tdns/tdns-imr-local.yaml
```
