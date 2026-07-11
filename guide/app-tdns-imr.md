# tdns-imr

A simple DNS IMR (Iterative Mode Resolver, i.e. a recursive DNS nameserver).

For the configuration file, see
[tdns-imr configuration](config-tdns-imr.md).

Features:

- **tdns-imr** does recursive lookups, caches intermediate referrals and final
  response (if any)

- incoming queries are first matched against the cache before initiating
  lookup via external queries

- supports modern DNS transports (DoT, DoH and DoQ) in addition to Do53 (UDP/TCP).

- consumes transport signals from authoritative nameservers — when an
  SVCB record at `_dns.<ns>` arrives in the Additional section (or via
  active discovery, see `query-for-transport` /
  `always-query-for-transport`), tdns-imr parses SvcParam key 65280,
  updates the server's transport preferences in the referral cache, and
  promotes the connection mode to "opportunistic" so subsequent queries
  attempt the preferred encrypted transport. TSYNC is supported as an
  alternative carrier. See section 2 of
  [TDNS Special Features](special-features.md) for the full picture.

## Daemon mode and interactive mode

**tdns-imr** runs in one of two modes, selected by the `--cli` flag.

```console
$ tdns-imr                       # daemon mode (the default)
tdns-imr: Starting in daemon mode, no CLI

$ tdns-imr --cli                 # interactive mode
```

Interactive mode is **not** a lightweight client. Startup is identical in both
modes: the resolver binds `imrengine.addresses`, starts the validator and the
HTTP management API, and begins answering queries. `--cli` merely layers a shell
on top of that running resolver, so every command below inspects and manipulates
the live in-process cache.

The shell is a `go-prompt` REPL with completion. `exit` or `quit` terminates it
— and with it the daemon. A bare `query` with no arguments is also treated as
`quit`.

Other flags: `--config`, `-d`/`--debug`, `-v`/`--verbose`, `--version`,
`-H`/`--headers`, `-z`/`--zone`, `-Z`/`--pzone`. Sending `SIGHUP` triggers a
zone reload.

## Interactive commands

**Querying**

| Command | Effect |
|---------|--------|
| `query <name> <type>` | Resolve in-process and print the answer with its DNSSEC validation state. `-v` also prints the negative proof |

**Cache inspection** — `dump` on its own lists the RRset cache.

| Command | Effect |
|---------|--------|
| `dump suffix <suffix>` | Cached RRsets whose owner name ends in `<suffix>` |
| `dump zones` | All cached zones, with secure-delegation status |
| `dump zone servers <zone>` | Servers known for one zone |
| `dump zone backoffs <zone>` | Lame-delegation backoffs for one zone |
| `dump servers` | Servers, grouped by zone |
| `dump auth-servers` | Authoritative-server table |
| `dump auth-servers servers` | The server entries |
| `dump auth-servers keys` | The cache keys |
| `dump auth-servers errors` | Servers currently in backoff |
| `dump keys` | Cache keys |
| `dump dnskeys` | Trust anchors and cached DS, with validation state |
| `dump tuning` | The effective `imrengine.tuning.*` values |
| `dump discovery` | Transport-signal and TLSA discovery state |

**Cache flushing**

| Command | Effect |
|---------|--------|
| `flush common <domain>` | Flush non-structural RRsets at and below `<domain>` |
| `flush all <domain>` | Flush all RRsets at and below `<domain>`. Refuses the root |

**Statistics**

| Command | Effect |
|---------|--------|
| `stats` | Large-KSK metrics, and lists the subcommands |
| `stats large-ksk` | DNSKEY-over-TCP counters for large algorithms |
| `stats auth-transports <zone>` | Per-transport counters |
| `stats auth-servers <zone>` | Alias of the above |

**Inspection and settings**

| Command | Effect |
|---------|--------|
| `show config` | Listen addresses, cache-primed flag, trust anchors, stub zones |
| `show options` | The configured `imrengine.options` |
| `set linewidth <n>` | Output truncation width |
| `set server transport --server <ns> --signal "doq:20,dot:100,do53:3"` | Override a server's transport signal at runtime (debug). `--reset` clears it |

**Zones**

`zone list` prints only, and `zone check <file>` is not yet implemented.

There is no interactive command to add, remove or reload trust anchors, and no
command to re-prime the cache. Trust anchors are display-only here (`show
config`, `dump dnskeys`); a cache reset exists only over the API. IMR debug
logging is configured with `imrengine.logging.enabled`, not toggled from the
shell.

## Relationship to `tdns-cli imr ...`

Three surfaces exist, and they are easy to confuse.

**The interactive shell** (above) acts on the tdns-imr process it is part of,
through in-process channels.

**`tdns-cli imr <cache-command>` does not work.** `tdns-cli` registers the same
command objects under `imr`, but their implementations reach for an in-process
resolver that `tdns-cli` does not have. `tdns-cli imr query` prints
*"No active channel to RecursorEngine. Terminating."* The only `tdns-cli imr`
subcommands that do anything are `imr ping`, `imr daemon ...` and
`imr dsync-query`.

**`tdns-cli agent imr ...` and `tdns-cli auth imr ...` are the real API-based
cache commands.** They POST to the `/imr` endpoint of a running **tdns-agent**
or **tdns-auth** — each of which embeds its own resolver — not to tdns-imr.

| Command | Wire command |
|---------|--------------|
| `query <qname> <qtype>` | `imr-query` |
| `flush <qname>` | `imr-flush` |
| `reset` | `imr-reset` (flush and re-prime, preserving root NS) |
| `show --id <agent>` | `imr-show` |
| `dump-tuning` | `imr-dump-tuning` |
| `dump-zone-backoffs [zone]` | `imr-dump-zone-backoffs` |

tdns-imr does serve the `/imr` endpoint itself, but no shipped CLI command is
wired to send these cache commands to it.
