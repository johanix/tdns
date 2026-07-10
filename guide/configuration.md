# TDNS Configuration Guide

This is the operator-facing guide to configuring the TDNS applications. It is
task-oriented: each page starts from a minimal working example and then works
outwards through the blocks you are most likely to need.

For an exhaustive per-key lookup, the annotated sample configs shipped next to
each binary are the reference:

| Application | Sample config |
|-------------|---------------|
| tdns-auth   | [`cmdv2/auth/tdns-auth.sample.yaml`](../cmdv2/auth/tdns-auth.sample.yaml), [`auth-zones.sample.yaml`](../cmdv2/auth/auth-zones.sample.yaml), [`auth-templates.sample.yaml`](../cmdv2/auth/auth-templates.sample.yaml) |
| tdns-imr    | [`cmdv2/imr/tdns-imr.sample.yaml`](../cmdv2/imr/tdns-imr.sample.yaml) |

For the command-line tools, see the generated [CLI reference](../reference/cli/).

## Documents

- [tdns-auth configuration](config-tdns-auth.md)
  -- Minimal working example, TSIG keys, the `allow-notify:` and
  `downstreams:` ACLs, zone declarations (every zone option, and the
  template system), the `dnsengine:` block, and DNSSEC policies
  (policy templates, `split_algorithms`, `large_algorithms`).

- [tdns-imr configuration](config-tdns-imr.md)
  -- Minimal working example, trust anchors, stub zones, and the
  `imrengine.tuning.*` knobs with their defaults.

- [tdns-agent configuration](config-tdns-agent.md)
  -- Placeholder. The agent's proxy configurations are not yet documented
  here; see [Agent as a DSYNC proxy](agent-dsync-proxy.md) meanwhile.

`dog` has no configuration file — see [DOG](app-dog.md).

## Conventions common to all TDNS applications

**Config file location.** Each binary reads `/etc/tdns/<appname>.yaml` by
default — `/etc/tdns/tdns-auth.yaml`, `/etc/tdns/tdns-imr.yaml` and so on.
Override with `--config <path>`. No TDNS application reads configuration from
environment variables.

> `tdns-imr` is the exception: `--config` does not select the config file. The
> named file is read and validated, but `/etc/tdns/tdns-imr.yaml` is then
> decoded on top of it, so the two are merged and the default file wins. See
> [tdns-imr configuration](config-tdns-imr.md).

**Includes.** A top-level `include:` list splices other YAML files into the
main config before it is parsed. Includes may nest, to a depth of 10.

```yaml
include:
   - auth-templates.yaml
   - auth-zones.yaml
   - /var/lib/tdns/dynamic-zones.yaml
```

**The `log:` block is special.** It is read directly out of the *main* config
file, early, before includes are resolved. It must therefore appear at the top
level of the file named by `--config`; putting it in an included file makes
startup fail. `log.file` is required.

**Unknown keys are warned about, not rejected.** The loader decodes the config
into Go structs and then logs every key it did not consume:

```
[WARN/config] unknown config keys ignored (possible misspellings) keys=[zones[0].dnssec_polciy]
```

A misspelled key is therefore *silently inert* — the feature it was meant to
enable simply never turns on. A small registry of keys that were renamed or
moved by past restructures gets a louder, specific message instead:

```
[ERROR/config] deprecated config key (config lags the code) — `dnssecpolicies:` moved
under `dnssec:` as `dnssec.policies:` (restructure 2026-06-16) key=dnssecpolicies
```

Both lines are worth grepping for after any config change.

**Some blocks are read outside the struct decoder.** A handful of top-level
blocks (`delegationsync:`, `childsync:`, `scanner:`, `server:`,
`resignerengine:`, `common:`) are read key-by-key rather than decoded into the
`Config` struct. They work, but because the struct decoder does not recognize
them they also appear in that "unknown config keys" warning at startup. That is
expected and not an error.

**Zone errors are quarantined, not fatal.** A zone whose configuration is
invalid — a bad ACL, an unknown TSIG key, a signing option with no DNSSEC
policy, a template that does not exist — is put into `ERROR` state on its own
while the rest of the server starts normally. Check for these with:

```console
$ tdns-cli auth zone list
mldsa.pq.axfr.net.   ERROR   Error[config]: downstreams: acl entry "": bad ip-spec ""
```
