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
  (policy templates, `split-algorithms`, `large-algorithms`).

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

**Includes.** A top-level `include:` list pulls other YAML files into the main
config before it is parsed. Includes may nest, to a depth of 10.

```yaml
include:
   - auth-templates.yaml
   - auth-zones.yaml
   - /var/lib/tdns/dynamic-zones.yaml
```

*An included file REPLACES, it does not add.* This is the part that surprises
people, so it is worth being precise about:

- A **list** — `zones:`, `templates:` — in an included file replaces the whole
  list. If the main config has three zones and an include names one, the server
  serves **one** zone.
- A **map** merges, but only one level down. `dnssec:` in an included file
  merges with `dnssec:` in the main config key by key, so `dnssec.completeness`
  in one and `dnssec.kasp` in the other both survive — but if both files set
  `dnssec.policies`, the included file's policies replace the main config's
  entirely.
- The **included file wins**, which is the opposite of most config systems.

A replace that actually discards something is logged, so it is not silent:

```
[WARN/config] include replaced a config section rather than adding to it
   key=zones replaced-by=/etc/tdns/generated.yaml entries-dropped=3
   hint=this is the historical behaviour; use `- {file: ..., merge: true}` to combine instead
```

**Merging an include.** To combine rather than replace, ask for it per include:

```yaml
include:
   - auth-templates.yaml           # replaces, as always
   - file: generated-zones.yaml
     merge: true                   # combines
```

A bare string is always a replace, so every config written before this existed
behaves exactly as it did. The map form takes `file:` (required) and `merge:`
(optional, default false) and nothing else; an unknown key, or `merge: true`
with no `file:`, is an error rather than a silently ignored entry.

Merging applies **only to these paths**, and only for an include that asked:

| Path | How it combines |
|---|---|
| `zones` | concatenated; a repeated zone name is an error |
| `templates` | concatenated; a repeated template name is an error |
| `dnssec.policies` | merged by policy name; a repeated name is an error |
| `dnssec.large-algorithms` | combined as a set |
| `dnssec.split-algorithms` | merged by KSK, the ZSK lists combined as sets |

Everything else replaces, whether or not the include asked to merge. That is
deliberate rather than an oversight: `dnsengine.addresses`, `apiserver.addresses`
and `dnsengine.transports` are lists too, and combining those would silently make
the server listen on more addresses than the file in front of you names — the
same shape of mistake as widening an ACL, and harder to notice.

Note that merging `dnssec.split-algorithms` **widens** which KSK/ZSK algorithm
pairings the server will accept. That is usually what you want when a generated
file brings its own pairings, but it is a widening, not a restatement.

**Two definitions of one name.** Whether they come from one file or from a
merged include, a repeated name is never resolved by picking one:

- A **zone** defined twice is served under *neither* definition. It stays
  visible in `zone list` carrying a config error, and every other zone is
  unaffected — a server does not stop over one zone pasted twice.
- A **DNSSEC policy** defined twice is dropped, and any zone naming it fails to
  resolve its policy and is quarantined the same way.
- A **template** defined twice fails config load, because every zone expanded
  from it would otherwise be a coin flip.
- A repeated key inside a *mapping* — two policies of one name in one file —
  is rejected by the YAML parser before any of this is reached.

Run `tdns-cli <role> config check` to find duplicates before a restart acts on
them; it reports them without changing anything. It reads the config through the
same loader the daemon uses, so what it reports is what the daemon will do.

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
