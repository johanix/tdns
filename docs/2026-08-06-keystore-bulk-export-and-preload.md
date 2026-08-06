# Keystore bulk export/import and startup pre-load

2026-08-06

## The problem

The keystore is a SQLite file. That is fine for a running server and bad for
everything else:

- **It cannot be reviewed.** There is no way to look at a zone's keys in a diff,
  a code review, or a config repo.
- **It cannot be versioned.** A lab or a testbed rebuilt from a git repo gets its
  zone files and its config back, but not its keys — so every committed DS
  record in every parent is wrong the moment the machine is rebuilt.
- **Losing it loses everything.** One file is the single point of unrecoverable
  loss for every key of every zone the server signs.

This is not specific to any one deployment. `dnslab`, `com`, `net` and the root
zone in the training lab have exactly the same exposure as a PQ testbed.

There is a second, sharper problem underneath. Even *with* the key material in
hand, there was no way to get it into the keystore in time. A signed zone that
comes up against an empty keystore mints its own keys
(`EnsureActiveDnssecKeys`), and by the time an operator could import the real
ones the zone has already published a DNSKEY set that no parent's DS matches.
Importing afterwards means racing the signer and then cleaning up after it.

## What this adds

Three things, at two layers.

1. **`keystore <class> bulk-export`** — write a selected subset of the keystore
   to a directory as BIND-convention key files plus a sidecar manifest.
2. **`keystore <class> bulk-import`** — read such a directory back into the
   keystore, create-if-absent by default.
3. **`keystore.preload.<class>`** — a config directory per key class, loaded at
   startup *before zones are parsed*, so the ordering problem disappears by
   construction: the zone finds its keys already there and adopts them.

`<class>` is `dnssec`, `sig0` or `tsig`. Each has its own commands and its own
config directory, so a deployment can export TSIG keys without exporting private
signing keys, or pre-load SIG(0) without pre-loading DNSSEC.

## On-disk format

```
/etc/tdns/keys/dnssec/
    manifest.yaml
    Kpq.dnslab.+015+12345.key
    Kpq.dnslab.+015+12345.private
    ...
```

The manifest is not decoration. A `K<name>+<alg>+<keyid>.{key,private}` pair
says nothing about whether the key is published, standby, active or retired, and
nothing about when it got there. Restore a key into the wrong state and you
either flatten a zone mid-rollover or — for a published key with no
`published_at` — restart its propagation clock, which `KeyStateWorker` will
notice and defer on. So the manifest carries `state`, `published_at`,
`active_at`, `retired_at` and `active_seq` alongside each entry.

```yaml
version: 1
dnssec:
    - zone: pq.dnslab.
      keyid: 12345
      flags: 257
      algorithm: MLDSA87
      state: active
      published_at: "2026-08-01T09:14:22Z"
      private_file: Kpq.dnslab.+201+12345.private
      public_file: Kpq.dnslab.+201+12345.key
tsig:
    - keyname: xfr.dnslab.
      algorithm: hmac-sha256
      secret: ...
```

Two deliberate choices:

- **The manifest records file names rather than deriving them.** The read side
  therefore never resolves an algorithm name to a codepoint, which means a key
  whose algorithm this binary does not link still loads into the keystore
  correctly. Only the export side, which by definition has the algorithm in
  hand, computes a filename.
- **TSIG keys live entirely in the manifest.** The secret *is* the key material;
  a separate file would add a step without adding protection. The manifest is
  written 0600 for that reason.

One manifest can carry all three classes, so pointing several `preload.*` keys
at the same directory works, each reading only its own section.

A manifest from a newer format version is refused rather than half-read.

## Merge, not overwrite

`bulk-export` into a directory that already has a manifest **merges**: entries
for keys not covered by this run are left alone. That makes several narrow
exports compose —

```sh
tdns-cli auth keystore dnssec bulk-export --dest /etc/tdns/keys/dnssec --zones pq.dnslab
tdns-cli auth keystore dnssec bulk-export --dest /etc/tdns/keys/dnssec --zone dnslab.
```

— rather than the second erasing the first. Entries are sorted on save, so
re-exporting an unchanged keystore produces a byte-identical file: these
directories are meant to live in version control, where a reordered manifest is
noise that hides the real change.

Key files are write-if-absent-else-verify. Identical content is a no-op;
different content under the same name is an error, not a silent overwrite.

## Selection

`--zone` takes one exact name. `--zones` takes a name **and everything below
it**. Both are repeatable and additive; with neither, the whole class is
exported (the whole-keystore backup case — the CLI says so before it does it).

Subtree matching is on label boundaries, not string suffixes: `--zones
pq.dnslab` must not also scoop up `notpq.dnslab`. `--zones .` is the root's
subtree, i.e. everything; `--zone .` is the root zone alone.

For TSIG the flags are `--key`/`--keys` — the same semantics, but TSIG keys are
named rather than zone-scoped, and calling that a "zone" would be a lie.

## Import semantics

Per key, one of four outcomes:

| Outcome     | When                                      |
|-------------|-------------------------------------------|
| `imported`  | not in the keystore — inserted            |
| `unchanged` | present and identical — left alone        |
| `conflict`  | present and **different** — SKIPPED       |
| `replaced`  | present and different, `--force` given    |

The conflict rule is the important one. **The running keystore outranks a file
on disk.** An export is a snapshot that may be arbitrarily stale, and letting it
overwrite live rows means a stale directory silently un-rolls a rolled key on
every restart — with the symptom (a suddenly-stale parent DS) surfacing nowhere
near the cause. So the default refuses, names which fields differ, and leaves
the keystore alone. `bulk-import` exits non-zero on any conflict, so a script
cannot mistake it for a successful restore.

`--force` flips conflicts to overwrite. That is the recovery path: it exists
because sometimes the thing you are restoring *from* is the correct copy and the
keystore is the wrong one.

An import is all-or-nothing. A single invalid key rolls the whole batch back; a
partially-restored keystore is the state nobody can reason about.

### What is and is not validated

The private key is stored **verbatim** — the PEM column is copied as-is, never
parsed. That is what lets a key restore correctly even when this binary has no
implementation for its algorithm (it will fail later, loudly, if the zone
actually tries to sign with it), and it is what makes pre-load safe to run before
any zone is bound.

The public half *is* parsed, because it is a cheap, crypto-free consistency
check: owner name must match the zone, flags and keytag must match what the
manifest claims. That catches a manifest that has drifted from its own files —
the failure that would otherwise surface much later as an unsignable zone.

## Startup pre-load

`PreloadKeystore()` runs in `MainInit` after the KeyDB exists and before
`LoadTsigKeys()` and `ParseZones()`:

- ahead of `LoadTsigKeys` so the TSIG reconcile sees the restored rows;
- well ahead of `ParseZones` so a signed zone adopts its real keys.

Failures that mean "the operator's intent could not be carried out" — a
configured directory that is missing, an unreadable or self-inconsistent
manifest — abort startup. A pre-load that half worked is precisely what this
exists to rule out.

Conflicts are **not** failures: a key already in the keystore under different
material is the keystore winning, which is the designed behaviour. Each one is
logged individually at WARN, because the operator needs to know their on-disk
copy is not what is running.

### overwrite-existing-keys

`keystore.preload.overwrite-existing-keys: true` inverts that rule for every
configured class: an on-disk key that differs replaces the keystore's copy.

It exists for hosts rebuilt from a repo — a training lab master, where the
committed export *is* the source of truth and the keystore is disposable. That
case wants a build script with no manual reconcile step in the middle, and
without this it does not have one.

It is dangerous everywhere else, and in a specific way. The CLI's
`bulk-import --force` is one shot, aimed, at a moment the operator chose. This
stays armed on **every restart**, so a stale committed export can silently
revert a key that was rolled by hand months later — and the restart that does it
may be unrelated and unattended.

Two mitigations, both deliberate:

- Every replacement is logged at WARN, naming the key and the fields that
  changed. If this setting ever reverts something, that line is the only place
  that says so.
- The setting is announced at WARN **on every boot**, before anything is
  touched — not only on boots where it happens to change something — so the log
  always records which mode the host is in.

The alternative for a scripted build, if you would rather not arm it, is to
delete the keystore file before first start: an empty keystore has nothing to
conflict with, so pre-load imports everything cleanly.

A directory readable beyond its owner gets a warning, not a refusal. It holds
private keys, but there are deliberate reasons to relax that (a lab where the
keys are public on purpose), and refusing to start over a permission bit is
worse than saying so.

## Configuration

```yaml
keystore:
   preload:
      dnssec:  /etc/tdns/keys/dnssec
      sig0:    /etc/tdns/keys/sig0
      tsig:    /etc/tdns/keys/tsig

      # Optional, DANGEROUS, applies to every class above. See above.
      overwrite-existing-keys:  false
```

The directory is the whole switch: set it and that class is pre-loaded, leave it
unset and it is not. One knob rather than an enable flag plus a path, which
cannot then be set to the invalid combination of "enabled, no directory".

## Worked example

```sh
# On a live server, once the keys exist:
tdns-cli auth keystore dnssec bulk-export --dest /etc/tdns/keys/dnssec --zones pq.dnslab
tdns-cli auth keystore tsig   bulk-export --dest /etc/tdns/keys/tsig

# Commit the directories. Point the config at them:
#   keystore.preload.dnssec / keystore.preload.tsig
#
# A rebuilt server now starts with the same keys, so every DS record committed
# alongside them is still correct.
```

## Deliberately not done

- **The single-key `keystore <class> import` path is unchanged.** It still uses
  `INSERT OR REPLACE` and still hardcodes `state: created` on the CLI side. The
  new create-if-absent semantics apply to the bulk and pre-load paths only —
  changing the existing command's behaviour is a separate decision from adding
  a new one. (Adding `--state` to that command remains a worthwhile small fix.)
- **No dry-run flag on `bulk-import`.** The default *is* the safe mode: it
  reports conflicts and skips them. A separate preview would be a second code
  path saying the same thing.
- **No pruning.** Neither import nor pre-load deletes keystore rows that the
  manifest does not mention. A restore is additive; deleting keys is
  `keystore <class> delete`, deliberately.
