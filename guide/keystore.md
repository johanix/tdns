# The tdns Keystore

Every private key a tdns daemon holds lives in one place: the keystore. It is
not a file you configure separately and not a directory of `.private` files —
it is a set of tables inside the SQLite database named by `db.file`.

This page is the complete description: what the keystore holds, how to look at
it and change it, and — the part that matters most in practice — how to get key
material *out* of it into a durable, reviewable form and back in again.

## What it holds

Three independent classes of key. They share a database and a command tree and
nothing else.

| Class | What it is | Used for |
|---|---|---|
| **DNSSEC** | KSK/ZSK/CSK private keys, one set per signed zone | online signing, key rollover |
| **SIG(0)** | per-zone private keys for signing DNS UPDATE | delegation sync to the parent, child-initiated updates |
| **TSIG** | shared HMAC secrets, keyed by key *name* | authenticating zone transfers and NOTIFY |

DNSSEC and SIG(0) keys are asymmetric and zone-scoped: the owner name of the key
is the zone it belongs to. TSIG keys are symmetric and *not* zone-scoped — a
TSIG key has a name of its own and any number of zones may reference it.

## Where it lives

```yaml
db:
   file:  /var/lib/tdns/tdns-auth.db
```

That is the whole configuration. There is no `keystore.path`; the keystore is
tables inside that database, alongside the daemon's other persistent state.

Each daemon has its own. `tdns-auth`, `tdns-agent` and `tdns-scanner` each
initialise a keystore from their own `db.file`; `tdns-imr`, `tdns-cli` and `dog`
have none. Do not point two daemons at the same `db.file` — it is not a
supported way to share keys, and they will fight over more than the keystore.

**Nothing reads the keystore directly.** Every operation goes through the
daemon's management API, which is why the CLI needs a working
`tdns-cli.yaml` and the daemon needs to be running:

```
tdns-cli auth keystore <class> <command>          # tdns-auth's keystore
tdns-cli agent keystore <class> <command>         # tdns-agent's keystore
```

The secrets are stored in cleartext. The SQLite file is a convenience store,
not an HSM: the API key and the file's permissions are the trust boundary, not
encryption at rest. Treat `db.file` exactly as you would treat a directory of
private keys.

### Not the keystore: the truststore

`tdns-cli auth truststore sig0` is a different store with a confusingly similar
name. The keystore holds **our own private keys**; the truststore holds **other
people's public keys** — the child SIG(0) keys a parent has decided to trust for
delegation updates. Nothing in this page applies to it.

## Key states

DNSSEC and SIG(0) keys carry a state. It is the rollover engine's view of where
a key is in its life, and getting it wrong is the main way a restore can go
subtly bad (see [Durability](#durability-getting-keys-out-and-back) below).

| DNSSEC state | Meaning |
|---|---|
| `created` | exists in the keystore, not published anywhere |
| `published` | DNSKEY is in the zone; not yet signing |
| `ds-published` | the parent's DS for this key is visible |
| `standby` | published and ready, waiting to be promoted |
| `active` | signing |
| `retired` | no longer signing; signatures may still be cached |
| `removed` | fully withdrawn; kept only for audit until purged |

SIG(0) keys use a shorter ladder: `created`, `published`, `active`, `retired`.

TSIG keys have no state — a shared secret is either present or it is not.

For what drives keys between these states, see
[Automatic DNSSEC Rollovers](key-rollover.md).

## The command tree

Every command below is prefixed `tdns-cli auth keystore` (or `agent`).

### Looking

| Command | |
|---|---|
| `<class> list` | everything in that class. Private material is redacted |
| `dnssec policies` | the DNSSEC policies the daemon loaded, including any that failed to parse |
| `<class> algorithms` | the algorithms *this daemon binary* links — worth checking before generating a PQ key |
| `dnssec gen-ds --zone Z` | DS records computed from the zone's KSKs. Read-only |

`tsig list` deliberately never shows secrets. `tsig export <keyname>` is the one
command that does, because handing you the secret is its entire purpose (add
`--bind` or `--nsd` to get a complete key block instead of the bare secret).

### Creating

```
tdns-cli auth keystore dnssec generate --zone example. \
    --keytype KSK --state active --algorithm ED25519

tdns-cli auth keystore sig0 generate --zone example. \
    --state active --algorithm ED25519

tdns-cli auth keystore tsig generate --name xfr-key-2026. \
    --algorithm hmac-sha256
```

`--keytype` is `KSK`, `ZSK` or `CSK`. For a zone with `online-signing` and a
DNSSEC policy you normally do **not** call `generate` at all — the daemon
creates what the policy calls for on first load. Reach for it when
pre-provisioning keys deliberately, which is exactly what a restore does.

`import` / `add` bring in an existing key pair from BIND-convention files;
`export` writes one key back out to such files. For moving more than one key at
a time, use the bulk commands below.

### Lifecycle

| Command | |
|---|---|
| `dnssec setstate` | move one key to another state by hand |
| `dnssec rollover` | one manual step: standby → active, active → retired |
| `dnssec auto-rollover …` | the rollover engine. See [key-rollover.md](key-rollover.md) |
| `dnssec ds-push`, `dnssec query-parent` | parent-side DS submission and polling |
| `dnssec policy`, `dnssec policy-cleanup` | policy utilities; drop a zone's retired keys and their RRSIGs |

### Removing

| Command | |
|---|---|
| `<class> delete` | one key, by keyid |
| `dnssec clear --zone Z` | **every** DNSSEC key for a zone. The daemon will regenerate per policy |
| `dnssec purge` | keys in `removed` state, keeping the 3 most recent per zone |
| `tsig purge` | unreferenced `api`-origin TSIG keys owned by `api` |

### Durability

| Command | |
|---|---|
| `<class> bulk-export --dest DIR` | write a selected subset out to a directory |
| `<class> bulk-import --src DIR` | read such a directory back in |

Covered in full below.

## TSIG keys have an origin

A TSIG key reaches the keystore one of two ways, and the difference constrains
what you may later do to it.

Keys declared in the config file under `keys.tsig:` are synchronised into the
keystore at startup as `origin=config` rows. Keys created at runtime through the
CLI or API get `origin=api`. Those two are the only valid origins. See
[tdns-auth configuration](config-tdns-auth.md#tsig-configuration) for the config
side.

`tsig delete`, `tsig setowner` and `tsig purge` only act on `api`-origin keys.
A config-origin key is owned by the config file — deleting it from the keystore
would just bring it back on the next restart, so the CLI refuses instead of
pretending.

## Durability: getting keys out and back

The keystore is a SQLite file. That is fine for a running server and bad for
everything else:

- **It cannot be reviewed.** There is no way to see a zone's keys in a diff, a
  code review, or a config repo.
- **It cannot be versioned.** A lab or testbed rebuilt from a git repository
  gets its zone files and its config back but not its keys — so every committed
  DS record in every parent is wrong the moment the machine is rebuilt.
- **Losing it loses everything.** One file is the single point of unrecoverable
  loss for every key of every zone the server signs.

Bulk export/import plus startup pre-load is the answer to all three.

### Exporting

```
tdns-cli auth keystore dnssec bulk-export --dest /etc/tdns/keys/dnssec \
    --zones pq.example.
```

Selection is additive and repeatable:

- `--zone example.` — that name exactly.
- `--zones example.` — that name **and everything below it**. Matching is on
  label boundaries, so `--zones pq.example.` does not also pick up
  `notpq.example.`.
- neither — the whole class. That is the whole-keystore backup case; the command
  says so before it does it.
- `--zones .` is the root's subtree, i.e. everything. `--zone .` is the root
  zone alone.

For TSIG the flags are `--key` / `--keys`, with the same semantics — TSIG keys
are named rather than zone-scoped, so calling them zones would be a lie.

**Re-exporting into the same directory merges.** Entries for keys this run did
not cover are left in place, so several narrow exports compose:

```
tdns-cli auth keystore dnssec bulk-export --dest /etc/tdns/keys --zones pq.example.
tdns-cli auth keystore dnssec bulk-export --dest /etc/tdns/keys --zone example.
tdns-cli auth keystore tsig   bulk-export --dest /etc/tdns/keys
```

leaves all three sets in one directory. Entries are sorted on write, so
re-exporting an unchanged keystore produces a byte-identical file — these
directories are meant to live in version control, where a reordered manifest is
noise that hides the real change.

### What an export directory looks like

```
/etc/tdns/keys/dnssec/
    manifest.yaml
    Kpq.example.+015+37134.key          # zone-file DNSKEY RR text
    Kpq.example.+015+37134.private      # PKCS#8 PEM, as the keystore stores it
    Kpq.example.+015+52388.key
    Kpq.example.+015+52388.private
```

The manifest is not decoration, and an export directory without one is not
usable. A `K<name>+<alg>+<keyid>.{key,private}` pair records nothing about
**key state** and nothing about **when** the key reached it. Restore a key into
the wrong state and you either flatten a zone mid-rollover, or — for a published
key with no `published_at` — restart its propagation clock. So the manifest
carries the metadata the BIND file convention has nowhere to put:

```yaml
# tdns keystore export manifest (v1) -- generated, but safe to read.
# Restored by 'keystore <class> bulk-import' and by keystore.preload at startup.
version: 1
dnssec:
    - zone: pq.example.
      keyid: 37134
      flags: 257
      algorithm: ED25519
      state: active
      creator: api-request
      active_at: "2026-08-06T08:58:39Z"
      private_file: Kpq.example.+015+37134.private
      public_file: Kpq.example.+015+37134.key
sig0:
    - zone: example.
      keyid: 12345
      algorithm: ED25519
      state: active
      private_file: Kexample.+015+12345.private
      public_file: Kexample.+015+12345.key
tsig:
    - keyname: xfr-key-2026.
      algorithm: hmac-sha256.
      secret: PvVrW0nqbJ8AVYQfI3BVJMHZtSEKRAVmvGxnJ0VvX48=
      origin: config
      owner: rollover-2026
```

Worth knowing about the format:

- **One manifest can carry all three classes.** A manifest describes whatever is
  in its directory, so pointing several pre-load settings at one directory works,
  each reading only its own section.
- **TSIG keys have no key files.** The secret *is* the key material, so it lives
  inline. That is why the manifest is written mode 0600 — and why the whole
  directory should be 0700.
- **File names are recorded, not derived.** The read side never has to turn
  `MLDSA87` into `201` to find a file, so a key restores correctly even into a
  binary that does not link its algorithm.
- Optional fields are omitted rather than written empty, and a manifest from a
  newer format version is refused rather than half-understood.

### Importing

```
tdns-cli auth keystore dnssec bulk-import --src /etc/tdns/keys/dnssec
```

Each key gets one of four outcomes:

| Outcome | When |
|---|---|
| `imported` | not in the keystore — inserted |
| `unchanged` | present and identical — left alone |
| `conflict` | present and **different** — reported and **skipped** |
| `replaced` | present and different, with `--force` |

The conflict rule is the important one, and it is deliberate: **the running
keystore outranks a file on disk.** An export is a snapshot that may be
arbitrarily stale. If it were allowed to overwrite live rows, a forgotten export
directory would silently un-roll a rolled key, and the symptom — a suddenly
stale DS at the parent — would surface nowhere near the cause. So the default
refuses, names the fields that differ, and changes nothing.

`bulk-import` exits non-zero when anything conflicted, so a build script cannot
mistake a partial restore for a good one.

`--force` flips conflicts to overwrite. That is the recovery path, for when the
thing you are restoring *from* is the correct copy and the keystore is the wrong
one.

An import is all-or-nothing: one invalid key rolls the whole batch back.

**What is checked.** The private key is stored verbatim, never parsed — which is
what lets a key restore into a binary that has no implementation for its
algorithm (it will fail later, loudly, if the zone tries to sign with it). It is
checked for PKCS#8 PEM armour, though, because that is what the keystore column
holds; see [key formats](#key-formats) below. The public half *is* parsed, as a
cheap crypto-free consistency check: owner name must match the zone, flags and
keytag must match what the manifest claims. That catches a manifest that has
drifted from its own files.

### Key formats

Private keys are **PKCS#8 PEM** everywhere inside tdns — that is what the
keystore column holds, and `export` and `bulk-export` write it out unchanged:

```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC6yHwqbCmGr+aAPEfQKDIqWBPfdFhy3erXHhdsPqeKT
-----END PRIVATE KEY-----
```

The public half is *not* PEM. A `.key` file holds the record in zone-file
presentation format, per the BIND convention:

```
pq.example.	3600	IN	DNSKEY	257 3 15 aIufB25wu/A9nLOZOm7ZlAxkdQyeCqAQcH7wMCg8DVo=
```

TSIG has neither: the secret is base64, and it lives in the manifest.

The two import paths differ, deliberately:

- **`keystore <class> import`** (one key) accepts PEM *or* the classic BIND
  `Private-key-format: v1.3` layout, converting the latter on the way in. That
  is how you bring in a key generated by `dnssec-keygen` or another tool.
- **`bulk-import`** accepts PEM only, and refuses anything else with a message
  pointing at the single-key command. It stores the blob verbatim, so accepting
  a BIND-format key would mean writing a non-PEM value into the PEM column — a
  mistake that would surface only later, as an unsignable zone.

### Pre-loading at startup

Having the key material in a directory is only half the problem. A signed zone
that comes up against an empty keystore mints its own keys, and by then it has
already published a DNSKEY set no parent's DS matches. Importing afterwards
means racing the signer and cleaning up after it.

```yaml
keystore:
   preload:
      dnssec:  /etc/tdns/keys/dnssec
      sig0:    /etc/tdns/keys/sig0
      tsig:    /etc/tdns/keys/tsig
```

Each directory is loaded at startup **before zones are parsed**, so a signed
zone finds its keys already present and adopts them. Correct by construction
rather than by winning a race.

Setting a directory is the whole switch — there is no separate enable flag, so
"enabled, but no directory" cannot be expressed. Classes left unset are not
touched.

Pre-load is create-if-absent, exactly like `bulk-import` without `--force`.
On each boot you get one summary line per class:

```
[INFO/config] keystore pre-load complete class=dnssec dir=/etc/tdns/keys/dnssec \
              imported=6 unchanged=0 conflicts=0 replaced=0
```

and a WARN naming each key whose on-disk copy differs from the keystore's —
those are skipped, the keystore wins.

Some failures abort startup rather than warn: a configured directory that does
not exist, a manifest that cannot be read, a manifest that disagrees with its
own key files. A pre-load that half worked is the state this feature exists to
rule out. A directory readable beyond its owner gets a warning, not a refusal.

### overwrite-existing-keys

```yaml
keystore:
   preload:
      dnssec:  /etc/labconfig/master/tdns-auth/keys
      overwrite-existing-keys:  true
```

This inverts the conflict rule for every configured class: an on-disk key that
differs **replaces** the keystore's copy.

It exists for hosts that are rebuilt from a repository — a training lab master,
say, where the committed export *is* the source of truth and the keystore is
disposable. That case wants a build script with no manual reconcile step in the
middle, and without this it does not have one.

It is dangerous everywhere else, in a specific way. `bulk-import --force` is one
shot, aimed, at a moment you chose. This stays armed on **every restart**, so a
stale committed export can silently revert a key you rolled by hand months
later, during a restart that had nothing to do with keys and that nobody was
watching.

Two things make that survivable, and both are deliberate:

- every replacement is logged at WARN, naming the key and what changed;
- the setting itself is announced at WARN on **every** boot, before anything is
  touched — not only on the boots where it changes something — so the log always
  records which mode the host was in.

If you would rather not arm it, the alternative for a scripted build is to
delete the keystore file before first start. An empty keystore has nothing to
conflict with, so pre-load imports everything cleanly.

### Worked example: a host rebuilt from a repository

On a live server, once the keys exist:

```
tdns-cli auth keystore dnssec bulk-export --dest /etc/tdns/keys/dnssec --zones example.
tdns-cli auth keystore tsig   bulk-export --dest /etc/tdns/keys/tsig
```

Commit both directories alongside the zone files and the config, and point the
config at them:

```yaml
keystore:
   preload:
      dnssec:  /etc/tdns/keys/dnssec
      tsig:    /etc/tdns/keys/tsig
```

A rebuilt server now starts with the same keys it had before, which means every
DS record you committed next to them is still correct, and every TSIG-protected
transfer still authenticates. No manual step, and nothing to remember.

Re-export after anything that changes keys — a rollover, a new zone — and commit
the diff. The manifest is sorted and stable, so the diff shows exactly which
keys moved.

## See also

- [tdns-auth configuration](config-tdns-auth.md) — `db.file`, and declaring TSIG
  keys in the config file
- [Automatic DNSSEC Rollovers](key-rollover.md) — what moves DNSSEC keys between
  states
- [Post-Quantum DNSSEC](pq-dnssec.md) — which algorithms a given binary links,
  and what `keystore <class> algorithms` reports about each
- [Certificate Provisioning](cert-provisioning.md) — the *other* private-key
  store, for TLS. Unrelated to the keystore: `tdns-cli cert` keeps plain PEM
  files on disk
