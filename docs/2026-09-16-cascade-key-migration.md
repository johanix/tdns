# Moving a zone from Cascade to tdns with the same keys

**Status:** proposal, under review. Q1–Q7 decided (r2).
**Repos:** tdns (converter, Ed448 registration), dnssec-algorithms (Ed448 implementation), johanix/dns fork (one comment)
**Read at:** tdns `49df2c3a`; tdns-mp `2c25bcd`; dnssec-algorithms `5462dd5`; Cascade `v0.1.0-beta6` and `main` `57e2565`; dnst `v0.2.0-alpha3` and `main` `f696f0a9`; domain 0.12.1 (dnst's), `8abed138` (Cascade's) and `main` `849de477`
**Related:** tdns-mp `docs/2026-09-13-key-lifecycle-ownership-design.md` (KLO) and its test plan `docs/2026-09-14-key-lifecycle-ownership-test-plan.md`

## Revision history

| Rev | Date | Change |
|---|---|---|
| r1 | 2026-09-16 | First version. |
| r2 | 2026-09-16 | Johan's answers: Q1–Q7 decided. Q6 extended to multi-signer zones moving to tdns-mpsigner: foreign keys come from the incoming zone, not from the conversion, and a new `--multi-signer` flag says so (§5.2, §5.3). §6.1 gains the multi-signer verification, §7 the multi-provider own-key import. F1 filed as #668. |

---

## 1. Goal

A zone is signed bump-on-the-wire by NLnet Labs' Cascade, with its keys in files (no HSM). The zone is to move to tdns-auth or tdns-signer, signing with **the same keys**, so the parent's DS stays as it is.

**What has to be right:**
- **The signing keys.** The keys tdns signs with must be the keys Cascade signs with: the ZSKs for zone data, the KSKs (or the CSK) for the DNSKEY RRset. This is the tdns state `active`.
- **The DNSKEY RRset.** tdns must serve the same keys Cascade serves, so that a validator holding Cascade's DNSKEY RRset in cache can validate tdns's signatures.
- **The key with a DS.** The KSK or CSK the parent's DS points at must be active in tdns.

**What can be approximate.** The zone uses short TTLs and short RRSIG lifetimes. A key that is on its way in or out of the DNSKEY RRset can land in a neighbouring tdns state, as long as it doesn't change which keys sign or which keys are published. The recommended procedure (§6) migrates only when no key roll is in progress, which removes those keys altogether.

## 2. What exists

### 2.1 Cascade

Cascade leaves key management to `dnst keyset`. For a zone with file-backed keys, `keys-dir` (default `/var/lib/cascade/keys`) holds:

- **One key pair per key:** `K<zone>.+<alg>+<tag>.key` (the DNSKEY RR as zone-file text, mode 0644) and `K<zone>.+<alg>+<tag>.private` (mode 0600). dnst writes the private half with domain's `SecretKeyBytes::display_as_bind` as `Private-key-format: v1.2`. Cascade's signer reads it back with `parse_from_bind`.
- **One state file per zone,** `<zone>.state`, JSON (§5.1). It lists every key with its role, its state and six timestamps, and it holds the DNSKEY, CDS and CDNSKEY RRsets dnst signed.
- **One config file per zone,** `<zone>.cfg`, dnst's key policy. The converter does not read it.

Cascade has no export command, and needs none: the key files are already in BIND format.

**Cascade's default policy** (`v0.1.0-beta6`, policy file v1):
- a KSK and a ZSK, not a CSK;
- ECDSAP256SHA256;
- NSEC;
- DNSKEY TTL 1 hour;
- zone signatures valid 14 days;
- automatic rolls on: double-signature KSK rolls and pre-publish ZSK rolls.

The tdns policy for a migrated zone has to match the zone's actual keys, whatever the Cascade policy was (§6.1).

### 2.2 tdns

- **The export directory** (`v2/keystore_manifest.go`): `K<zone>+<alg>+<keyid>.key` with the public RR, `.private` with the private key as PKCS#8 PEM, and `manifest.yaml` (version 1) with one entry per key: zone, keyid, flags, algorithm, state, creator, comment, `published_at`, `active_at`, `retired_at`, `active_seq`, and the two file names.
- **`keystore dnssec bulk-convert --dir <dir>`** (`v2/bind_convert.go`) turns a directory of BIND keys into an export directory, **in place**: each `.private` is rewritten as PEM (the original kept as `.private.orig`) and the manifest is written. State comes from BIND's per-key `.state` file, or from `--state` for keys without one. Before writing anything it parses every key and proves each pair belongs together by signing and verifying.
- **`keystore dnssec bulk-import --src <dir>`** and **`keystore.preload.dnssec: <dir>`** (`v2/keystore_bulk.go`, `v2/keystore_preload.go`) load an export directory into the keystore. Pre-load runs before any zone is parsed, so a signed zone finds its keys already there instead of minting its own.
- **Import goes through the keystore's one insert function.** Since KLO S1a, `BulkImportDnssec` inserts through `insertKeyRowTx` (`keystore_bulk.go:423`). The row gets `pub` and `sign` from its state, and `ds` once the zone's policy binds (S1b). An imported `active` key is therefore `pub=1, sign=1`, and an active KSK gets `ds=1` in every DS model.

`bulk-convert` already reads Cascade's key files: tdns's parser accepts `v1.2` as well as `v1.3` (the fork's `dnssec_keyscan.go:36`). Three things are missing:

1. **State.** Cascade writes no per-key `.state` file. Its state is in `<zone>.state`, which `bulk-convert` does not read. `--state` sets one state for every key in the directory.
2. **Timestamps.** dnst writes no timing lines into `.private`, so the manifest gets none. Cascade's timestamps are in the state file.
3. **Ed448.** Cascade can generate Ed448 keys (algorithm 16). tdns cannot parse, sign with or validate Ed448, so converting such a key fails at the PEM step.

In-place conversion is also wrong for Cascade: run on `keys-dir`, it would replace the files Cascade's signer reads with PEM.

---

## 3. Relationship to key lifecycle ownership (KLO)

KLO is rebuilding the keystore's write paths, the signer's key selection (`pub`/`sign`/`ds` columns), the DS engine's inputs and the ownership of key lifecycles. S1a, S1b and S2 are merged; S3 is in review; S4–S6 follow.

**This design's first step changes nothing inside the keystore or the signer.** It needs:

| Needs | Where | Touched by KLO? |
|---|---|---|
| The export-directory format, manifest version 1 | `keystore_manifest.go` | No. |
| tdns's DNSSEC state names for zones tdns owns | `structs.go`, `keyFlagsForState` in `keyrow.go` | No. KLO moves only the multi-provider states out of tdns (S4); single-provider zones stay tdns-owned. |
| Import through the one insert function | `keystore_bulk.go`, `keyrow.go` | Already done (S1a/S1b). |
| An algorithm registered with its PKCS#8 codec | `v2/algorithms`, dnssec-algorithms, the fork's registry | No. Signing and validation reach a registered algorithm through `crypto.Signer` and the fork's registry, with no per-algorithm code in the signer. |

**So step 1 is:**
- **1a:** Ed448 (§4).
- **1b:** a Cascade converter that writes an export directory (§5).

Both can land while KLO is in progress.

**What waits for KLO to conclude (§7):** every change inside the signer or keystore that a migration exposes. The first one is already known (§6.3, F1).

---

## 4. Step 1a: Ed448

### 4.1 Implementation

A new package `ed448/` in dnssec-algorithms, next to `mldsa44/`:

- **A `dns.Algorithm`** over CIRCL's `sign/ed448`, which is pure Go and already a dependency of the module.
  - 57-byte public key, 114-byte signature, 57-byte private key (the seed).
  - Ed448 as RFC 8080 takes it from RFC 8032: pure Ed448 with an empty context string, not Ed448ph. The RFC 8080 §6.2 examples pin this down.
  - `Hash()` returns 0: the signed bytes go to the signer unhashed, as for Ed25519.
  - BIND private format: one `PrivateKey:` line with the base64 seed, the form domain writes (`Algorithm: 16 (ED448)`).
- **A PKCS#8 codec** (`pkcs8.go`) for OID 1.3.101.113 (RFC 8410), registered with `dnsalgpkcs8.Register`. tdns stores private keys as PKCS#8 PEM and `PrepareKeyCache` encodes to PEM on the read path (`readkey.go`), so without a codec an Ed448 key would not load for signing at all.

### 4.2 Registration: in every binary

Ed448 is a standard algorithm (RFC 8080) that every validator is expected to implement, not an experiment. **Decided (Q2):** register it the way Ed25519 is present, in every tdns binary, rather than as a line in each app's `algs.list`.
- **Where:** `v2/algorithms`' `init` calls `Register(16, ed448.New(), dnssecCaps, facts)` next to the built-in records.
- **Why not `algs.list`:** tdns has seven of them (agent, auth, cli, dog, imr, ncli, signer), and tdns-mp has its own. A binary left out cannot sign or validate Ed448; a validator treats an Ed448-only zone as insecure.
- **Cost:** `tdns/v2` imports `dnssec-algorithms/ed448` and so links CIRCL (pure Go, no cgo). tdns's pin of dnssec-algorithms moves from `v0.0.0-20260513135759-676b5158decd` to a version with the package.
- **genalgs must not register it a second time.** Either ED448 stays out of `dnssec-algorithms/registry`'s generator table, or genalgs skips table entries tdns registers itself. The `record` promotion rule allows metadata then real, and refuses two real registrations.

### 4.3 The fork

No code change. `builtinAlgorithms` (`algorithm.go:106-118`) does not include 16, so `RegisterAlgorithm(16, …)` succeeds, and the dispatch tables have no ED448 arm to shadow it. Two comments claim ED448 is built in (`algorithm.go:19`, `:98`); they are wrong and should be corrected.

### 4.4 Tests

- The RFC 8080 §6.2 Ed448 examples: DNSKEY, DS and RRSIG verify; signing the example RRset reproduces the RRSIG (Ed448 is deterministic).
- PKCS#8 round trip, and a PEM from OpenSSL (`genpkey -algorithm ED448`) parses.
- A `.private` written by domain (dnst or Cascade) converts to PEM and signs.
- tdns-imr validates an Ed448-signed zone; a policy with `ED448` passes the config check.

---

## 5. Step 1b: converting Cascade keys and state

### 5.1 The state file

`dnst keyset` writes the file with serde's derived serialization (`serde_json::to_string_pretty`, dnst `src/commands/keyset/cmd.rs`). The format is the same in dnst `v0.2.0-alpha3` (domain 0.12.1), in Cascade `v0.1.0-beta6` (which reads it with domain `8abed138`) and on both main branches. None of the repositories ships a real state file; the description below is derived from source, and the fixtures in §6.4 have to come from a running Cascade.

**Fields the converter reads:**

| Field | Content | Used for |
|---|---|---|
| `keyset.name` | the zone, without a trailing dot (`"example.com"`) | the manifest's zone |
| `keyset.keys` | a map from the public key's URL (`file:///…/K….key`, or `kmip://…`) to the key | one entry per key |
| `privref` | the private key's URL, or `null` for a public-only key | the private file; §5.3 item 3 |
| `keytype` | `{"Ksk":S}`, `{"Zsk":S}`, `{"Include":S}`, or `{"Csk":[S_ksk,S_zsk]}` (index 0 is the KSK role) | role and state |
| a state `S` | five booleans: `available`, `old`, `signer`, `present`, `at_parent` | §5.4 |
| `algorithm`, `key_tag` | numbers | §5.3 item 4 |
| `timestamps` | `creation`, `published`, `visible`, `ds_visible`, `rrsig_visible`, `withdrawn`, each `{"secs":N,"nanos":N}` or `null` | §5.5 |
| `keyset.rollstates` | a map from roll type (`KskRoll`, `KskDoubleDsRoll`, `ZskRoll`, `ZskDoubleSignatureRoll`, `CskRoll`, `AlgorithmRoll`) to its step; `{}` when no roll is in progress | §5.3 item 2 |
| `apex_extra` | the records Cascade puts at the apex, the signed DNSKEY RRset among them. Older files may carry them only in `dnskey_rrset`. | §5.3 item 6 |
| `ds_rrset` | the DS records for the parent | §5.3 item 6 |

`cds_rrset`, `ns_rrset`, `apex_remove`, `cron_next`, `kmip`, `internal` and `decoupled` are not needed.

**What the flags mean to Cascade:**
- **Zone data** is signed by every ZSK whose state has `signer`, and every CSK whose ZSK-role state has it, provided the key has a private key (Cascade `src/signer/keys.rs`).
- **The DNSKEY RRset** holds every key whose (KSK-role) state has `present`. It is signed by every KSK, or CSK in its KSK role, whose state has `signer` (dnst `cmd.rs`).
- **The DS set** and CDS/CDNSKEY hold the keys with `at_parent`.
- **Cascade's own labels** combine the booleans: Future, Incoming, Active, Leaving (old and still signing), Retired (old, published, not signing), Stale (old and gone).

### 5.2 The command

**Decided (Q1):** `keystore dnssec bulk-convert --from cascade --state-file <zone>.state [--state-file …] --dest <dir> [--keys-dir <dir>] [--allow-roll-in-progress] [--multi-signer]`.

- `--from bind` (the default) keeps today's behaviour, including `--state`, the state for BIND keys without a `.state` file. The Cascade flag is `--state-file` so the two don't collide.
- **`--from cascade` never writes to the source.** It reads the state files and the key files they name, and writes a new export directory at `--dest`. It refuses a `--dest` that holds any file it read. Cascade's `keys-dir` stays usable by Cascade, which is also what makes a rehearsal harmless.
- **Key files are found by base name.** A state file names each key by an absolute `file://` URL on the Cascade host. The converter takes the URL's base name and looks for it in `--keys-dir`, which defaults to the state file's own directory. That works both for the live directory and for a copy.
- **`--multi-signer`** states that the target is tdns-mpsigner in a multi-signer zone, where the other signers' keys arrive in the incoming zone (§5.3 item 3, Q6).
- **Several state files, one destination:** one run can move many zones.
- **Offline,** like `bind` conversion: no daemon, no API, no keystore.

### 5.3 What it checks

The converter reads and checks everything before it writes anything, as the BIND conversion does:

1. **The state file parses** into the fields the converter needs. Unknown fields are ignored (the format is a pre-1.0 serialization, and newer releases add fields with serde defaults). Missing required fields are refused.
2. **No key roll is in progress:** `rollstates` is `{}`. Otherwise the converter refuses, unless `--allow-roll-in-progress` is given (§5.4; decided, Q3).
3. **Every key to convert is file-backed.**
   - A `kmip://` reference is refused: the private key is in an HSM, outside this design.
   - **A key with no private key** (`privref` is `null`, as for an `Include` key) is another signer's key. It is never written to the export directory, but it is listed in the report with its key tag, flags, algorithm, `present` and `at_parent`. The cross-checks in item 6 count it.
   - **Such a key with `present` is refused unless `--multi-signer` is given.** tdns-auth and tdns-signer build the DNSKEY RRset from their own keystore rows only, so the zone would lose the other signer's key. tdns-mpsigner instead takes the other signers' keys from its incoming zone (Q6).
4. **Every key file agrees with its state entry:** algorithm and key tag from the `.key` file match the entry, and the SEP bit matches the role (KSK and CSK have it, ZSK does not).
5. **Every pair belongs together:** parse the `.private`, re-encode it as PEM, sign and verify against the `.key` (`PrepareKeyCache` and `VerifyKeyPairCorrespondence`, as `bind_convert.go` does).
6. **The mapping reproduces what Cascade serves.** A mismatch in either check is refused.
   - **DNSKEY RRset:** the keys mapped to a state with `pub=1`, together with the other signers' keys that have `present`, must be exactly the DNSKEY records in `apex_extra` (or `dnskey_rrset`), compared as RDATA.
   - **DS set:** with no roll in progress, two sets must be the same, and must also match the keys `ds_rrset` names when it is not empty:
     - the active KSKs and CSKs, together with the other signers' keys that have `at_parent`;
     - all keys with `at_parent`.
   
   These checks prove, for this zone, that §5.4 got "active" right.

### 5.4 State mapping

A key's effective state is its state for a KSK or ZSK. For a CSK, `signer` is true if either role signs, and `old`, `present` and `at_parent` come from the KSK role, which decides DNSKEY membership and the DS.

| Cascade (`old`, `signer`, `present`, `at_parent`) | Cascade label | tdns state | `pub` | `sign` |
|---|---|---|---|---|
| any, **true**, true, any | Active, Leaving | **active** | 1 | 1 |
| false, false, true, true (KSK or CSK) | Incoming, DS at parent | standby | 1 | 0 |
| false, false, true, false | Incoming | published | 1 | 0 |
| true, false, true, any | Retired | retired | 1 | 0 |
| false, false, false, true | Future, DS at parent | ds-published | 0 | 0 |
| false, false, false, false | Future | not converted | | |
| true, false, false, any | Stale | not converted | | |

A key that signs but is not present is refused: tdns requires `sign` to imply `pub`, and dnst's roll sequences never produce such a key.

`ds` is not set by the converter. tdns resolves it from the state and the zone's DS model when the policy binds (KLO Amendment 1): an active KSK gets `ds=1` in every model.

**With no roll in progress,** which is the default, only the first row and the last two occur. That follows from dnst's roll sequences (`keyset.rs`):
- every roll starts from a new key that is Future;
- every roll ends when the old key is Stale and the roll's entry is removed from `rollstates`.

In a steady state every published key signs. The mapping then reduces to "present means active", and §5.3 item 6 proves it for the zone at hand.

**With `--allow-roll-in-progress`** the other rows occur. tdns does not continue Cascade's roll: the zone lands in a state tdns keeps, and the operator finishes the roll with tdns's keystore commands. Examples:
- **Mid-ZSK roll:** the incoming ZSK becomes published, and tdns's key state worker moves it to standby after propagation; or the outgoing ZSK becomes retired and is removed after tdns's margin.
- **Mid-KSK roll:** both KSKs are active, and both get `ds=1`.
- **Mid-CSK roll:** a new CSK whose KSK role signs and whose ZSK role does not yet sign becomes active in both roles. tdns has no state for a key that signs the DNSKEY RRset but not the zone data.
- **`ds-published`** is the multi-DS pipeline's state. Under another DS model a key stays there until the operator moves it.

### 5.5 Timestamps

Cascade's times are Unix seconds and nanoseconds; the manifest takes RFC 3339 in UTC (as `BindTimeToRFC3339` writes it), with the nanoseconds dropped. Most of Cascade's times record when a change was seen to propagate, where BIND's record a plan.

| Manifest | From Cascade | What tdns does with it |
|---|---|---|
| `published_at` | `published` | Moves a published key to standby once propagation time has passed. An empty value restarts that clock. |
| `active_at` | `rrsig_visible`, else `published` | The ZSK's lifetime counts from here, so tdns's first ZSK roll comes when Cascade's would have. |
| `retired_at` | the time of conversion | Removes a retired key once the margin has passed. Cascade records no "stopped signing" time. **It must not be empty:** the key state worker skips a retired key without `retired_at` on every tick, and the key is never removed (`key_state_worker.go:216`). |
| `active_seq` | not set | Filled in for active keys by the heal passes (`healBootstrapActiveAt` for a KSK under a rollover method, `healZskActiveAt` for a ZSK). |
| `comment` | `creation`, `visible`, `ds_visible`, `withdrawn` that are set, with Cascade's label | Not read by tdns. |

### 5.6 Output

Per key: `K<zone>+<alg>+<keyid>.key` (the public RR, canonical text), `.private` (PKCS#8 PEM, mode 0600), and a manifest entry with `creator: cascade` and a comment carrying Cascade's own label for the key, for example `cascade: KSK Active, at parent`. The destination directory is created 0700. The output is an ordinary export directory: `bulk-import` and `keystore.preload` read it unchanged.

---

## 6. Migration procedure and risks

### 6.1 Procedure

1. **Freeze Cascade's key rolls** for the zone (automatic roll start off in its policy), and wait until no roll is in progress: `rollstates` in the state file is `{}`.
2. **Convert** with `bulk-convert --from cascade`, from `keys-dir` itself or from a copy: the converter only reads it. Review the dispositions: every key, its tdns state, and the DNSKEY and DS cross-checks.
3. **Configure tdns** for the zone:
   - inline signing, with a DNSSEC policy that matches the imported keys: `mode` (`csk` or `ksk-zsk`) and the algorithms;
   - no automated KSK or ZSK rollover at first, so tdns starts no roll on the imported keys;
   - `keystore.preload.dnssec` pointing at the export directory.
4. **Start** tdns-auth or tdns-signer. Pre-load puts the keys in the keystore before the zone is parsed, and the zone signs with them.
5. **Verify before the cutover,** by querying tdns directly:
   - tdns's DNSKEY RRset has the same records as Cascade's;
   - tdns's RRSIGs validate against the DS the parent serves;
   - the CDS tdns publishes, if any, matches the parent's DS.
   - **For a multi-signer zone on tdns-mpsigner:** the other signers' DNSKEYs are served too. The signer records them as foreign rows when the zone arrives, and serves them from the re-sign that follows, not from the first publish (tdns-mp `hsync_utils.go`, the comment at the `syncForeignDNSKEYs` call). Compare after that re-sign.
6. **Cut over:** the servers that take the zone from Cascade take it from tdns instead. Then stop Cascade for the zone. Never let both sign or roll the zone.
7. **Later,** bind the zone to the policy with the rollover method it should have.

### 6.2 Risks

| # | Risk | Mitigation |
|---|---|---|
| M1 | Cascade starts a roll after the conversion; the two key sets diverge. | Freeze rolls first (§6.1 step 1). The converter refuses a roll in progress, and the DNSKEY cross-check refuses a state file that doesn't match its own RRset. |
| M2 | tdns's policy doesn't match the imported keys. An active KSK of another algorithm makes `reconcileActiveKeyAlgorithms` refuse to sign the zone. A missing role makes tdns mint a key. | Step 3 of the procedure; the verification in step 5 catches it before the cutover. |
| M3 | A CSK zone gains a ZSK at the first signing pass (F1, §6.3, #668). | Verify F1 before moving any CSK zone; until it is fixed, see F1. |
| M4 | tdns's CDS differs from what the parent holds. tdns publishes CDS with SHA-256 only (`ops_cds.go:42`). A parent that scans CDS and holds a DS with another digest type may replace the DS: still a valid chain, but a change at the parent. | Check the parent's DS digest type at step 5. |
| M5 | Denial of existence changes at the cutover. Cascade signs with NSEC by default, as tdns does. A zone configured for NSEC3 in Cascade becomes walkable under tdns. Validation is unaffected: each denial is self-contained. | An operator decision, not a validation risk. |
| M6 | The state file format changes between Cascade releases. It is a pre-1.0 serialization with no version field. | Tolerant parsing (§5.3 item 1), fixtures from each release (§6.4), and the cross-checks in §5.3 item 6. |
| M7 | The export directory holds private keys. | 0700 directory, 0600 files, as `bulk-export` writes them. |

### 6.3 Findings

**F1: a CSK-mode zone gets a ZSK.** `EnsureActiveDnssecKeys` (`sign.go:452`) returns early only when it finds an active KSK and an active key with flags 256. A CSK has flags 257, so it counts as "KSK reused as CSK" (`sign.go:513`), and the function mints an **active** ZSK (`sign.go:640`) without looking at `DnssecPolicy.Mode`. A throwaway test at `49df2c3a` confirms it: a zone bound to a `csk` policy, holding one active Ed25519 CSK, has an active CSK and an active ZSK after one call.

- **Which zones:** only CSK zones. Cascade's default is a KSK and a ZSK.
- **For a new zone** this is invisible: all its keys are new.
- **For a migrated CSK zone** the new ZSK signs the zone data before its DNSKEY reaches resolvers. Validators that cached Cascade's DNSKEY RRset fail validation until that RRset's TTL expires.
- **Independently of this migration,** a zone configured as CSK is not a CSK zone in tdns.
- **The fix is in the signer,** the code KLO is changing (§3.5 of that design lists `EnsureActiveDnssecKeys` among the lifecycle paths). It waits for KLO. Filed as #668.
- **Until then:** a CSK zone either migrates with a DNSKEY TTL short enough to accept a brief validation failure, or waits for the fix.

### 6.4 Tests

- **Fixtures:** real state files from Cascade `v0.1.0-beta6` with dnst `v0.2.0-alpha3`, and from the current releases, with their key files, with names and addresses replaced: a KSK+ZSK zone, a CSK zone, a zone in each roll type mid-roll, a zone with a public-only (`Include`) key, a zone with a KMIP key.
- **Converter:** golden manifests; each refusal in §5.3; a state file doctored to disagree with its own DNSKEY RRset is refused; `--dest` equal to the source is refused; a second run into the same destination is idempotent.
- **Import:** each fixture through `BulkImportDnssec` into a test keystore. The `sign=1` keys equal Cascade's signers, and the `pub=1` keys equal Cascade's DNSKEY RRset.
- **End to end:** a zone signed by Cascade, converted, pre-loaded into tdns-signer. tdns's DNSKEY RRset equals Cascade's, and tdns's signatures validate with a DS computed from Cascade's KSK. Once F1 is fixed, the CSK fixture as well.

---

## 7. After KLO concludes

Changes inside the signer and keystore, in order of value:

1. **F1:** `EnsureActiveDnssecKeys` honours `Mode: csk`.
2. **The rollover clock:** carry `active_at` from the manifest into the rollover bookkeeping. Today `healBootstrapActiveAt` (`ksk_rollover_automated.go:2155`) registers an imported active KSK that lacks a rollover row, so its lifetime starts again rather than continuing Cascade's.
3. **A roll in progress:** map Cascade's roll states onto tdns's rollover rows so tdns continues the roll rather than the operator waiting for it to finish.
4. **Import into a running daemon** for a zone that is already loaded and signing, instead of pre-load before the first start.
5. **A multi-provider zone's own keys.** The conversion itself is the same for tdns-mpsigner. What changes with KLO S3 and S5 is who adopts the imported keys:
   - tdns-mp's state machine owns the zone and writes its columns;
   - the zone's DS set follows D4;
   - foreign rows gain a provider and a state (tdns-mp #58).
   
   Whether the owner accepts an imported active key that has no distribution record is S3's question. The multi-signer procedure is validated end to end once S5 has landed.

---

## 8. Questions

| # | Question | Answer |
|---|---|---|
| Q1 | Extend `bulk-convert` with `--from cascade`, or add a verb of its own? | **Decided:** extend it: one command for "keys from another signer". `--dest` is required for Cascade; BIND conversion stays in place. |
| Q2 | Ed448 in every binary, or through `algs.list`? | **Decided:** every binary, not through `algs.list` (§4.2). |
| Q3 | Refuse a roll in progress, or convert with the approximate mapping? | **Decided:** refuse by default; `--allow-roll-in-progress` for a zone that cannot wait. |
| Q4 | A key that is leaving but still signs: `active` or `retired`? | **Decided:** `active`. It signs, and "active" is what must be right. |
| Q5 | A CSK with different states in its two roles? | **Decided:** active if either role signs; otherwise the KSK role decides (§5.4). This occurs only during a CSK roll. |
| Q6 | A public-only key (another signer's, `Include`), including a multi-signer zone moving from Cascade to tdns-mpsigner? | **Decided:** never convert it, and report it. Refuse a present one unless `--multi-signer`. Reasons below. |
| Q7 | Where do Cascade's other timestamps go (`creation`, `visible`, `ds_visible`)? | **Decided:** into the manifest comment. The manifest has no field for them. Adding one means manifest version 2, which every reader of export directories would have to learn. |

### Q6: other signers' keys

**tdns-mpsigner does keep foreign keys,** but it does not store them independently. `syncForeignDNSKEYs` (tdns-mp `signer_keydb.go`) runs on every incoming zone in multi-signer mode:
- every DNSKEY in the zone from the combiner that is not one of the signer's own keys becomes a foreign row;
- every foreign row whose DNSKEY is no longer in the incoming zone is deleted.

The foreign rows are a mirror of the combiner's DNSKEY RRset. A foreign row imported from a Cascade state file would therefore be either:
- **redundant:** the combiner carries the key, and the signer creates the same row itself; or
- **deleted at the next transfer:** the combiner does not carry the key.

Two more reasons not to import them:
- **Missing provenance.** After KLO S5, a foreign row carries the provider and that provider's state for the key (tdns-mp #58, D4). A Cascade state file knows neither.
- **Cascade got them from the same place.** Cascade replaces the incoming apex DNSKEY RRset with its own (`apex_remove`), so in a multi-signer arrangement the operator had to mirror the other signers' DNSKEYs into dnst as `Include` keys. On tdns-mpsigner that manual step disappears: the keys come straight from the incoming zone.

**The import path via tdns-mp** is therefore:
- the converter writes only the zone's own keys, the same export directory as for tdns-auth;
- tdns-mpsigner pre-loads them;
- the other signers' keys arrive with the zone.

What the Cascade state file still contributes is the check: the DNSKEY and DS cross-checks (§5.3 item 6) account for the `Include` keys. The verification before the cutover (§6.1 step 5) compares tdns-mpsigner's served RRset, foreign rows included, with Cascade's.

**Without `--multi-signer`,** a present `Include` key is refused. The target would be tdns-auth or tdns-signer, whose publish rebuilds the DNSKEY RRset from the keystore and drops whatever DNSKEYs the upstream carried. The other signer's key would vanish from the zone.

## 9. Size

| Part | Repo | Production | Tests |
|---|---|---|---|
| Ed448 algorithm and PKCS#8 codec | dnssec-algorithms | ~250 | ~300, plus RFC 8080 vectors |
| Ed448 registration, pin bump, genalgs exclusion | tdns | ~40 | ~80 |
| Fork comment | johanix/dns | 2 | – |
| State file reader and mapping | tdns | ~350 | ~400, plus fixtures |
| `--from cascade` in `bulk-convert` | tdns | ~250 | ~250 |
