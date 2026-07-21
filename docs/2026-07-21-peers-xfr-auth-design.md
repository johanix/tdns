# Peers, Per-Zone Transfer Authentication, and Transfer-Terminology Alignment

**Date:** 2026-07-21
**Scope:** `v2/` (module `github.com/johanix/tdns/v2`) and `cmdv2/`.
**Baseline:** builds on the XoT work (branch `feature/xot`, PR #314) and the
PKIX cert tooling (branch `feature/xot-cert-tooling`, PR #316, stacked on
#314). File/line anchors refer to those branches, not to `main`, which does
not yet carry the XoT code. Per the agreed stacking, the implementation of
this design lands as a **new PR on top of #316** (or on `feature/xot` after
#316 has been folded into it); nothing merges to `main` until the complete
design + implementation is accepted.
**Status:** design agreed in discussion 2026-07-21; ready to implement.
**Companion docs:** `docs/2026-07-20-xot-implementation-plan.md`,
`docs/2026-07-21-pkix-cert-tooling-design.md`, `docs/2026-07-21-xot-operations.md`.

---

## 1. Problems this design solves

1. **Server descriptions are repeated per zone.** A primary typically serves
   the same secondaries for hundreds of zones, and a secondary typically
   pulls from the same primary for hundreds of zones. Zone templates
   (`ExpandTemplate`, `v2/parseconfig.go:1172`) already gap-fill `Primaries`
   and `Downstreams`, which de-duplicates *per zone shape* — but a server
   referenced from two templates, or in different roles (transfer source
   here, notify target there), is still described in multiple places. Change
   one pin and you edit every place. What is missing is a *per-server*
   single source of truth.

2. **The TLS configuration is asymmetric between the two sides.** On the
   secondary, TLS details live per zone in the `primaries:` entries (which is
   correct). On the primary, they landed listener-wide in
   `dnsengine.downstream-auth` — an artifact of enforcing at the TLS
   *handshake*, which is inherently per listener. This is both confusing
   (agreed: "very strange") and operationally wrong, see next point.

3. **Listener-wide mTLS breaks ordinary DoT service.** The auth DoT listener
   serves normal queries (ADoT) as well as transfers. With
   `downstream-auth` set, *every* DoT client must present a client
   certificate, including cert-less resolvers that have no business having
   one. Two hard requirements (MUSTs) follow: ordinary queries (and
   transfers, ACL permitting) over DoT **without** a client cert must work,
   and ordinary queries and transfers over the other transports (Do53, DoQ,
   …) must work.

4. **The term "downstream(s)" describes secondaries** (and "upstream(s)"
   primaries) — a transfer relationship. It does not describe query clients,
   so a knob named `downstream-auth` must not gate them, and it belongs on
   the zone, not on the listener.

5. **The config vocabulary is mismatched.** `primaries:` is BIND9
   terminology while `downstreams:` is tdns terminology; NSD's
   request-xfr/provide-xfr pair appears only in code comments. No aliases
   exist in the decode layer today.

## 2. Agreed decisions (summary)

- **D1** One object kind, **`peers:`**, declared in a top-level `peers:`
  block. The name matches the existing internals (`PeerConf`,
  `SignForPeer`, `ClientTLSConfigForPeer`) — external vocabulary aligns
  with two dozen existing code names.
- **D2** Reference syntax: an entry of the form **`- peers: [ id1, id2 ]`**
  (plural list form only; singular is a one-element list) may appear in any
  of the four peer/ACL lists, freely mixed with inline entries, which keep
  working unchanged. No bare-string references: bare strings remain the
  legacy-config quarantine marker.
- **D3** Canonical documentation vocabulary is the tdns pair
  **`upstreams:` / `downstreams:`**. The BIND9 pair
  (`primaries:`/`secondaries:`) and the NSD pair
  (`request-xfr:`/`provide-xfr:`) are accepted as input aliases.
- **D4** Per-zone (and per-template) **`downstream-auth:`** — a list of
  acceptable authentication *mechanism classes* for outbound transfer of
  this zone: `[ prefix, tsig, tls-pin, tls-pkix, tls-dane ]`. Absent =
  unrestricted (exactly today's behavior). The concrete credentials live in
  the `downstreams:` entries and referenced peers; the list is policy, not
  data.
- **D5** Enforcement happens **at transfer time**, not at the TLS
  handshake. The DoT listener always uses `tls.RequestClientCert`
  (request, never require) — an implementation detail, not a config knob.
  Queries on every transport, and cert-less DoT clients, are unaffected.
- **D6** The `dnsengine` knobs `downstream-auth` / `downstream-pins` /
  `downstream-ca` / `downstream-names` are **removed outright** (they exist
  only on the unmerged #314/#316; nothing has ever run them). No
  per-listener mTLS knob replaces them: "drop non-TLS traffic" is already
  `dnsengine.transports: [ dot ]`, handshake-time rejection buys ~nothing
  over transfer-time REFUSED (the handshake is the expensive part either
  way), and tdns has no per-listener config granularity for a
  "transfer-only listener" anyway (that deployment shape = a second
  instance whose zones all carry a strict `downstream-auth`).
- **D7** DANE authentication of a *client* cert (`tls-dane`) is in scope:
  validate the presented certificate against the DNSSEC-validated TLSA
  RRset of the peer's name. (The earlier "no client name exists before the
  handshake" objection dissolves once verification moves to transfer time:
  the peer's configured name provides the TLSA base.)
- **D8** All documentation and examples use one vocabulary consistently
  (D3); error messages migrate in a cleanup sweep.

## 3. The `peers:` block

```yaml
peers:
   ns1-example:                       # identifier used in references
      addr: ns1.example.net:853       # outbound dial target (upstream role)
      prefixes: [ 198.51.100.7,       # inbound source match (downstream role);
                  2001:db8::7 ]       #   one server, several source addresses
                                      #   (dual-stack); default: addr's host
      keys: [ xfr-key-2026 ]          # TSIG key NAMES; NOKEY allowed (alone).
                                      #   Outbound: sign with the FIRST.
                                      #   Inbound: accept ANY listed.
                                      #   `key: x` is sugar for `keys: [x]`.
      # --- outbound TLS: how WE verify ITS server cert when we dial ---
      transport: dot                  # "" | do53 | dot (as in PeerConf today)
      tls-auth: pkix                  # pin | dane | pkix
      tls-name: ns1.example.net       # SNI + DANE base (defaults from addr)
      ca-file: /etc/tdns/certs/tdns-ca.crt
      pins: [ ... ]
      # --- inbound TLS: how WE verify ITS client cert when it dials us ---
      tls-identity:
         name: ns1.example.net        # SAN requirement (pkix) / TLSA base (dane);
                                      #   default: addr's hostname
         pins: [ "spki-b64=" ]        # enables satisfying tls-pin
         ca-file: /etc/tdns/certs/tdns-ca.crt   # enables satisfying tls-pkix
         dane: true                   # enables satisfying tls-dane (needs name)
```

Design points:

- A peer is a **superset of today's `PeerConf`**: the outbound fields map
  1:1 onto the existing struct, plus `prefixes` (inbound address match) and
  `tls-identity` (inbound certificate identity). One object serves both
  roles; which fields are consumed depends on where it is referenced.
- **`keys:` is a list to keep TSIG rollover a one-place edit.** Today's
  ACL grammar rolls a key by listing the same prefix twice with old and
  new key; a peer expresses the same thing as
  `keys: [ xfr-key-2026, xfr-key-2025 ]` — prepend the new key, migrate
  the peer, drop the old entry. Inbound, any listed key is accepted;
  outbound, where exactly one key must sign the request, the first is
  used. `NOKEY` is only valid as the sole element — mixing `NOKEY` with
  named keys inside one peer would recreate the NOKEY-shadows-TSIG footgun
  in a single object, and is rejected at config load.
- `tls-identity` is **data-driven**: whichever credentials are present
  determine which mechanisms this peer *can* satisfy (pins → `tls-pin`,
  ca-file → `tls-pkix`, dane+name → `tls-dane`). Which of those *suffice*
  is the zone's decision via `downstream-auth` (§5) — policy lives on the
  zone, data lives on the peer.
- **`tls-identity.ca-file` holds trust anchors only** — the root CA
  certificate(s), concatenated PEM; never an intermediate chain and never
  the peer's leaf. If the peer's cert was issued via intermediates
  (external PKI), those arrive in the TLS handshake as part of the
  *client's presented chain* and are used as intermediates by the
  server-side `x509.Verify`; the ca-file still holds only roots. Certs
  from the tdns minimal CA involve no intermediates at all.
- **Chain verification alone is not an identity** — any certificate the CA
  ever signed passes it. The identity pin is `tls-identity.name`: the
  `tls-pkix` mechanism requires chain **plus** leaf DNS SAN == name
  whenever a name is known. Because `name` defaults to the host part of
  `addr`, a normally-declared peer gets name-pinning by default; only a
  peer declared with neither an `addr` hostname nor a `name` (i.e. there
  is no name to check) degrades to chain-only semantics — the coarse
  "any member of this CA" policy, acceptable for a CA dedicated to
  transfer peers.
- `prefixes` defaults to the host part of `addr` (exact /32 or /128).
  Multihomed peers whose transfer requests originate from other addresses
  list them explicitly.
- Validation of the outbound fields reuses `validatePeerXoT` unchanged.
  Inbound: pins must be well-formed base64 SHA-256; `ca-file` readable PEM;
  `dane: true` requires a resolvable `name`; `NOKEY` must be alone in
  `keys`.

### 3.1 References

Any of the four lists may mix inline entries with references:

```yaml
zones:
   - name: example.com.
     type: secondary
     upstreams:                       # canonical spelling of primaries:
        - peers: [ ns1-example ]      # reference
        - addr: 203.0.113.5:53        # inline entry, unchanged
          key: NOKEY

   - name: example.net.
     type: primary
     downstreams:
        - peers: [ sec1, sec2, sec3 ]
        - prefix: 192.0.2.0/24
          key: NOKEY
```

Expansion happens at parse time (immediately after template expansion, so
templates may carry references too):

- In `upstreams:`/`notify:` a reference expands to the peer's **outbound**
  fields as an ordinary `PeerConf` (signing key = `keys[0]`) — the entire
  existing runtime (`resolvePrimaries`, the refresh engine, XoT) is
  untouched.
- In `downstreams:`/`allow-notify:` a reference expands to the
  **prefix × key cross-product** of `AclEntry`s — exactly the shape the
  hand-written rollover pattern produces today, so the ACL matcher is
  untouched — plus (downstreams only) the peer's `tls-identity` and name
  for the transfer-time check (§6).
- An unknown identifier quarantines the zone
  (`unknown peer "ns1-exmaple" (or legacy bare-address syntax?)`) — which
  also improves today's legacy bare-string error.
- `allow-notify:` keeps pure prefix+TSIG semantics (NOTIFY is Do53); a
  referenced peer contributes prefixes+key there, its `tls-identity` is
  ignored. `downstream-auth` gates transfers only.

## 4. Terminology aliases

A key-normalization pass runs over the decoded zone/template maps before
unmarshal:

| accepted spellings | canonical (internal) |
|---|---|
| `upstreams:`, `primaries:`, `request-xfr:` | `primaries` (mapstructure tag unchanged) |
| `downstreams:`, `secondaries:`, `provide-xfr:` | `downstreams` |

- Two spellings of the same field in one zone/template = config error
  (quarantine), never silent preference.
- The aliases are registered with the unknown-key warner and
  `config check`.
- **All documentation, sample configs, and examples use
  `upstreams:`/`downstreams:` exclusively** (D3/D8); the alias table is
  documented once in the config guide. Internal Go identifiers
  (`ZoneConf.Primaries` etc.) are not renamed — the mapstructure tags are
  the compatibility surface, not the field names. Error messages that say
  "primary/primaries" migrate to the canonical vocabulary as a cleanup
  sweep in the final phase.
- `notify:` and `allow-notify:` are not part of the mismatch and stay as
  they are.

## 5. Per-zone `downstream-auth:` — the mechanism ladder

```yaml
zones:
   - name: foo.bar.
     type: primary
     downstream-auth: [ tsig, tls-pkix ]     # policy: acceptable proof classes
     downstreams:                            # data: who, with what credentials
        - peers: [ sec1, sec2 ]
        - prefix: 10.0.0.0/8                 # legacy Do53 secondary
          key: xfr-key-2026
```

Mechanism classes, from weakest to strongest:

| Mechanism | The matched entry proved |
|---|---|
| `prefix` | source address only (entry key was `NOKEY`) |
| `tsig` | source address + valid TSIG |
| `tls-pin` | the above + client cert SPKI matching the entry's pins |
| `tls-pkix` | the above + client cert chaining to the entry's CA (+ SAN = entry name, when set) |
| `tls-dane` | the above + client cert matching the peer name's DNSSEC-validated TLSA |

Semantics (precise):

1. ACL matching is **unchanged**: collect every non-`BLOCKED` entry whose
   prefix matches the source; an entry with a named key requires a valid
   TSIG to count as matched; `BLOCKED` supersedes everything.
2. For each matched entry, compute the **satisfied mechanism set**: the
   base (`prefix` if the entry key was `NOKEY`, else `tsig`) plus every
   TLS mechanism whose credentials the entry carries *and* whose check
   passes against the connection's client certificate.
3. The transfer is authorized iff some matched entry's satisfied set
   intersects the zone's `downstream-auth` list. **Absent list = every
   matched entry authorizes** — exactly today's behavior, so existing
   configs are untouched.

Consequences worth stating:

- The mechanisms **compose**: `tls-*` never replaces the address/TSIG
  check of the matched entry, it escalates on top of it.
- Keeping `prefix` and `tsig` as distinct classes turns the documented
  `NOKEY`-shadows-a-keyed-entry footgun into a hard refusal: with
  `downstream-auth: [ tsig, … ]`, a transfer that only satisfied a `NOKEY`
  entry maps to `prefix` and is refused even though an entry matched.
- Listing only `tls-*` classes makes a zone DoT-only *for transfers* while
  leaving queries untouched on every transport (the MUSTs in §1.3).
- A **template** carrying `downstream-auth` is the intended way to enforce
  one policy across hundreds of zones. Because template gap-fill treats an
  empty slice as unset, a zone that needs to *relax* a template's policy
  cannot write `downstream-auth: []`; the explicit value **`[ any ]`**
  means "unrestricted" and overrides the template.

Load-time cross-checks (per zone, after expansion):

- a listed mechanism that no entry can ever satisfy (e.g. `tls-pin` with no
  pins anywhere) → warning: *allowed but unsatisfiable*;
- an entry that can only produce mechanisms outside the list (e.g. a
  `NOKEY` inline entry under `[ tsig, tls-pkix ]`) → warning: *dead entry*;
- `tls-dane` listed but the IMR is not active → warning at load; the
  mechanism is simply unsatisfiable at runtime (fail closed).

## 6. Enforcement path

- **Listener:** the auth DoT listener's `tls.Config` always sets
  `ClientAuth: tls.RequestClientCert` — clients *may* present a
  certificate; the handshake verifies nothing and never fails for lack of
  one. Not configurable. The IMR's DoT front end is untouched.
- **Transfer time:** `ZoneTransferOut` (`v2/dnsutils.go`), after the
  existing ACL/TSIG gate, evaluates §5: obtain the client certificate via
  the miekg `ConnectionStater` interface
  (`w.(interface{ ConnectionState() *tls.ConnectionState })`, implemented
  by the fork's response writer, `server.go:850`); run the per-entry
  checks — pin = constant-time SPKI compare (`SPKISHA256`), pkix = full
  `x509.Verify` against the entry's CA pool with `ExtKeyUsageClientAuth`
  (the handshake verified nothing, so this code does), dane = the existing
  validated-TLSA machinery (`lookupTLSAValidated`, fail closed, honoring
  `require_dnssec_validation`). Failure → REFUSED, with the mechanism
  decision logged.
- **Everything else** — queries on all transports, NOTIFY, cert-less DoT
  clients — never reaches this code.
- Transfers over DoH/DoQ remain out of scope (XoT is TLS; those listeners
  use custom writers without `ConnectionStater`).

## 7. Removal of the dnsengine knobs

Delete `DnsEngineConf.DownstreamAuth/DownstreamPins/DownstreamCA/
DownstreamNames`, the downstream branches of `ServerTLSConfigForDoT`
(`v2/xot.go`), the `applyDownstreamAuth` parameter of `DnsDoTEngine`, the
sample-config block, and the listener-mTLS tests (superseded by per-zone
tests). This supersedes #314 Phase 5's mTLS portion and #316's LE-4 commit
(`downstream-names`, deliberately kept droppable). Two sequencing options,
operator's (Johan's) choice at implementation time:

- merge #314/#316 as they stand, and this work removes the knobs in its
  own PR (honest history; a brief window where the branch carries a knob
  the docs already footnote), or
- strip the listener-mTLS commits from those branches before their merge
  (cleaner history, more surgery on reviewed branches).

Either way `main` never carries the knobs.

## 8. Worked example

```yaml
peers:
   ns1:                                # our primary (we are secondary for it)
      addr: ns1.example.net:853
      key: NOKEY
      transport: dot
      tls-auth: dane
   sec1:                               # modern secondary, mTLS-capable
      addr: sec1.example.net:853       # supplies the default tls-identity
      prefixes: [ 198.51.100.7,        #   name and prefix; extra source
                  2001:db8::7 ]        #   addresses listed explicitly
      keys: [ xfr-key-2026,            # mid-rollover: new key signs/preferred,
              xfr-key-2025 ]           #   old still accepted inbound
      tls-identity:
         name: sec1.example.net        # the identity pin (SAN check)
         ca-file: /etc/tdns/certs/tdns-ca.crt   # roots only — the trust domain
   sec-legacy:                         # NSD box on the trusted LAN, Do53 only
      prefixes: [ 10.1.2.3 ]
      key: xfr-key-2026                # sugar for keys: [ xfr-key-2026 ]

templates:
   - name: served-strict
     type: primary
     downstream-auth: [ tsig, tls-pkix ]
     downstreams:
        - peers: [ sec1, sec-legacy ]

zones:
   - name: example.com.               # 1 of 500 identical declarations
     template: served-strict
     zonefile: /var/lib/tdns/example.com

   - name: internal.example.          # relaxes the template policy
     template: served-strict
     downstream-auth: [ any ]

   - name: pulled.example.
     type: secondary
     upstreams:
        - peers: [ ns1 ]
```

Rolling `sec1`'s certificate, CA, or address touches exactly one place.

## 9. Implementation phases

Each independently mergeable (onto the XoT branch stack, per D8/§Baseline).

**P1 — peers + references + aliases (config only).**
`peers:` block parsing/validation; reference expansion into
`PeerConf`/`AclEntry` after template expansion; terminology normalization
pass + unknown-key/config-check registration; quarantine on unknown ids and
alias conflicts. *No behavior change for any existing config* (regression:
current parse tests byte-identical). Acceptance: worked example (§8) parses
to the expected expanded structures; alias matrix tests; conflict/unknown-id
quarantine tests.

**P2 — downstream-auth + transfer-time enforcement.**
`downstream-auth` field (zone + template, `any` sentinel); mechanism
evaluation in `ZoneTransferOut` via `ConnectionStater`; listener switched
to `RequestClientCert`; dnsengine knob removal (§7); load-time
cross-checks. Acceptance: integration matrix against the in-process DoT
harness with client certs — {no list, each single mechanism, mixed lists} ×
{cert-less client, pinned, CA-signed, DANE-satisfying (injected TLSA),
wrong-everything}; the two MUSTs as explicit tests (cert-less DoT query
succeeds against a `tls-pin`-only zone; Do53 transfer succeeds under
`[ tsig ]`); NOKEY-shadow refusal under `[ tsig ]`.

**P3 — documentation and vocabulary sweep.**
Config guide ACL section rewritten around peers + the ladder in
`upstreams:`/`downstreams:` vocabulary; alias table documented once;
sample configs and mwe converted; cert-provisioning guide cross-linked
(tls-identity provisioning = `cert leaf --client` / CSR flow); error-message
vocabulary migration. dog needs no changes (client side only).

## 10. Risks and open questions

1. **gap-fill zero-value semantics** are load-bearing twice (empty
   `downstream-auth`, empty `prefixes`); the `any` sentinel handles the
   first, and `prefixes` defaulting from `addr` handles the second — both
   need explicit tests.
2. **Alias normalization vs. viper key case-folding**: viper lower-cases
   keys; the normalization pass must run on the same representation
   `config check`'s loader sees, or the two will disagree.
3. **Per-transfer PKIX cost** (an `x509.Verify` per AXFR) is negligible
   against the transfer itself.
4. **`tls-dane` on the primary requires the IMR**, mirroring the secondary
   side; warn-at-load + fail-closed (§5) rather than refusing the config.
5. **tdns-mp**: consumes `PeerConf` via the tdns module; P1 keeps that
   struct's existing fields untouched (additions only), so no fallout
   beyond the already-noted TLSA verify signature change from #314.
