# XFR over TLS (XoT)

XoT (XFR-over-TLS, [RFC 9103](https://www.rfc-editor.org/rfc/rfc9103.html))
carries AXFR/IXFR inside a DoT (DNS-over-TLS) connection, and lets the two
ends authenticate each other with X.509 certificates. tdns implements it in
both directions:

- **Serving a zone out** (primary → secondary): the primary authenticates the
  **secondary's client certificate** at transfer time, per zone, via the
  `downstream-auth:` ladder and the peer's TLS identity fields
  (`tls-name`/`ca-file`/`pins`/`dane`).
- **Pulling a zone in** (secondary ← primary): the secondary verifies the
  **primary's server certificate** while dialing, via the upstream's
  `tls-auth:` mode.

The two directions are independent — you can use either alone — but a
mutually-authenticated setup uses both.

> **Companion:** certificate provisioning (`tdns-cli cert`) has its own guide,
> [Certificate Provisioning](cert-provisioning.md). This document assumes you
> can mint certs; every example starts by showing the exact commands.

---

## Key ideas

**Enforcement happens at transfer time, never at the TLS handshake.** The auth
DoT listener always *requests* (never *requires*) a client certificate, so
ordinary queries — and cert-less DoT clients — are completely unaffected. A
zone only refuses a transfer when its `downstream-auth:` policy is not
satisfied.

**The `tls-*` mechanisms are additive.** Each one escalates *on top of* the
address (and TSIG, if the matched `downstreams:` entry carries a key) that the
entry already required — it never replaces them:

| `downstream-auth:` mechanism | what the secondary must prove |
|---|---|
| `prefix` | source address only (matched entry's `key:` was `NOKEY`) |
| `tsig` | source address + valid TSIG |
| `tls-pin` | the above + client-cert SPKI is in the peer's `pins:` |
| `tls-pkix` | the above + client cert chains to the peer's `ca-file:` and carries its `name:` as a SAN |
| `tls-dane` | the above + client cert matches the peer name's DNSSEC-validated TLSA |
| `any` | sentinel: unrestricted (used to relax a template's policy) |

Absent `downstream-auth:`, any entry that matches by address (+ TSIG)
authorizes, exactly as before the ladder existed. A `tls-*`-only list makes the
zone **DoT-only for transfers** (the mechanisms are only satisfiable on the DoT
listener); ordinary queries still work on every transport.

**One identity, selected per direction.** A peer declares its TLS identity and
trust material **once**, as flat fields under its id — `tls-name`, `ca-file`,
`pins`, `dane` — and both directions use them. Only the *mode selection*
differs: the outbound (dial) side names it with `tls-auth: pin | pkix | dane`;
the inbound (verify) side lets each zone's `downstream-auth: [ tls-pin |
tls-pkix | tls-dane ]` choose which of the peer's credentials to require.

---

## Prerequisite: turn on the DoT listener

XoT rides the same DoT listener as encrypted queries. Add `dot` to
`transports:` and give the engine a server certificate:

```yaml
dnsengine:
   addresses:   [ 198.51.100.53:53, '[2001:db8::53]:53' ]
   transports:  [ do53, dot ]        # do53 is always on; dot adds the XoT listener
   ports:
      dot:      [ 853 ]              # default; the host part is taken from addresses
   certfile:    /etc/tdns/certs/ns1.example.net.crt
   keyfile:     /etc/tdns/certs/ns1.example.net.key
```

`certfile`/`keyfile` are **required** once any encrypted transport is listed; if
they are absent the DoT listener does not start. The quickest way to create them
is `tdns-cli cert init` (see [Certificate Provisioning](cert-provisioning.md)).

---

## Example 1 — `tls-pkix` (one CA, many secondaries)

pkix is the mode that scales: the primary trusts a **single CA file**, and every
secondary whose client cert was signed by that CA (and carries the expected
name) is authorized — no per-secondary config on the primary.

### 1a. Provision the certificates

```bash
# On the CA host, once: create the CA.
tdns-cli cert ca --name tdns-ca --out-dir /etc/tdns/ca

# The primary's DoT server cert (SANs: its addresses + hostname).
tdns-cli cert leaf --ca /etc/tdns/ca/tdns-ca.crt --ca-key /etc/tdns/ca/tdns-ca.key \
   --name ns1.example.net --dns ns1.example.net --ip 198.51.100.53 \
   --out-dir /etc/tdns/certs

# The secondary's CLIENT cert (--client adds the clientAuth EKU; keep serverAuth
# too if the same host is also a primary elsewhere).
tdns-cli cert leaf --ca /etc/tdns/ca/tdns-ca.crt --ca-key /etc/tdns/ca/tdns-ca.key \
   --name ns2.example.net --dns ns2.example.net --client \
   --out-dir /etc/tdns/certs
```

Copy `tdns-ca.crt` (never the `.key`) to whichever hosts need it as a
`ca-file:` — the primary (to verify secondaries) and the secondary (to verify
the primary).

### 1b. Primary: authorize the secondary's client cert

```yaml
peers:
   ns2:
      prefixes: [ 198.51.100.7/32 ]            # the secondary's source address
      key:      NOKEY                          # cert is the sole credential here
      tls-name: ns2.example.net                # required SAN on its client leaf
      ca-file:  /etc/tdns/certs/tdns-ca.crt    # verify ITS client cert against this anchor (roots only)

zones:
   - name:      example.com.
     type:      primary
     zonefile:  /etc/tdns/zones/example.com
     downstream-auth: [ tls-pkix ]             # this zone: cert-authenticated XoT only
     downstreams:
        - peers: [ ns2 ]
```

> **Defense in depth:** give `ns2` a TSIG key (`key: xfr-key` instead of
> `NOKEY`) and use `downstream-auth: [ tls-pkix ]` — the entry then requires
> *both* a valid TSIG and the client cert, because `tls-*` is additive. Use
> `NOKEY` only when the certificate alone is the intended credential.

### 1c. Secondary: pull over XoT and verify the primary

```yaml
zones:
   - name:      example.com.
     type:      secondary
     upstreams:
        - addr:      ns1.example.net:853
          key:       NOKEY
          transport: dot                       # dial over DoT
          tls-auth:  pkix                       # verify the primary's cert via a CA
          ca-file:   /etc/tdns/certs/tdns-ca.crt
          # tls-name: ns1.example.net           # SNI + required SAN; defaults to addr's host
```

The secondary presents its own `dnsengine` cert as the client certificate, so
the same `certfile`/`keyfile` that run its DoT listener also authenticate it
outbound.

### 1d. Test it with `dog`

`dog` is an XoT client too: `+dot` selects the transport, `+cert=`/`+key=`
present a client certificate, `+cafile=` verifies the server.

```bash
# Success: present the secondary's client cert over DoT.
dog example.com AXFR @ns1.example.net +dot \
   +cafile=/etc/tdns/certs/tdns-ca.crt \
   +cert=/etc/tdns/certs/ns2.example.net.crt \
   +key=/etc/tdns/certs/ns2.example.net.key

# Refused: no client cert (tls-pkix unsatisfied).
dog example.com AXFR @ns1.example.net +dot +cafile=/etc/tdns/certs/tdns-ca.crt

# Refused: over Do53 the mechanism can never be satisfied.
dog example.com AXFR @ns1.example.net
```

The primary logs the exact reason on a refusal, e.g.
`refusing transfer … no matched downstreams entry satisfies downstream-auth
[tls-pkix] (… client cert present: false)`.

---

## Example 2 — `tls-pin` (SPKI pinning, no CA)

pin trusts an exact key, not an issuer: the primary stores the base64 SHA-256
**SPKI digest** of the secondary's cert. No CA is needed, and the pin survives
cert renewal as long as the key is reused. It is stricter than pkix — a cert
that would pass pkix (right CA, right name) is still refused if its SPKI is not
pinned.

### 2a. Get the secondary's SPKI pin

```bash
# From an existing cert:
tdns-cli cert pin /etc/tdns/certs/ns2.example.net.crt
# -> spki pin (for pins: / +pin=): je101TybRFS6ECK3Z7DXyu6inLmxskIjMOlvjcfrIMg=

# ...or print it at issue time with --emit-pin.
```

### 2b. Primary: pin the secondary

```yaml
peers:
   ns2:
      prefixes: [ 198.51.100.7/32 ]
      key:      NOKEY
      tls-name: ns2.example.net
      pins: [ "je101TybRFS6ECK3Z7DXyu6inLmxskIjMOlvjcfrIMg=" ]   # any listed pin matches

zones:
   - name:      example.com.
     type:      primary
     zonefile:  /etc/tdns/zones/example.com
     downstream-auth: [ tls-pin ]
     downstreams:
        - peers: [ ns2 ]
```

### 2c. Secondary: pin the primary in return (optional)

```yaml
zones:
   - name:      example.com.
     type:      secondary
     upstreams:
        - addr:      ns1.example.net:853
          key:       NOKEY
          transport: dot
          tls-auth:  pin
          pins:      [ "<ns1's SPKI pin>" ]      # tdns-cli cert pin ns1…crt
```

### 2d. Test it with `dog`

```bash
# Success: the presented cert's SPKI matches the pin.
dog example.com AXFR @ns1.example.net +dot \
   +pin=<ns1's SPKI pin> \
   +cert=/etc/tdns/certs/ns2.example.net.crt \
   +key=/etc/tdns/certs/ns2.example.net.key

# Refused: a different key/cert — right CA and SAN, wrong SPKI.
dog example.com AXFR @ns1.example.net +dot \
   +cert=/etc/tdns/certs/other.crt +key=/etc/tdns/certs/other.key
```

---

## Example 3 — `tls-dane` (DNSSEC-validated TLSA)

dane replaces the local trust file with a DNSSEC-signed **TLSA record** the peer
publishes about itself: the verifier fetches and DNSSEC-validates the TLSA at
`_853._tcp.<name>` and checks the presented cert against it. There is no
`ca-file` or `pins` to distribute — trust follows the DNSSEC chain.

> **Requires validation.** dane needs a working DNSSEC-validating resolver: the
> auth server's `imrengine` must be active (`active: true`) with a trust anchor,
> and the peer name must be securely delegated with a published, signed TLSA.

### 3a. Publish the TLSA record

```bash
# Emit a 3-1-1 TLSA RR for the secondary's cert at _853._tcp.ns2.example.net.
tdns-cli cert leaf --ca /etc/tdns/ca/tdns-ca.crt --ca-key /etc/tdns/ca/tdns-ca.key \
   --name ns2.example.net --dns ns2.example.net --client \
   --emit-tlsa ns2.example.net --tlsa-port 853 --out-dir /etc/tdns/certs
# -> _853._tcp.ns2.example.net. IN TLSA 3 1 1 <hash>
```

Add that RR to the `ns2.example.net` zone and (re)sign it.

### 3b. Primary: trust the secondary via DANE

```yaml
peers:
   ns2:
      prefixes: [ 198.51.100.7/32 ]
      key:      NOKEY
      tls-name: ns2.example.net       # the TLSA base name (and required SAN)
      dane: true                      # verify the client cert against its validated TLSA

zones:
   - name:      example.com.
     type:      primary
     zonefile:  /etc/tdns/zones/example.com
     downstream-auth: [ tls-dane ]
     downstreams:
        - peers: [ ns2 ]
```

### 3c. Secondary: verify the primary via DANE

```yaml
zones:
   - name:      example.com.
     type:      secondary
     upstreams:
        - addr:      ns1.example.net:853
          key:       NOKEY
          transport: dot
          tls-auth:  dane
          tls-name:  ns1.example.net    # TLSA base name; must have a signed _853._tcp TLSA
```

### 3d. Test it with `dog`

```bash
# +tlsa DANE-verifies the SERVER cert against _853._tcp.<server>.
dog example.com AXFR @ns1.example.net +dot +tlsa \
   +cert=/etc/tdns/certs/ns2.example.net.crt \
   +key=/etc/tdns/certs/ns2.example.net.key
```

---

## Reference: outbound peer XoT fields

These live on an `upstreams:`/`primaries:` entry (inline, or on the peer it
references) and control how a **secondary dials and verifies a primary**:

| Field | Values | Meaning |
|---|---|---|
| `transport` | `do53` \| `dot` | `dot` dials over TLS (XoT); empty/`do53` is plain, pre-XoT behavior |
| `tls-auth` | `pin` \| `pkix` \| `dane` | how to verify the primary's server cert (**required** when `transport: dot`) |
| `tls-name` | FQDN | SNI sent, and the required SAN / TLSA base name; defaults to the host part of `addr` |
| `pins` | list of base64 SPKI SHA-256 | trusted server pins (`tls-auth: pin`) |
| `ca-file` | path to PEM | trust anchors for the server cert (`tls-auth: pkix`); empty = system roots |

The inbound counterparts (how a **primary verifies a secondary**) are the
peer's shared TLS fields (`tls-name` / `pins` / `ca-file` / `dane`) plus the
zone's `downstream-auth:` policy — see
[the tdns-auth config guide](config-tdns-auth.md#peers-describe-a-server-once-reference-it-everywhere).

---

## Notes and gotchas

- **cert-less clients are never blocked at the handshake.** If a zone has no
  `tls-*` in its `downstream-auth:`, a DoT client without a cert transfers
  normally (subject to address/TSIG). The listener requesting a cert is not the
  same as requiring one.
- **`certfile` must present a full chain if issued via intermediates.** Certs
  from the tdns CA have no intermediates by design; an external-CA leaf must be
  concatenated leaf-first into `dnsengine.certfile` or secondaries fail chain
  building.
- **DANE needs `imrengine.active: true`** and a signed TLSA at
  `_<port>._tcp.<name>`; the other two modes work with the resolver off.
- **Quote bracketed IPv6** in YAML flow sequences (`'[2001:db8::53]:53'`), and
  write single-host prefixes with an explicit mask (`198.51.100.7/32`).
