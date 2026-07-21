# Certificate Provisioning: the tdns Minimal CA

tdns ships a deliberately small built-in certificate authority,
`tdns-cli cert`, so that TLS between tdns components (XoT zone transfer,
DoT/DoH/DoQ service, mutual TLS) never *requires* an external CA. It is a
provisioning convenience for a **private trust domain** — your own primaries
and secondaries — not general CA tooling: there is no CRL, no OCSP, no
renewal automation and no certificate database. The only persistent state
is plain PEM files plus a human-readable audit log.

**Do you need it at all?** Not for kicking the tires. `tdns-cli auth config
mwe` generates a self-signed certificate, and both the `pin` and `dane`
authentication modes (and `dog +showpin`) work fine against self-signed
certs. Reach for the CA when you want `tls-auth: pkix` (one trusted file on
every secondary instead of per-server pins), or mutual TLS.

## The pieces

| Path | What | Notes |
|---|---|---|
| `/etc/tdns/ca/` | the CA's home (dir mode 0700) | default when running as root; otherwise the cwd is used — override with `--out-dir`/`--ca-dir` |
| `/etc/tdns/ca/<name>.crt` | the CA certificate (public) | distribute freely — this **is** the `ca-file` |
| `/etc/tdns/ca/<name>.key` | the CA signing key (mode 0600) | guard it; no tdns daemon ever reads it |
| `/etc/tdns/ca/issued.log` | append-only audit trail | one line per issuance; nothing reads it programmatically |
| `/etc/tdns/certs/` | where daemons' certs/keys live | the existing convention (`dnsengine.certfile`/`keyfile`) |

Key files are always written mode 0600 and never overwritten without
`--force`. The CA is hard-coded to only ever sign end-entity certificates
(pathlen 0) — it cannot mint sub-CAs, and no flag can change that.

## Quick start: one host, one command

```
tdns-cli cert init [--serverconfig /etc/tdns/tdns-auth.yaml]
```

`cert init` creates the CA if it does not exist yet (and reuses it on every
later run), issues a server certificate whose SANs are derived from the
config's `dnsengine.addresses` plus this host's name and loopback, writes
cert and key to the **exact `dnsengine.certfile`/`keyfile` paths the config
already names** (no config editing needed), drops a copy of the CA cert
next to them, and prints ready-to-paste secondary configuration for all
three XoT auth modes. Restart `tdns-auth` and you are serving CA-signed
TLS.

The rest of this page is the manual toolbox behind that one-shot.

## Creating the CA (once)

```
tdns-cli cert ca --name tdns-ca --out-dir /etc/tdns/ca
```

produces `/etc/tdns/ca/tdns-ca.crt` (the trust anchor) and
`/etc/tdns/ca/tdns-ca.key` (the signing key). Default validity 3650 days,
default algorithm ed25519 (`--algorithm ecdsa-p256|rsa2048` for interop
with older peers).

## Upgrading a LOCAL self-signed cert to a CA-signed cert

Scenario: this host already runs tdns-auth with a self-signed certificate
(from `config mwe` or `utils/gen-cert.sh`), e.g.
`/etc/tdns/certs/servers/ns1.example.net.crt` + `.key`, and you want the
same server to present a CA-signed certificate instead.

The important idea: you do not replace the *key*, only the *certificate*.
`cert csr --key` re-certifies the existing key, which keeps the public key
(SPKI) identical — so any `pins:` entries and published TLSA records that
point at this server **remain valid** across the upgrade.

```
cd /etc/tdns/certs/servers

# 1. CSR from the existing cert + key: --from-cert copies the CN and all
#    SANs, --key reuses the existing private key (nothing new generated).
tdns-cli cert csr --from-cert ns1.example.net.crt --key ns1.example.net.key

# 2. Sign it with the CA (same host, so no file shipping involved):
tdns-cli cert sign --ca /etc/tdns/ca/tdns-ca.crt --ca-key /etc/tdns/ca/tdns-ca.key \
    --csr ns1.example.net.csr --server --force
#    -> ns1.example.net.crt is now CA-signed (--force: it replaces the
#       self-signed one; the .key file is untouched)

# 3. Restart tdns-auth. Done — certfile/keyfile paths in the config never
#    changed, and neither did the SPKI:
tdns-cli cert pin ns1.example.net.crt      # same pin as before the upgrade
```

(`--server` is the default EKU; add `--client` too if this daemon will also
present the cert as a *client* under mutual XoT.)

If you do not care about keeping the key (no pins/TLSA published yet), skip
the CSR dance entirely: `tdns-cli cert leaf --ca … --ca-key … --name
ns1.example.net --dns ns1.example.net --ip 192.0.2.53 --force` mints a
fresh key + cert in one step.

## Upgrading a REMOTE self-signed cert

Scenario: a secondary (or another primary) elsewhere runs with a
self-signed cert; you operate the CA. Same flow — the only difference is
*where* each command runs, and that the CSR/cert travel between hosts while
**the private key never leaves the remote host**:

```
# --- on the REMOTE host (ns2) ---
cd /etc/tdns/certs/servers
tdns-cli cert csr --from-cert ns2.example.net.crt --key ns2.example.net.key
scp ns2.example.net.csr ca-host:

# --- on the CA host ---
tdns-cli cert sign --ca /etc/tdns/ca/tdns-ca.crt --ca-key /etc/tdns/ca/tdns-ca.key \
    --csr ns2.example.net.csr --server --client
scp ns2.example.net.crt tdns-ca.crt ns2:/etc/tdns/certs/servers/

# --- back on the REMOTE host ---
# ns2.example.net.crt replaces the self-signed cert (same key, same paths);
# tdns-ca.crt is there for when ns2 needs a ca-file itself (see below).
# Restart the daemon.
```

A CSR is public data — it can travel by scp, mail, or ticket attachment.
The CA operator can inspect it before signing; `cert sign` refuses a CSR
whose signature does not verify. `--client` on the sign step gives the cert
the clientAuth EKU too, which a secondary needs when the primary's zones
require a certificate mechanism in their `downstream-auth:` ladder (see
[the tdns-auth config guide](config-tdns-auth.md)).

## Creating the ca-file (for each kind of cert)

A "ca-file" is nothing more than the PEM certificate(s) a verifier should
trust as roots. What goes in it depends on how the *server's* cert was
made:

- **Cert signed by the tdns CA** → the ca-file is a **copy of the CA
  certificate**:

  ```
  scp ca-host:/etc/tdns/ca/tdns-ca.crt /etc/tdns/certs/tdns-ca.crt
  ```

  One file covers every cert that CA ever signs — that is the point of
  pkix mode: new servers need no per-server configuration on the clients.

- **Self-signed cert** → the ca-file is **the certificate itself** (a
  self-signed cert is its own root). Copy the server's `.crt` (never the
  `.key`!) to the verifying side and point `ca-file` at it. This works
  today, before any CA exists — it is per-server pinning by file instead
  of by digest.

- **External CA** (corporate PKI, etc.) → the ca-file is that CA's root
  certificate (concatenate roots if there are several). If the server's
  cert was issued via an intermediate, the *server* must present the
  intermediate: concatenate leaf-first into `dnsengine.certfile`
  (see [XoT operations](../docs/2026-07-21-xot-operations.md)). Certs from
  the tdns CA never need this — there are no intermediates by design.

Where a ca-file is consumed:

```yaml
# secondary: verify the primary's cert when pulling over XoT
zones:
   - name: example.com.
     type: secondary
     upstreams:
        - addr: ns1.example.net:853
          key: NOKEY
          transport: dot
          tls-auth: pkix
          ca-file: /etc/tdns/certs/tdns-ca.crt

# primary: verify SECONDARIES' client certs, per zone via peers +
# downstream-auth (see the tdns-auth config guide)
peers:
   ns2:
      prefixes: [ 198.51.100.7 ]
      key: NOKEY
      tls-identity:
         name: ns2.example.net
         ca-file: /etc/tdns/certs/tdns-ca.crt
zones:
   - name: example.com.
     type: primary
     downstream-auth: [ tls-pkix ]
     downstreams:
        - peers: [ ns2 ]
```

and on the command line: `dog +dot +cafile=/etc/tdns/certs/tdns-ca.crt
AXFR example.com @ns1.example.net`.

## Verifying what you built

```
tdns-cli cert show ns1.example.net.crt    # subject, issuer, SANs, EKU, validity, pin
tdns-cli cert pin  ns1.example.net.crt    # just the SPKI pin
dog +dot +cafile=tdns-ca.crt SOA example.com @ns1.example.net   # live PKIX check
dog +dot +showpin @ns1.example.net                              # what the server presents
cat /etc/tdns/ca/issued.log               # what the CA has signed, when
```

## Renewal, rotation and the ugly cases

- **Renewal** (cert expiring, default leaf validity 397 days): re-run the
  same `csr --key` + `sign --force` flow (or `cert leaf --force` /
  `cert init --force`). Reusing the key keeps pins/TLSA valid; the server
  logs a warning 30 days before expiry.
- **Key rotation** (you *want* a new key): mint a fresh leaf, and if pins
  or TLSA are in play, publish old + new side by side first — `pins:`
  accepts a list and any match admits; TLSA RRsets can hold both digests —
  then remove the old one after the switch.
- **Compromise**: there is no revocation (no CRL/OCSP — deliberate scope).
  If a *server* key leaks: issue a new key+cert and update pins/TLSA; pkix
  clients are only safe once the attacker can no longer use the cert, so
  treat a leaked server key in a pkix setup as urgent. If the **CA key**
  leaks: create a new CA and re-issue everything; the small size of a
  private trust domain is what makes this feasible — which is also why the
  CA key belongs on an access-controlled (ideally offline/admin) host, not
  on the DNS servers.

## Relation to pin and dane

One issuance feeds all three auth modes: `--emit-pin` prints the `pins:` /
`+pin=` value and `--emit-tlsa <owner> [--tlsa-port 853]` prints the TLSA
3-1-1 record for DANE. pkix is about *not* having to manage those
per-server values — but nothing stops you from mixing modes per primary in
`upstreams:`.
