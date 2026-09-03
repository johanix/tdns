# DSYNC API: client certificates as an alternative to username + key

**Status:** implemented. See
`docs/2026-09-01-dsync-api-client-cert-auth-implementation-plan.md`.

## How it works today

A child authenticates to the parent's DSYNC API with HTTP Basic auth over TLS.
The *username* is only a login handle; what matters is `cred.Principal`, which
is the string `updatepolicy.child` is evaluated against — the same slot the
SIG(0) signer name occupies on the DDNS path. It is treated as a DNS name
throughout (canonicalised to a lowercase FQDN, and refused at provisioning if it
could never match an owner name). `--principal` decouples the login handle from
the policy identity, for a registrar acting on behalf of a child.

So the credential exists to produce a *name*. Any mechanism that yields a
trustworthy name would serve.

## What a client certificate would change

The credential is a **bearer token**, and the design spends real effort on that
fact: the child refuses an endpoint whose URI and TXT records do not
DNSSEC-validate, because — in the code's own words — "an unvalidated lookup could
send it to an attacker". `allow-insecure` is deliberately one switch for two
protections for the same reason.

With a client certificate nothing secret leaves the child. Discovering the wrong
endpoint costs a failed handshake, not a reusable credential. The DNSSEC gate
becomes "do not send my delegation to the wrong place" rather than "do not give
away my password" — a materially weaker requirement, and one that is much less
painful to get wrong.

It also fits the provisioning that already exists: `cert csr` + `cert sign` means
the child's private key never travels, which is strictly better than the parent
generating the secret and displaying it once, unrecoverably.

## The machinery is already here

Client-certificate authentication is not new ground in tdns:

- `v2/xot.go` requests client certs on the XoT listener;
- `v2/downstream_auth.go` takes the peer leaf and chain, validates for
  `ExtKeyUsageClientAuth`, and offers a per-zone **tls-pin / tls-pkix / tls-dane**
  ladder;
- `v2/apirouters.go` requests client certs on the management API.

The DSYNC API listener is the one that does not. Deriving the principal from a
DNS-SAN would reuse the ladder rather than adding a second credential system.

## Against

- Bearer tokens survive TLS-terminating proxies and CDNs; client certs do not,
  without extra plumbing.
- Issuance is heavier ceremony when the child is operated by someone else.
- The registrar indirection is still needed either way: a certificate may name
  one entity while the policy principal must be another.

## Reading

An addition, not a replacement. The policy layer consumes only the principal
string, so both mechanisms can serve the same endpoint and the same
`updatepolicy.child`. Worth doing if the bearer-token handling becomes a burden;
not worth blocking anything on today.
