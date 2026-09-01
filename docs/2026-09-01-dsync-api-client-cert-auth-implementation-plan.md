# DSYNC API client certificates: implementation plan

**Status:** implemented. Base was `main` @ `404e03b3`.
**Revision 2**, incorporating `reviews/2026-09-01-dsync-api-client-cert-auth-plan-review.md`.
Changes from rev 1: `tls-dane` deferred (§7); identity resolution for `tls-pkix`
specified (D2); D8 restored, having been lost to a bad edit in rev 1; the
handshake contradiction in §2 fixed; D5 restated in terms of the `Authorization`
header rather than `r.BasicAuth()`; open questions 1–3 closed.
**Predecessor:** `docs/2026-08-23-dsync-api-client-cert-auth.md`, which argued the
case and left it as an open question. This plan takes that as settled and says how.

**Hard constraint: purely additive.** Every deployment that authenticates with
`<username, key>` today keeps working, byte for byte, with no config change and
no new failure mode. Client certificates are a second way in, never a
replacement, and never a precondition.

## 1. The hinge

The handlers do not consume a credential. They consume a *principal*:

    v2/dsync_api_delegation.go:250
        zd.ApproveActionsForPrincipal(policy, cred.Principal, actions, "dsync-api update")

`cred` arrives through one seam, `dsyncApiCredentialFrom(r)`
(`v2/dsync_api_server.go:224`), which reads a `*DsyncApiCredential` out of the
request context. Apart from `cred.Principal` and `cred.Username` in log lines
and one description string, nothing downstream inspects it.

So the whole feature reduces to: *populate that same context value from a client
certificate when there is no `Authorization` header.* No handler changes. No
policy changes. That is what makes this cheap, and it is the reason to do it
this way rather than teaching the handlers about a second credential type.

## 2. Additivity contract

These are the invariants the implementation must not break. They are worth
stating because most of them are one careless line away from being violated.

- **The listener must REQUEST, never REQUIRE, a client certificate.**
  `tls.RequestClientCert`, matching `v2/xot.go:306` and `v2/apirouters.go:313`.
  `tls.RequireAndVerifyClientCert` would break every existing bearer-token child
  at the handshake, before any of this code ran. `tls.VerifyClientCertIfGiven`
  is also wrong here: it would break a client that presents an unrelated
  certificate it happens to have configured for something else.
- **A deployment that does not configure `client-auth` gets no behaviour change
  at all, including at the TLS layer.** The `TLSConfig` is installed only when
  the block is present, so an unconfigured listener does not even send a
  `CertificateRequest`. (Rev 1 said the request was always sent and harmless
  because conforming clients ignore it. True, but it is still an observable
  handshake change that some stacks log, and there is no reason to take it.)
- **Verification happens at use, not at handshake.** This is the house pattern,
  stated at the head of `v2/downstream_auth.go`: the listener "merely REQUESTS a
  client certificate and verifies nothing", and enforcement happens later, per
  matched entry. Same here.
- **Basic auth decides whenever an `Authorization` header is present** —
  including when it is wrong, and including when it is not Basic at all. See D5.
- **No schema migration.** `v2/db_schema.go` creates tables with
  `CREATE TABLE IF NOT EXISTS` and has no column-migration machinery, so an
  added column would silently not exist on any established database. New table
  only. See D4.
- **`allow-insecure` semantics are untouched.** See §7.

## 3. Design decisions

### D1. Where the principal comes from: the store, not the certificate

The tempting design is principal = the leaf's DNS SAN. Reject it.

A SAN-derived principal means any certificate the trust anchor ever issued can
claim any principal, and the parent's only control is the CA. That is a weaker
authorization story than the one bearer tokens already have, where the principal
is a provisioned, auditable row. It also throws away the `--principal`
decoupling that exists precisely for the registrar case — and the predecessor
doc calls that out as still needed either way: "a certificate may name one
entity while the policy principal must be another."

So: **the certificate proves an identity; a stored row maps that identity to a
principal.** The certificate is the key, not the claim. This keeps the whole
existing credential lifecycle — disable, expire, list, comment, audit — working
unchanged for the new credential type, because it is the same lifecycle.

### D2. Which identity, which proof, and how a row is found

Two mechanisms in v1, named as in the transfer-auth ladder
(`v2/downstream_auth.go:73-80`). `tls-dane` is deferred; see §7.

| mechanism  | stored identity | proof |
|---|---|---|
| `tls-pin`  | SPKI SHA-256 of the leaf, base64 | `pinMatches` (`downstream_auth.go:226`) |
| `tls-pkix` | DNS name | `verifyClientCertPKIX` (`:242`) — chain + `VerifyHostname` |

**Identity resolution — this is the part that decides who gets in, so it is
spelled out rather than left to the implementer.** The two mechanisms find their
row differently, and only `tls-pin` is a pure function of the leaf:

    tls-pin   identity := SPKISHA256(leaf)                     -- xot.go:371
              one lookup on (zone, "tls-pin", identity)

    tls-pkix  for each name in leaf.DNSNames, IN THE ORDER THE CERTIFICATE
              PRESENTS THEM:
                  identity := core.CanonicalizeName(dns.Fqdn(name))
                  row, ok  := lookup(zone, "tls-pkix", identity)
                  if !ok { continue }
                  if verifyClientCertPKIX(leaf, presented, caFile, identity) == nil {
                      return row          -- first VERIFIED hit wins
                  }

`leaf.Subject.CommonName` is never consulted. `pki.go:170-171` sets `CommonName`
and `DNSNames` as separate fields, and Go's `VerifyHostname` matches on SANs
alone — so a CN-based lookup would fail against the very certificates
`tdns-cli cert leaf` mints.

The walk is over the certificate's names, not over the table: a certificate
presents names, and the store says which of those names is a credential. That is
D1 restated at the lookup level. It also bounds the work by the certificate
rather than by the number of rows in the zone.

Mechanisms are tried in the order configured (D3), and `tls-pin` before
`tls-pkix` is the sensible order: exact, single lookup, no chain building.

**Honest note on reuse.** The predecessor doc says this would "reuse the ladder".
It reuses the ladder's *primitives* — `SPKISHA256`, `pinMatches`,
`verifyClientCertPKIX`, `loadCAPool` — not `authorizeTransfer`. That function is
built around `AclEntry`: source-address matching and TSIG, with the `tls-*`
classes escalating on top of a matched ACL entry (`:144-178`). The DSYNC API has
no ACL and no address expectation — a registrant connects from wherever they are.
Forcing one function to serve both would distort it. Leave `authorizeTransfer`
alone.

### D3. Configuration lives on the listener block

    delegationsync:
      parent:
        api:
          listen: [...]
          cert: ...
          key: ...
          client-auth:                       # NEW. Absent = feature off = today.
            mechanisms: [tls-pin, tls-pkix]  # order is evaluation order
            ca-file: /path/to/clients-ca.crt # required iff tls-pkix is listed

Listener-scoped, not zone-scoped, for v1. The mechanism list says "what proof
types are acceptable at this endpoint"; the per-zone credential rows say "which
identity is which principal". One listener fronts many parent zones
(`dsyncApiParentZone`, `dsync_api_server.go:238`), and a per-zone override can be
added later without changing this shape. Absent block means the middleware never
looks at a certificate, and the listener never asks for one.

Validate at config load, warn-not-fail in the style of
`crossCheckDownstreamAuth` (`downstream_auth.go:330`): `tls-pkix` without
`ca-file` is unsatisfiable; an unknown mechanism name is a config error, not a
warning, matching `validateDownstreamAuth` (`:291`).

### D4. Storage: a new table

    "DsyncApiCertCredential": `CREATE TABLE IF NOT EXISTS 'DsyncApiCertCredential' (
        id         INTEGER PRIMARY KEY,
        parentzone VARCHAR(255) NOT NULL,
        authmech   VARCHAR(16)  NOT NULL,   -- tls-pin | tls-pkix
        identity   VARCHAR(255) NOT NULL,   -- base64 SPKI pin, or DNS name
        principal  VARCHAR(255) NOT NULL,
        created    INTEGER NOT NULL,
        expires    INTEGER NOT NULL DEFAULT 0,
        disabled   INTEGER NOT NULL DEFAULT 0,
        comment    TEXT,
        UNIQUE (parentzone, authmech, identity)
    )`

A separate table rather than nullable columns on `DsyncApiCredential`, for the
reason in §2: no migration machinery exists. It is also honest — `keyhash NOT
NULL` and `UNIQUE (parentzone, username)` describe a bearer credential, and a
certificate credential has neither a key hash nor a username.

`identity` is canonicalised with `core.CanonicalizeName` for `tls-pkix`, for
exactly the reason spelled out at `dsync_api_credentials.go:105-109` —
`strings.ToLower` folds U+212A onto `k` and would collapse two distinct DNS names
into one credential. Pin values are base64 and stored verbatim, case-sensitive
(D8 refuses anything that is not the house format).

`principal` goes through the existing `usableAsPrincipal` gate at provisioning
(`:121`), same as today, for the same reason: an unusable principal is otherwise
an unexplained 403 on every request.

### D5. Precedence: the `Authorization` header wins, whatever it contains

    Authorization header present  -> Basic path decides. Success or failure.
                                     A non-Basic header is a 401, not a fallthrough.
    Authorization header absent   -> certificate path, if configured.
    Neither                       -> 401 + WWW-Authenticate, exactly as today.

The gate is `r.Header.Get("Authorization") != ""`, **not** the `ok` from
`r.BasicAuth()`. Those differ: `BasicAuth()` returns false for a missing header
*and* for `Authorization: Bearer …`, Digest, or anything malformed. Gating on
`BasicAuth()` would let a request carrying a non-Basic header plus a client
certificate through the certificate path — a request that is a 401 today. That
is precisely the behaviour change this plan promises not to make.

A wrong password does not fall through to the certificate either, for the same
reason and one more: silent fallback between credential types is a bad property
in itself.

Failure on the certificate path must be as undifferentiated as
`VerifyDsyncApiCredential` is (`dsync_api_credentials.go:281-283`): unknown
identity, disabled, expired, and failed chain verification all produce the same
empty 401. Log the detail, answer with none.

Keep sending the `WWW-Authenticate: Basic` challenge on certificate-path failure.
It tells a client that Basic is available, it is what a bearer client already
expects, and it leaks nothing.

### D6. The seam stays one type

`dsyncApiCredentialFrom` keeps returning `*DsyncApiCredential`. The certificate
path constructs one in memory:

    &DsyncApiCredential{ParentZone: zd.ZoneName, Username: row.Identity,
                        Principal: row.Principal, ...}

with `Id` from the cert-credential row. This is what keeps the handler diff at
zero. Add one field — `AuthMethod string` ("basic" / "tls-pin" / "tls-pkix") —
used only for logging, so that operators can tell the paths apart in the log
without the handlers having to care.

### D7. Client side

Three things change; §9 has the whole client-side diff in full.

**(a) The credential entry gains a client keypair, nested under `tls:`.** `key:`
in `DsyncApiChildCredentialConf` (`config_delegationsync.go:161`) already means
the bearer key, so the certificate's private key is `tls.key` rather than a
sibling field. Nesting is the shape this file already uses for a subtree hanging
off one node — `DsyncUpdateSchemeConf` nests `key-verification` and `keygen`
(`config_delegationsync.go:83-84`). §9.4 records the flat alternative and why it
was refused.

**(b) `DsyncApiClientCredential` gains a `Usable()` method — and four call sites
must adopt it.** This is the part most likely to be missed, because it is not in
the config layer at all. Four places currently treat "no username or no key" as
"no credential":

    v2/delegation_sync_plan.go:339   if !ok || cred.Username == "" || cred.Key == "" {
    v2/ksk_rollover_ds_api.go:101    if !ok || cred.Username == "" || cred.Key == "" {
    v2/delsync_proxy_api.go:107      if cred.Username == "" || cred.Key == "" {
    v2/delegation_sync_api.go:51     if cred.Username == "" || cred.Key == "" {

A cert-only credential has neither field. Left alone, these four silently skip
the API scheme for a correctly configured child — and the first one reports it
as "no usable credential for parent X", pointing the operator straight at the
config they just got right. Replace all four with `!cred.Usable()`.

**(c) The request stops unconditionally setting Basic auth.**
`dsync_api_client.go:280` calls `req.SetBasicAuth(cred.Username, cred.Key)` on
every request; it becomes conditional on a username being configured, and
`dsyncApiHttpClient` (`:329`) loads `tlsconf.Certificates`.

An entry carrying both a bearer credential and a keypair is a config error
refused at load: it is ambiguous, and D5 means the answer would be "the
certificate you carefully configured is ignored".

Note that the certificate's private-key *path* is not itself a secret, so it is a
plain `string` and not a `SensitiveString` — unlike the bearer `Key` beside it.

### D8. Provisioning surface

Certificate credentials are provisioned exactly where bearer ones are: on the
**management** API with the operator key, never on the DSYNC listener. That
separation is the design (`dsync_api_server.go:21-30`) — a registrant is not an
operator — and it is why the undifferentiated-401 discipline of D5 does not apply
to these verbs. An operator asking for a credential that does not exist should be
told so plainly.

Mirror the bearer verbs (`v2/cli/dsync_api_cred_cmds.go:52-105`) rather than
inventing a second vocabulary:

    tdns-cli auth dsync-api cert-credential add \
        --zone example. --mech tls-pkix --identity child1.example. \
        --principal child1.example. [--expires ...] [--comment ...]

    tdns-cli auth dsync-api cert-credential add \
        --zone example. --mech tls-pin --cert /path/to/child.crt \
        --principal child1.example.

    tdns-cli auth dsync-api cert-credential list   [--zone ...]
    tdns-cli auth dsync-api cert-credential delete|disable|enable \
        --zone example. --mech tls-pkix --identity child1.example.

Keyed on `(zone, mech, identity)`, matching the UNIQUE constraint in D4.

**`--cert` for pins, `--identity` for names.** For `tls-pin` the operator hands
over the certificate and the *parent* computes `SPKISHA256` — a pin is a digest
nobody should be retyping, and the format is easy to get wrong in a way that
fails silently. `SPKISHA256` returns standard-encoding base64 (`xot.go:367-374`);
a TLSA 3-1-1 record carries the same bytes in **hex**, and a hex value in this
column would never match `pinMatches`, which is a constant-time compare of the
base64 *string* rather than of digest bytes. Accepting `--pin <literal>` as well
is fine, but it must reject anything that is not 44 characters of valid base64.

Refuse at provisioning, where the error can explain itself, rather than at
authentication where every failure is a bare 401:

- an unknown `--mech`, the same way `validateDownstreamAuth` refuses an unknown
  mechanism name;
- a `principal` that fails `usableAsPrincipal` (`dsync_api_credentials.go:121`);
- `--identity` given for `tls-pin`, or `--cert` for `tls-pkix`;
- a duplicate `(zone, mech, identity)`, with the same "it may have been created
  with different capitalisation" hint the bearer path gives
  (`dsync_api_credentials.go:185-189`).

`list` shows both credential kinds with a mechanism column — one table, because
an operator asking "who can update delegations in this zone" wants one answer,
not two. Bearer rows display as mechanism `basic`. Both
`tdns-cli auth dsync-api credential list` and
`tdns-cli auth dsync-api cert-credential list` return that union; the existing
`credential list` is not left as bearer-only.

`add` for a certificate credential prints no secret. There is nothing to print,
which is the point the predecessor doc makes about `cert csr` + `cert sign`
(`v2/cli/cert_cmds.go:122`): the child's private key never travels.

Management API: the parallel operations alongside `apihandler_dsync_api.go:74`,
and the new fields on `api_structs.go:453`'s struct.

## 4. Phases

Each phase compiles, tests green, and is independently reviewable. Phases 1–2
are invisible from outside; the feature only becomes reachable in phase 3.

**Phase 1 — storage and lifecycle.** New table in `v2/db_schema.go`. New file
`v2/dsync_api_cert_credentials.go`: `DsyncApiCertCredential` type,
`AddDsyncApiCertCredential`, `ListDsyncApiCertCredentials`, `Delete…`,
`SetDsyncApiCertCredentialDisabled`, `LookupDsyncApiCertCredential(zone,
authmech, identity)`. Reuse `canonDsyncApiZone`, `usableAsPrincipal`,
`Usable`/`Expired`. No caller yet.

**Phase 2 — config.** `ClientAuth` struct on `DsyncApiSchemeConf`
(`config_delegationsync.go:243`), its `Validate`, and the load-time
cross-checks from D3. `tls` block on `DsyncApiChildCredentialConf`. Still no
caller.

**Phase 3 — the listener and the middleware.** This is the behavioural change.

- `StartDsyncApiListener` (`dsync_api_server.go:96-111`): when — and only when —
  `client-auth` is configured, give each `http.Server` a `TLSConfig` carrying
  `ClientAuth: tls.RequestClientCert` and `MinVersion: tls.VersionTLS12`. Keep
  passing the cert/key files to `ListenAndServeTLS`: Go clones the `TLSConfig`
  and loads the keypair on top of it, preserving `ClientAuth`. Regression test 3
  is the proof of that; if it fails, load the keypair into
  `TLSConfig.Certificates` and call `ListenAndServeTLS("", "")` instead.
- `dsyncApiAuthMiddleware` (`:175`): after the zone is resolved, branch on D5 —
  `r.Header.Get("Authorization") != ""` selects the existing Basic path
  unchanged; an absent header selects the certificate path when configured.
  Extract the leaf from `r.TLS.PeerCertificates` (index 0 leaf, rest
  intermediates — same split as `downstream_auth.go:138-141`).
- New `v2/dsync_api_cert_auth.go`: the identity resolution of D2, per configured
  mechanism in order, returning a `*DsyncApiCredential`.

No IMR is involved in v1, because `tls-dane` is deferred (§7). That is not an
accident of scheduling — see the note there about what it would cost.

**Phase 4 — provisioning.** The CLI verbs and management-API operations of D8.

**Phase 5 — client.** The `tls` block on `DsyncApiChildCredentialConf`, the
`CertFile`/`KeyFile` fields on `DsyncApiClientCredential` and the `build`
closure that populates them (`config_delegationsync.go:195`), the new `Usable()`
method and its four adopting call sites (D7b), `tlsconf.Certificates` in
`dsyncApiHttpClient`, the conditional `SetBasicAuth`, and the ambiguity
refusal.

## 5. Tests

Three modules, all three must be run — `go test ./...` from `v2/` does not
descend into `v2/cli` or `v2/cache`. `GOROOT=/opt/local/lib/go` must be set.

New `v2/dsync_api_cert_auth_test.go`, alongside the existing
`dsync_api_credentials_test.go` and `downstream_auth_test.go` (the latter has
usable CA/leaf minting helpers at `:55-70` — reuse rather than re-mint).

Additivity regressions, which matter more than the happy path:

1. Bearer credential still authenticates with `client-auth` **unset**.
2. Bearer credential still authenticates with `client-auth` **set** and no
   certificate presented.
3. Certless client still completes the TLS handshake once the listener requests
   certificates — the `RequireAndVerifyClientCert` regression, and also the
   proof for the `ListenAndServeTLS` + `TLSConfig` question in phase 3.
4. Client presenting an **unrelated** certificate plus valid Basic auth: still
   authenticates, certificate ignored (D5).
5. Wrong password plus valid certificate: **401**, no fallthrough (D5).
6. **Non-Basic `Authorization` header** (`Bearer …`) plus a valid certificate:
   **401**, no fallthrough. This is the `BasicAuth()`-versus-header distinction
   in D5, and it is invisible unless tested for directly.
7. `client-auth` unset ⇒ the handshake carries no `CertificateRequest` at all.

Feature path: valid cert per mechanism → correct principal; unknown identity →
401; disabled row → 401; expired row → 401; cert valid but chain fails → 401;
all indistinguishable in the response.

Identity resolution (D2), which is where a wrong implementation lets in the wrong
principal:

- leaf with **two SANs**, rows for both: the one earlier in `leaf.DNSNames` wins.
- leaf with two SANs, a row for the **second only**: authenticates as that row
  (the walk does not stop at the first name, only at the first *verified hit*).
- leaf whose **CN** names a provisioned identity but whose SANs do not: **401**.
  CN is never consulted.
- a row whose identity the leaf carries, but whose chain does not verify: **401**,
  and the walk does not then fall through to a different row.

Policy: a cert-authenticated principal is confined by `updatepolicy.child`
exactly as a bearer one is — assert against `ApproveActionsForPrincipal` with a
`self`/`selfsub` policy, since the whole claim of this design is that the two
paths are indistinguishable past the seam.

Provisioning (D8): hex pin refused; `--identity` with `tls-pin` refused; unknown
mechanism refused; unusable principal refused; duplicate `(zone, mech, identity)`
refused with the capitalisation hint.

## 6. Documentation

- `docs/2026-08-23-dsync-api-client-cert-auth.md` Status points here.
- The DSYNC API scheme doc (`docs/2026-08-11-dsync-api-scheme.md`, §5/§10) describes
  the second mechanism.
- Operator-facing: mint a client cert with `cert csr` + `cert sign` and provision
  the matching row (`tdns-cli auth dsync-api cert-credential add`). See
  `guide/special-features.md`.

## 7. Deliberately out of scope

**`tls-dane`, deferred.** `verifyClientCertDANE` (`downstream_auth.go:266-285`)
looks up `_853._tcp.<name>`, because `daneClientTLSAPort = "853"` and the helper
exists for a *secondary* proving itself with the TLSA record it publishes for its
own DoT service. A DSYNC API client is a child or a registrar: it has no DoT
listener and no `_853._tcp` TLSA. Calling that helper from this middleware would
mean a registrant authenticates only if they happen to publish a DoT TLSA
matching this certificate — failing closed for every intended client, which is
safe and useless.

Bringing `tls-dane` here needs a DSYNC-specific TLSA owner convention
(`_443._tcp`, a dedicated prefix, something else) and a port-taking variant of
the helper. That is a protocol decision with its own argument to make, not a
line in this plan.

**One trap to remember when it returns.** `tls-dane` needs the IMR, and the IMR
must be looked up **per request**, never captured at router-setup time.
`StartAuth` (`main_initfuncs.go:287-289`) calls `SetupDsyncApiRouter` inside the
`DsyncApiListener` engine, and `ImrEngine` does not start until `:294` — so
`conf.Internal.ImrEngine` is still nil there. Closing over it, "exactly as `kdb`
already is", would capture nil for the process lifetime and make the
fail-closed behaviour permanent. `kdb` is safe to capture because it is assigned
before any engine starts; the IMR is published later, which is what
`imr_readiness.go` and its `Ready()` channel exist for.

**Relaxing the DNSSEC discovery gate.** The predecessor doc's most interesting
argument is that with a client certificate the gate becomes "do not send my
delegation to the wrong place" rather than "do not give away my password", and is
therefore a weaker requirement. That is likely right, and it is still out of
scope here: it changes an existing security posture rather than adding a
mechanism, it needs its own analysis of what a mis-discovered endpoint can still
do to a child that talks to it, and bundling it here would mean this change could
no longer be described as purely additive. Separate change, separate argument.

**Certificate-derived principals** (D1), **per-zone mechanism overrides** (D3),
and **CRL/OCSP revocation checking**. On revocation: `expires` and `disabled` on
the row are the revocation mechanism in v1, which is the same answer the bearer
path gives and is under the parent's own control rather than the CA's.

## 8. Open questions

Rev 1's three open questions are closed:

1. **Pin format** — settled. `SPKISHA256` (`xot.go:367-374`) is standard-encoding
   base64 of SHA-256 over the SubjectPublicKeyInfo: the same string `pins:` holds
   and `--emit-pin` prints, 44 characters, comfortably inside `VARCHAR(255)`.
   Stored verbatim; hex refused at provisioning (D8).
2. **Multiple SANs** — settled by the resolution order in D2 and its tests.
   A load-time warning when one zone has the same identity under two mechanisms
   is worth adding, and is now well defined rather than speculative.
3. **`ListenAndServeTLS` with a populated `TLSConfig`** — Go clones the config
   and loads the keypair on top, preserving `ClientAuth`. Regression test 3 is
   the proof; the fallback if it ever fails is in phase 3.

Nothing outstanding blocks phases 1–5.

## 9. Appendix: the client credential shape

### 9.1 Config structs

```go
type DsyncApiChildCredentialConf struct {
	Parent string `yaml:"parent" mapstructure:"parent"`
	Child  string `yaml:"child" mapstructure:"child"`

	// Bearer credential. Both empty when TLS is set instead.
	Username string          `yaml:"username" mapstructure:"username"`
	Key      SensitiveString `yaml:"key" mapstructure:"key"`

	// TLS is the client-certificate alternative to Username/Key. A pointer so
	// that "the operator wrote no tls block" and "the operator wrote an empty
	// one" are distinguishable -- the second is a config error worth naming,
	// the first is every config written before this existed.
	//
	// Both tags are spelled out because the decoder runs with TagName "yaml"
	// (see DsyncUpdateSchemeConf) -- a nested struct carrying only the
	// mapstructure tag would decode as empty with nothing logged.
	TLS *DsyncApiChildTLSConf `yaml:"tls" mapstructure:"tls"`
}

// DsyncApiChildTLSConf is one client keypair. Both paths, no secrets: the
// private key stays in its file and is never read into the config. Plain
// strings and not SensitiveString for that reason -- these name files, they do
// not carry their contents.
type DsyncApiChildTLSConf struct {
	CertFile string `yaml:"cert" mapstructure:"cert"`
	KeyFile  string `yaml:"key" mapstructure:"key"`
}

// Validate rejects a half-written block early, where the error can name the
// field, rather than at first use where it surfaces as a TLS handshake failure
// against the parent.
func (t *DsyncApiChildTLSConf) Validate() error {
	if t == nil {
		return nil
	}
	if strings.TrimSpace(t.CertFile) == "" || strings.TrimSpace(t.KeyFile) == "" {
		return fmt.Errorf("delegationsync.child.api.credentials[].tls needs both cert and key")
	}
	return nil
}
```

An entry carrying both a bearer credential and a `tls:` block is refused at load
(D7c): it is ambiguous, and D5 means the answer would be "the certificate you
carefully configured is ignored".

### 9.2 As an operator writes it

```yaml
delegationsync:
  child:
    api:
      cafile: /path/to/parent-ca.crt
      credentials:
        - parent: example.
          username: child1.example.
          key: "<bearer key>"

        - parent: other-parent.
          tls:
            cert: /path/to/child1.crt
            key:  /path/to/child1.key
```

`key:` means the bearer key at the top level and the private key inside `tls:`,
and in both places it is the obvious reading. The two credential kinds read as
alternatives rather than as a flat list of fields where some combinations are
legal and others are not.

### 9.3 The value type and the usability gate

```go
// DsyncApiClientCredential is what a child holds for one parent.
type DsyncApiClientCredential struct {
	Parent   string
	Username string
	Key      string

	// Client-certificate paths, empty for a bearer credential. Exactly one of
	// the two pairs is populated; see Usable.
	CertFile string
	KeyFile  string
}

// Usable reports whether this credential can authenticate at all.
//
// Replaces the four open-coded `Username == "" || Key == ""` checks, which
// predate certificates and would reject a perfectly good cert-only credential
// -- reporting it, in delegation_sync_plan.go, as "no usable credential" and
// pointing the operator at config that is in fact correct.
func (c DsyncApiClientCredential) Usable() bool {
	if c.Username != "" && c.Key != "" {
		return true
	}
	return c.CertFile != "" && c.KeyFile != ""
}
```

The `build` closure in `CredentialForChild` (`config_delegationsync.go:195`)
populates the new fields:

```go
	build := func(cc DsyncApiChildCredentialConf) DsyncApiClientCredential {
		out := DsyncApiClientCredential{
			Parent:   wantParent,
			Username: strings.TrimSpace(cc.Username),
			Key:      cc.Key.Value(),
		}
		if cc.TLS != nil {
			out.CertFile = strings.TrimSpace(cc.TLS.CertFile)
			out.KeyFile = strings.TrimSpace(cc.TLS.KeyFile)
		}
		return out
	}
```

and the four gates become, uniformly:

```go
	if !ok || !cred.Usable() {
```

(`delsync_proxy_api.go:107` and `delegation_sync_api.go:51` have no `ok` in
scope at that point and become plain `if !cred.Usable() {`; both should keep
their existing error text, which currently says "missing a username or key" and
wants rewording to name both mechanisms.)

### 9.4 Rejected: a flat `certkey:` field

The alternative was two sibling fields on the credential entry, `cert:` and
`certkey:`, the second so named because `key:` was taken.

Refused on the failure mode rather than on taste. `key:` and `certkey:` are
adjacent, near-identically named, and hold different kinds of thing: one is the
credential itself, the other names a file. An operator who writes `key:` where
they meant `certkey:` produces a bearer credential whose key is a filesystem
path — structurally valid, so nothing is refused at load. The result is a 401
from the parent, and the parent's failures are deliberately undifferentiated
(D5), so neither end says what is wrong. Under `tls:` the same typo lands on
`tls.key`, which is simply correct.
