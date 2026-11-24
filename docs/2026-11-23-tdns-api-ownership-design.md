# Owners for zones and keys: scoped API access for applications

Date: 2026-11-23
Status: r2, decided (section 8). Implementation in progress, as four PRs
(section 6): Z (`zone delete` deletes the zone's keys), A (owners recorded),
B (application clients and zone scope), C (keystore for application
clients). Builds on 2026-11-20-api-pinning-mtls-roles-design.md (pinned
certificates, the access file, the three roles, admin on the local socket
only).

Revisions:

- r1, 2026-11-23: first cut.
- r2, 2026-11-24: Johan's answers to the six open questions (section 8).
  Application clients see only their own zones (4.5). They may export the
  DNSSEC private keys of their own zones (4.6). `zone delete` also deletes
  the zone's SIG(0) and DNSSEC keys unless told to keep them (new 4.10). No
  bulk handover (5). Size and risks updated, with one new risk (R12). Q7
  (re-adding with kept keys) decided the same day: operators are never
  refused. Section 5 now spells out how an application gets its certificate
  and is enrolled (steps 2 and 3).

## 1. The scenario

A tdns-auth server runs zones from its static config. Operators manage it with
tdns-ncli: over the local admin socket (admin), or over TCP with a pinned
client certificate (read-write).

Next to the operators there are **applications**: separate processes, with
their own service account, sometimes on another host. They drive the same
management API. A typical one is a provisioning application that:

- adds, modifies and deletes secondary zones for its customers (`zone add`
  with the customer's primaries and TSIG key; `zone modify`; `zone delete`);
- puts those zones into catalog zones (`catalog zone-add`, `group-add`,
  `zone-group-add`);
- keeps a few records current in a service zone that the operator configured
  statically (`zone update`), for example the nameservers' address records;
- cleans up the TSIG keys its customers no longer use (`keystore tsig-mgmt
  list` and `delete`).

A second kind of application manages zones on many servers at once. It needs
the same things on each one.

Today such an application authenticates with the API key. Two things go wrong:

1. **The key is a kludge that breaks.** As soon as the server gets an access
   file (one `tdns-ncli config add` is enough), the key is read-write and
   every keystore command needs admin, which only the local socket has. The
   application's TSIG clean-up then fails. Moving the application to a client
   certificate doesn't help: the certificate is read-write too.
2. **Read-write is too wide.** A read-write caller may modify or delete any
   API-created zone, and update any zone. A provisioning application can
   delete zones that an operator, or another application, created.

Granting such an application admin would fix the first problem and make the
second one worse. A separate "application API" would be a lot of work.

## 2. Goals and non-goals

Goals:

- An application authenticates with its own pinned client certificate, never
  the API key.
- An application may manage **what it owns**: its zones, and its keys
  (TSIG, SIG(0) and DNSSEC). That includes the keystore commands it needs,
  over TCP, without admin.
- An application can't see or touch zones or keys it doesn't own: not the
  static config's, not the operators', not another application's. An
  application is not the nameserver operator.
- Which clients are applications is decided in the **daemon config**, not in
  the access file, which tdns-ncli rewrites.
- Nothing changes for a server whose config names no application clients,
  except that `zone delete` takes the zone's keys along (4.10).

Non-goals:

- No new API and no new endpoints. The existing routes and commands are
  reused, and ownership is checked on top of the role.
- No change to admin (the local socket) or to the three roles.
- No ownership limits on operators: an operator's certificate stays
  read-write on everything, as today.
- The truststore (trust anchors, the SIG(0) keys of children) stays admin.
  Adding trust authorizes someone else; it isn't "my key".

## 3. What exists today

- **Identity.** Every authenticated request carries an `ApiIdentity` in its
  context (`v2/api_auth.go`): `Name` (the access-file client, "apikey" or
  "local"), `Role` and `Via` ("local socket", "certificate", "api key"). So
  handlers can already see who is calling.
- **Roles.** `RequiredApiRole(route, cmd)` (`v2/api_roles.go`) maps route and
  `Command` to a role, and anything undeclared needs admin. The whole of
  `/api/v1/keystore` is admin. The check looks at `Command` only, never at
  `SubCommand`.
- **TSIG keys** already have `origin` (config|api), `owner` (default "api"),
  `creator` and a reference count (`v2/tsig_keystore_mgmt.go`,
  `v2/tsig_keystore.go`). The keystore refuses to delete a key that came from
  the config or that a zone still uses. Clean-up by an API client works
  today, but only as admin.
- **Inline TSIG keys.** `zone add` and `zone modify` take the key's name,
  secret and algorithm in the request, and add the key to the keystore if it
  isn't there. They refuse a different secret under the same name
  (`commitStagedTsigKey`, `v2/dynamic_zones.go`). The key gets owner "api"
  and creator "inline-zone". So a read-write caller can already put TSIG
  secrets into the keystore.
- **SIG(0) and DNSSEC keys** have a `creator`: the code path that made the
  key, such as bind9, cascade, rollover-sig0 or bootstrap-sig0. They have no
  owner. They always belong to a zone.
- **Zones.** API-created zones carry `OptApiManagedZone`, and only they can
  be deleted over the API (`RemoveDynamicZone`). Catalog-created zones carry
  `SourceCatalog`. There is no notion of who created a zone. As far as I can
  see, deleting a zone leaves its DNSSEC and SIG(0) keys in the keystore.
- **Import and export go through the API.** On import, the CLI reads the file
  and sends the keys in the request body (`BulkTsigKeys`, `BulkSig0Keys`,
  `BulkDnssecKeys`, `TsigSecret`). On export, the server returns the private
  key or secret in the response (`PrivateKeyForExport`). The server does no
  file I/O for either. Exporting therefore means secrets leave over the wire.

The keystore commands today, all admin:

| kind | subcommands |
|---|---|
| tsig-mgmt | list, add, import, generate, export, bulk-export, bulk-import, setowner, delete, purge |
| sig0-mgmt | list, add, generate, export, bulk-export, bulk-import, setstate, setparentstate, delete |
| dnssec-mgmt | list, add, generate, export, bulk-export, bulk-import, setstate, rollover, delete, clear, policy-cleanup, purge, check |
| other | list-algorithms, list-policies, list-dnskey, child-sig0-mgmt |

## 4. The design

### 4.1 Owners

An **owner** says who may manage a zone or a key. Its values:

| owner | meaning |
|---|---|
| `config` | from the static config; managed by editing the config |
| `api` | created over the API by an unscoped caller (the socket, the key, or a key-era client); managed by operators |
| `cert:<name>` | created by the certificate client `<name>` from the access file |

A certificate caller that creates something records `cert:<name>` as its
owner, whether or not it is an application client. Socket and key callers
record `api`. The record costs nothing, and it later lets an operator see who
made what.

### 4.2 Application clients, in the daemon config

```yaml
apiserver:
  access-file: /etc/tdns/tdns-auth-access.yaml
  app-clients: [ provisioner ]
```

`app-clients` lists access-file client names. A client named there is an
**application client**:

- It must authenticate with its certificate. The name means nothing over the
  key or the socket.
- Its role in the access file still applies, and it must be read-write to
  change anything.
- On top of the role, its writes are limited to what it owns (4.5), and in
  return it gets the keystore commands for its own keys (4.6).

The access file says **who** a certificate is. The daemon config says what
that name may do as an application. tdns-ncli edits the access file but never
this list. A name in the list that isn't in the access file grants nothing,
and config check warns about it. The list reloads with the config, under the
same lock as the access file.

An empty or missing list means no application clients, and behaviour is
exactly as today.

### 4.3 Zone owners

Every zone has an owner, kept in its zone config as `api-owner:`:

- **Static config zones:** `config`, unless the operator writes
  `api-owner: cert:<name>` in the zone's config. That's how an operator hands
  a static zone, such as a service zone or a catalog zone, to an application.
  The grant lives in the central config, where tdns-ncli doesn't write. A
  static zone still can't be deleted over the API, whoever owns it.
- **API-created zones:** the caller's owner (4.1), written with the zone into
  the dynamic config, where the zone's inline TSIG secret is already kept.
  Zones created before this change read as `api`.
- **Catalog-created zones:** the owner of their catalog zone.

The field is called `api-owner`, not `owner`, because "zone owner" already
means the zone's registrant in the multi-provider work (HSYNC).

### 4.4 Key owners

- **SIG(0) and DNSSEC keys take their owner from their zone.** They always
  belong to a zone, so the zone's owner is the key's owner. The key rows get
  no new column, and nothing has to be kept in step when the server rolls a
  key on the zone's behalf. A key whose zone isn't served here is admin-only.
- **TSIG keys keep their own `owner`** (the field exists), because one TSIG
  key may serve many zones. A key added by a certificate caller, inline on
  `zone add`/`modify` or with `tsig-mgmt add`/`import`/`generate`, gets
  `cert:<name>`. Today the inline add hardcodes "api".
- **`creator` stays as it is: provenance, never authority.** It records which
  code path made the key. Owner and creator answer different questions: a
  rollover of a key in an application's zone is created by rollover-sig0 and
  still belongs to the application. One field would lose one of those facts.

### 4.5 The rule for application clients

> An application client sees only what it owns and manages only what it
> owns. Lists are filtered to its own objects. Commands that act on the
> whole server are refused.

For the zone routes:

| commands | for an application client |
|---|---|
| `zone` list-zones, list-dynamic; `catalog` group-list | filtered to its own zones (own catalog zones for group-list) |
| `zone` get-name, get-delegation, journal, show-nsec-chain, zonemd, proxy-key; `catalog` zone-list, notify-list; `delegation` status/export; `rollover` status/when; `parentsync` status/inquire | own zone only; a catalog zone it owns is shown whole, since its members are that zone's data |
| `zone add` | allowed if the zone doesn't exist; its owner becomes the caller |
| `zone` modify, delete, update, bump, write-zone, sync, sign-zone, resign-zone, policy-set, change-policy, policy-reset, freeze, thaw, reload | own zone only |
| `zone update` | own zone only, and every RR in the update must be in that zone |
| `parentsync` bootstrap, roll-key; `childsync` publish, unpublish, advert, reconcile; `delegation sync`; `rollover` asap, cancel, reset, unstick | own zone only |
| `catalog` create, delete | the catalog zone must be its own |
| `catalog` zone-add, zone-delete, zone-group-add, zone-group-delete | the member zone and the catalog zone must both be its own (a static catalog zone by grant) |
| `catalog` group-add, group-delete, notify-add, notify-remove | own catalog zone only |
| `config` reload, reload-zones, transport-signal-release; `scanner` on/off/follow-config/scan/delete; `imr` flush/reset | refused (whole server) |

This is about the management API only. The DNS still answers for every
zone. An application is not the nameserver operator, so it gets no view of
the server's other zones (Johan, 2026-11-24).

The check runs in the handler after it has resolved the zone it will act on,
not on a field peeked at in the middleware, so a command can't act on a
different zone from the one that was checked. Middleware adds one cheap
pre-check: any route or command with no entry in the application table is
refused for application clients, the same fail-closed default that
`RequiredApiRole` has for roles.

### 4.6 The keystore for application clients

| subcommands | for an application client |
|---|---|
| list (all three kinds), list-dnskey | own keys only; list never shows a secret |
| list-algorithms, list-policies | open (no key material) |
| export, bulk-export | own keys only, DNSSEC private keys included: moving a zone to another signer needs them, the reverse of the bind9 and cascade imports |
| add, import, generate, bulk-import | allowed if nothing conflicts (4.7); the new key's owner is the caller; for SIG(0) and DNSSEC keys the zone must be its own |
| delete | own keys only; the existing rules still apply (not from the config, not in use) |
| setstate, setparentstate, rollover | own keys only |
| setowner, purge, clear, policy-cleanup, check | admin only (they act across owners) |
| truststore, child-sig0-mgmt, dsync credentials | admin only |

Bulk commands are filtered per key. A bulk export returns only own keys. A
bulk import reports a key it may not add as refused, with the reason, and
adds the rest.

To make this possible, `/api/v1/keystore` stops being admin for a read-write
application client. The role check learns `SubCommand` for this route.
Admin over the socket keeps everything, as today.

### 4.7 Conflicts

- **TSIG:** the same name with a different secret or algorithm is refused. An
  identical existing key is a no-op and keeps its owner, so the caller can't
  delete it later. That's the inline add's rule today.
- **SIG(0) and DNSSEC:** the zone must be the caller's own. That replaces any
  "no conflict" test, because a key added to someone else's zone is a
  takeover: whoever holds the private key can sign for that zone. Within its
  own zone, the existing per-zone checks apply (duplicate key IDs, state
  rules).

### 4.8 Operators and admin

- Operator certificates (read-write, not in `app-clients`) stay as today:
  read-write on all zones, no keystore. They do key work over the socket.
- Admin gets two tools: `zone setowner <zone> <owner>` (a new command) and
  `keystore … setowner` for all three kinds (TSIG has it; SIG(0) and DNSSEC
  follow their zone). These hand existing zones and keys to an application,
  or take them back.
- Status shows owners: `zone list-dynamic`, `keystore … list` and
  `config status -v` (the app-clients list).

### 4.9 Callers on the key

A caller on the API key has no name, so it is never an application client.
When `app-clients` is set and the access file still has `keyauth` on, config
check warns: the key bypasses every application limit. The recommended state
is `keyauth: false` once the applications have their certificates.

### 4.10 Deleting a zone deletes its keys

Today `zone delete` leaves the zone's SIG(0) and DNSSEC keys in the keystore
(section 3). Left behind, they block a re-add (R3) and need a manual purge.
So:

- `zone delete` also deletes the zone's SIG(0) and DNSSEC keys. That is the
  default for every caller. `zone delete --keep-keys` leaves them.
- TSIG keys are never deleted with a zone, because one key may serve many
  zones. The zone's reference is dropped as today, and an unused key is
  removed with `tsig-mgmt delete`.
- Kept keys belong to no zone, so they are admin-only (4.4). An operator who
  re-adds the zone gets them back. An operator's add is never refused because
  of existing keys: operators must be able to do whatever is needed (Johan,
  2026-11-24).
- An application client's `zone add` is refused while keys for that zone
  exist: the previous zone is not completely gone. The refusal says how to
  clear them. An operator either deletes them, or re-adds the zone and hands
  it over with `zone setowner`.
- `--keep-keys` is refused for application clients. They couldn't re-add the
  zone anyway, so the option would only leave keys behind for an operator to
  clean up.
- The output says how many keys were deleted. For a signed zone, it also says
  that a DS at the parent no longer matches a key here (R12).

## 5. Moving an existing deployment

The feature is off until `app-clients` names someone. For a server where an
application uses the key today:

1. Upgrade tdns-auth. Nothing changes yet; the application's existing zones
   read as owner `api`.
2. Give the application certificate support, which is a client-side change
   in the application. Then create its pair on the application's own host,
   as its service account, so the private key never leaves that host:

   ```
   tdns-ncli client init --name provisioner \
       --cert /path/to/provisioner.crt --key /path/to/provisioner.key
   ```

   This makes a P-256 certificate and its key (mode 0600) and prints the
   pin. Without `--cert` and `--key`, the files go under the service
   account's `~/.config/tdns/certs/`. The application loads the pair from
   wherever they are. The operator needs only the certificate or the pin,
   never the key.
3. Enrol it read-write on the daemon's host, with the same name:

   ```
   tdns-ncli auth client add provisioner --cert provisioner.crt \
       --role read-write --comment "provisioning application"
   ```

   `--pin <pin>` works instead of `--cert`. This creates the access file if
   there is none, checks it with the daemon's validator, writes it
   atomically (the old file is kept as `.prev`) and reloads the daemon.
   The name is the one `app-clients` refers to in step 6. Both commands
   exist today, so the design adds nothing to tdns-ncli here.
4. Hand over its zones and TSIG keys over the socket: `zone setowner` per
   zone, `keystore tsig-mgmt setowner` per key. Per zone and per key is
   enough for now, so there is no bulk form (Johan, 2026-11-24).
5. Grant any static zones it must write (service zone, catalog zones) with
   `api-owner: cert:<name>` in the daemon config.
6. Add it to `app-clients`, reload, and switch the application to its
   certificate.
7. Set `keyauth: false`.

Until step 6, the application can't run with an access file in force. That
is the situation today, so it is no worse.

## 6. Size estimate

The rough size, from the files involved: `keystore.go` 1,800 lines,
`tsig_keystore_mgmt.go` 410, `dynamic_zones.go` 1,640, `apihandler_zone.go`
1,460, `apihandler_catalog.go` 840, `api_roles.go`/`api_auth.go`/
`api_access.go` 770.

| part | Go code | tests |
|---|---|---|
| Z. `zone delete` deletes the zone's SIG(0) and DNSSEC keys; `--keep-keys`; the count and DS warning in the output (4.10) | 120 | 150 |
| A. Owners recorded: `api-owner` in ZoneConf (static and dynamic), the caller's owner on zone add and on inline TSIG; shown in list output; `zone setowner`. No behaviour change. | 300 | 350 |
| B. `app-clients` (config, reload, config check warnings) and the application table with the zone-scope checks in the zone, catalog, parentsync, childsync, delegation and rollover handlers, reads included; filtered lists; the refused re-add and `--keep-keys`; fail-closed default; refusal texts | 550 | 700 |
| C. Keystore for application clients: SubCommand in the role check; own-key filters in list/export/bulk-export for three kinds; owner and zone checks on add/import/generate/bulk-import/delete/setstate/rollover; per-key bulk dispositions | 450 | 600 |
| D. tdns-ncli/tdns-cli: owner columns, `zone setowner`, refusal texts | 150 | 100 |
| Total | about 1,570 | about 1,900 |

The plan is four PRs in this order: Z, A, B, C, with D folded into each. Z
stands on its own and helps today, so it goes first. It is small, about half
a day. A, B and C are each about the size of #1184 (+2,265 −189), which took
about a day including CodeRabbit rounds and rig runs. So **about four working
days**, plus rig work: about 45 new rig cases (each command class allowed and
refused for an application client, the filtered lists, `zone delete` with and
without `--keep-keys`, the key bypass warning, the migration steps). The
application's certificate support is separate, in its own repo, and small
(about 150 lines).

## 7. Risks

| # | risk | likelihood | impact | mitigation |
|---|---|---|---|---|
| R1 | **A command acts on a zone other than the one checked.** Handlers name their zone in different fields (`Zone`, `CatalogZone`, the RRs of an update), so a check on one field can miss another. | medium | high: an application writes into a zone it doesn't own | Check in the handler after it resolves the zone; check every RR of an update; one refusal test per scoped command |
| R2 | **A new route or command is added without an application-table entry.** | high over time | high if it fails open | Fail closed: no entry means refused for application clients. A unit test fails when a route in `apiRouteRoles` has no application-table entry |
| R3 | **Leftover keys are inherited.** Deleting a zone leaves its SIG(0) and DNSSEC keys behind. If another client re-adds the same name, it would own them by 4.4 and could export them. | low (was medium) | high: private-key disclosure across applications | `zone delete` deletes them by default (4.10). If they were kept, an application client's `zone add` is refused while they exist (decided 2026-11-24); an operator deletes them, or re-adds the zone and hands it over. The same class of problem was handled for transport-signal state in `RemoveDynamicZone` |
| R4 | **Bulk commands leak or half-apply.** Selectors and lists cover many keys of mixed owners. | medium | high (leak) or medium (confusing partial import) | Filter by owner in the DB query itself, not after it; per-key dispositions; tests with mixed owners |
| R5 | **The key bypasses all limits.** With `keyauth` on, anyone with the key is read-write and unscoped. | high while migrating | high | Config check warning (4.9); the migration ends with `keyauth: false` |
| R6 | **A reused certificate name inherits ownership.** Owner is `cert:<name>`, so a new certificate enrolled under an old name gets that name's zones and keys. This is what you want for a rotation, and wrong if the name goes to a different application. | low | high | Names are root-managed in the access file; document it; `client add` refuses an existing name unless told to replace it (check what it does today) |
| R7 | **The upgrade breaks a running application.** After step 6 of section 5, its old zones read as `api` and it can't touch them. | medium | medium (provisioning stops; DNS keeps working) | Feature off by default; handover (step 4) before enabling; a refusal text that says "owned by api: an operator can hand it over with zone setowner" |
| R8 | **Owner confusion.** "owner" already means a DNS owner name and, in multi-provider work, the zone's registrant. | medium | low | The field is called `api-owner`; docs and output say "API owner" |
| R9 | **DNSSEC private keys can be exported over the network** for an application's own zones (decided 2026-11-24: moving a zone to another signer needs it). Someone holding a stolen application certificate can take those keys and keep signing after the certificate is revoked. | low | medium | Own zones only; TLS with a pinned client certificate; every private-key export logged with the client name and key ID; the application's certificate is protected like a signing key |
| R10 | **Static-zone grants are too broad.** `api-owner: cert:x` on a static zone allows every zone write in 4.5 on it (but not delete). | low | medium | Document it; if needed later, a narrower grant (update only) |
| R11 | **Performance.** One more check per request: an in-memory zone lookup, and owner filters in keystore SQL. | low | low | None needed |
| R12 | **Keys deleted with a zone are gone for good.** By default, deleting a signed zone deletes its private keys (4.10). Re-adding the zone gives it new keys, so a DS at the parent stops matching until it is replaced, and validating resolvers treat the zone as bogus in the meantime. | low | high for that zone | `--keep-keys` for operators who plan a re-add; the output says how many keys went and warns when the zone had a DS at the parent |

The biggest risks are R1, R2 and R5. R1 and R2 are the classic failure of an
authorization layer added to existing handlers. The handler-side check plus
the fail-closed table test are the defence. R3 is specific to this design's
choice that zone-bound keys take their zone's owner. It now has two defences:
the keys go with the zone by default, and an application's re-add is refused
while kept keys exist. If the refusal turns out awkward, the fallback is to
give SIG(0) and DNSSEC key rows their own owner column after all, filled from
the zone when the key is made.

## 8. Decisions

Johan's answers, 2026-11-24. No open questions remain.

1. **Names:** `app-clients` and `api-owner`.
2. **Zones owned by `api`** (key-era and socket-created zones): application
   clients can't touch them. An operator hands them over with
   `zone setowner`.
3. **DNSSEC private-key export:** allowed for an application's own zones,
   like every other own-key export. Moving a zone to another signer needs it,
   the reverse of the bind9 and cascade imports (4.6, R9).
4. **Leftover keys on re-add:** refuse the add. If old keys are left, the
   previous zone is not completely gone. So that keys aren't left by mistake,
   `zone delete` deletes the zone's keys unless told to keep them (4.10).
5. **Reads:** an application client sees only its own zones. An application
   is not the nameserver operator (4.5).
6. **Bulk handover:** `setowner` per zone and per key is enough for now.

7. **Re-adding with kept keys:** an operator's add is never refused because
   keys exist, and the re-added zone takes the kept keys. Operators must be
   able to do whatever is needed. The refusal applies to application clients
   only, and so does the refusal of `--keep-keys` (4.10).

## 9. Alternatives considered

- **Keep applications on the API key.** It breaks as soon as the server gets
  an access file, and the key has no name, so nothing can be scoped to it.
- **A "provision" role with all of tsig-mgmt.** Simpler, but an application
  could delete any unused API-origin key, including an operator's, and the
  same question comes back for SIG(0) and DNSSEC keys.
- **Admin over TCP for certificate clients.** That also gives stop, the whole
  keystore, the truststore and the DSYNC credentials. The socket-only rule
  for admin is what keeps a stolen network credential from being total.
- **A group-accessible admin socket for the application.** Full admin again,
  and only for an application on the same host.
- **Per-client grants in the access file.** Rejected because tdns-ncli
  rewrites that file. The daemon config is where an operator states policy.
- **A separate application API.** Clean, but a large amount of new surface,
  and it would duplicate most of the zone and keystore commands.
- **Removing a TSIG key when its zone goes.** Wrong: one TSIG key can serve
  many zones. The reference count already prevents deleting a key in use.

## 10. Implementation notes

Decisions taken while building it that the sections above don't settle.

Part Z (`zone delete` deletes the zone's keys):

- The keys go last, after the dynamic config is rewritten, under
  `templateApplyMu` and the zone's rollover lock, in one transaction. If
  that fails, the zone stays deleted and the answer is an error that says
  how to finish by hand.
- The rollover state that describes the keys goes with them
  (RolloverKeyState, RolloverZoneState, ZskRolloverState,
  RolloverCdsPublication, ZonePolicyOverride), so a re-added zone doesn't
  inherit the old phase and DS/CDS ranges. ZoneSigningState stays.
- The keystore's own TrustStore copies of the SIG(0) keys go too; a child's
  key under the same name stays.
- The DS warning uses what the KSK rollover engine last saw at the parent:
  a fact when it saw a DS, nothing when it saw none and none was ever
  confirmed, and a conditional warning otherwise.
- `catalog delete` and `catalog zone-delete` have their own removal path and
  are unchanged.

Part A (owners recorded):

- `api-owner: config` may be written out in the config; `api` there is a
  config error that puts the zone in error state, like other invalid
  per-zone settings.
- `api-owner` is never copied from a template: a grant is said of one zone.
- A dynamic-config entry with an invalid owner is logged and read as `api`,
  not skipped (a skipped zone would be dropped by the next rewrite).
- A catalog member records no owner and follows its catalog zone on every
  lookup. A member whose catalog zone isn't served here reads as `api`.
- `zone setowner` works on zones created over the API (`zone add` zones and
  API-created catalog zones). Config-file zones and catalog members are
  refused with a text that says where their owner comes from. An owner
  that names no client in the access file is accepted with a warning.
- The CLI's `tsig-mgmt --owner` no longer defaults to `api`, so that the
  daemon records the caller.
- `zone list-dynamic` shows the API owner. To stay within 72 characters,
  the catalog, template and error move to indented lines under the row,
  and the Notify column is dropped (`zone list -N` has it).
