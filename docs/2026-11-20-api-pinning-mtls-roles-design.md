# Management API: a local socket for admin, pinned keys for the network, three roles

**Date:** 2026-11-20
**Status:** being implemented. Steps 0 and 1 (section 5) are #1163 and #1164,
on main. Step 2, the local socket, is #1165, stacked on the tdns-ncli PRs #1159,
#1160 and #1161; step 3, the access file and the roles, is stacked on #1165.
Step 4 follows. Section 9 lists what implementing changed or settled.

Scope: the management API of every daemon that builds its router with
`SetupAPIRouter` (tdns-auth, tdns-agent, ...) or `SetupSimpleAPIRouter`
(tdns-imr, ...), and the tools that call it (tdns-ncli first; tdns-cli keeps
working throughout).
Not in scope: the agent sync API, the DSYNC API listener (separate surfaces with
their own authentication), and the tdns-mp daemons (their router setup was not
checked).

## Summary

Today the API is protected by one shared secret, sent in a header, over a TLS
connection that the CLI does not verify unless told to. This proposal:

- adds a **local unix socket**. Whoever can open it is admin, authenticated by
  file permissions alone: root on the daemon host needs no key, no pin and no
  enrollment, and nothing can take that way in from them;
- makes **admin exist only on that socket**. The network API (TCP, loopback
  included) tops out at read-write;
- authenticates **both ends of the network API by a pinned public key** (SHA-256
  of the SPKI), with no CA;
- moves the access policy of the network API into **one access file**, named by
  a single line in the daemon config: the list of clients (name, pin, role) and
  the switch that turns the API key off;
- has **three roles**, one per client: `read-only`, `read-write`, `admin`;
- lets a **local tdns-ncli manage the access file, and nothing else**, through a
  validator the daemon shares, so the tool cannot write a state the daemon would
  refuse;
- keeps everything as it is until the operator opts in, per daemon.

The aim is 1–3 operators and a handful of daemons. Everything here is sized for
that; nothing is meant to scale to a fleet.

## 1. Where we are

Checked against the code on main (9da5f34d), 2026-11-20.

- **One shared secret.** `X-API-Key`, compared in constant time, one check in
  front of every `/api/v1` route (`apiKeyAuthMiddleware`, `v2/apirouters.go`).
  The key is captured when the router is built, so a config reload does not
  change it.
- **No identity.** Every key holder is the same principal; logs name nobody.
- **The CLI does not verify the daemon by default.** An empty `rootca:` becomes
  `insecure`, i.e. `InsecureSkipVerify` (`v2/cli/apiclient.go`). The sample
  config sets no `rootca:`. TLS then protects only against passive listening: a
  host that answers on the address receives the key and can replay it.
- **The daemon never asks for a client certificate.** `APIdispatcher` sets no
  TLS config. `apiserver.usetls: false` serves plain HTTP.
- **The key sits in cleartext** in the daemon config and in every CLI config.
- **`config status` returns the key.** It encodes the whole `ApiServer` block as
  JSON. `SensitiveString` redacts only in `String()`; `encoding/json` ignores
  that and writes the value (shown with a stand-alone snippet; to be confirmed
  against a running daemon). Harmless while every key holder is admin. With
  roles it would hand the admin key to a read-write client, so it is fixed first
  (section 5, step 0).
- **The verb is in the body.** The routes are mostly one POST per area
  (`/keystore`, `/zone`, `/config`, `/imr`, ...) with `Command` and
  `SubCommand` in the JSON. The unit that a role applies to is therefore
  (route, command), not the URL.
- **SIGHUP reloads zones, not the config.** In tdns-auth the SIGHUP watcher calls
  `ReloadZoneConfig` (`cmdv2/auth/main.go`). A full config reload goes through
  the API (`config reload`). A daemon whose API is down therefore cannot be told
  to re-read its access policy without a restart, unless something other than
  the network API can do it (section 3.2).
- **Routes added later escape the key check.** `SetupAPIRouter` puts the check on
  one `/api/v1` subrouter (`sr.Use(...)`). A route registered afterwards on
  *another* `/api/v1` subrouter of the same root router is not behind it.
  tdns-mp does exactly that in `SetupMPAgentRoutes`, `SetupMPSignerRoutes`,
  `SetupMPCombinerRoutes` and `SetupMPAuditorRoutes` (tdns-mp origin/main, no
  `.Use(` in any of them), so its management routes (`/agent`, `/keystore`,
  `/truststore`, `/peer`, ...) look to be reachable with no key. Reproduced
  with gorilla/mux 1.8.1: the request without a key is refused on the first
  subrouter and answered by the second; with the middleware on the root router
  both are refused. Not yet confirmed against a running tdns-mp daemon. The fix
  is independent of this design and goes first (section 5, step 1).

## 2. Goals and non-goals

Goals: no CA; no lock-out; a model an operator can hold in their head; root on
the daemon host needs no credential; the operator never hand-builds API access
(`tdns-ncli config add` does the client side, `tdns-ncli client add` the daemon
side); enrolling a remote operator is two commands and cannot lock anyone out.

Non-goals: CA or PKIX provisioning, a database-backed client store, a daemon
that rewrites its own access policy over the network, per-operator custom roles,
sets of capabilities, revocation lists, OAuth/OIDC, TLSA, rate limiting, admin
for local users other than root (a socket group), peer-credential identities on
the socket.

## 3. The model

Two ways in, with different jobs:

| | local socket | network API (TCP) |
|---|---|---|
| who | whoever can open the socket file: root on the host | remote operators, scripts |
| authentication | file permissions | a pinned client certificate, or the API key |
| roles | admin | read-only, read-write |
| depends on the access file | no | yes |

### 3.1 The client verifies the daemon (network API)

A tdns-ncli `apiservers:` entry for a TCP daemon gains:

```yaml
tlsauth: pin                   # pin | pkix; entries written by config add use pin
pins:    [ "<base64 sha256>" ] # a list: the current key and the next one
```

The pin is `SPKISHA256`: base64 of SHA-256 over the certificate's
SubjectPublicKeyInfo. It is the value `tdns-cli cert pin` prints and the one XoT
`pins:` already uses. It is checked in `VerifyConnection` with
`InsecureSkipVerify` set, the pattern already in `v2/xot.go`. There is no name
check and no expiry check: the pin is the trust anchor, the certificate is only
its container.

`tdns-ncli config add <daemon.yaml>` already reads the daemon's config for the
address and the key; it would also read `apiserver.certfile` and write the pin.
The operator does nothing. (For a daemon with a socket it writes a socket entry
instead, section 3.2.)

`tlsauth: pkix` (system roots or a `rootca:` file) stays for anyone with a real
CA. `insecure` is accepted only when spelled out, and tdns-ncli warns each time.
A tdns-ncli TCP entry with none of the three refuses to connect. (tdns-ncli has
its own config file and is a prototype; tdns-cli's defaults do not change.)

### 3.2 The local socket

```yaml
apiserver:
   socket: /var/run/tdns/tdns-auth.sock    # unset = no socket, as today
```

- **Authentication is the file system.** The daemon creates the socket with mode
  0600 inside a directory that is not accessible to group or others, and refuses
  to serve it from a directory that is (a socket in `/tmp` would be an open
  door). Whoever can open it is admin. No TLS, no key, no certificate: nothing
  secret travels, and nothing can be replayed.
- **Nothing on the network can reach it**, by construction.
- **It does not depend on anything else.** Not on the access file, the API key
  or any certificate. Root on the host can always manage the daemon, fix the
  access file and tell the daemon to reload it, whatever state those are in.
  This is what makes lock-out impossible rather than unlikely.
- **All routes, all commands.** The role is admin.
- **Housekeeping.** A stale socket file left by a crash is removed at start, but
  only if it is a socket and nothing answers on it, never a regular file. The
  path must fit the platform limit (about 100 bytes). The daemon logs requests on
  it as `local`.
- **Client side.** A tdns-ncli entry (or a tdns-cli one: the code is the shared
  `NewClient`) with `baseurl: unix:///var/run/tdns/tdns-auth.sock` dials the
  socket; it needs no `apikey`, no `authmethod` and no TLS settings (the
  `validate:"required"` tags on `ApiKey` and `AuthMethod` in `ApiDetails` must
  be relaxed for such an entry). `tdns-ncli config add <daemon.yaml>` writes
  this entry when the daemon config has `apiserver.socket`, so a local daemon
  needs no secret in any CLI config.

### 3.3 The daemon verifies the remote operator (network API)

**The operator's identity** is one key pair per person, used for every daemon: a
self-signed certificate (ECDSA P-256), the key in a file with mode 0600. The
default location is per user: `~/.config/tdns/client.crt` and `client.key`; for
root, `/etc/tdns/tdns-ncli-client.crt` and `.key`, next to `tdns-ncli.yaml`,
where it can be tracked and is not scattered over `/root/.config/` on many hosts.
It is expanded when the tool runs, so the system-wide config needs no entry for
it; a top-level `client:` block can name other files. `tdns-ncli client init`
creates the pair if it is absent and never overwrites one. Root on a daemon host
does not need one (it uses the socket); the key is for people on their own
machines.

**The access policy of the network API** is one file, named by one line in the
daemon config. Unset, the network API behaves exactly as it does today.

```yaml
# daemon config: set once, by hand. New installs get it from the sample config.
apiserver:
   addresses: [ 127.0.0.1:8989 ]
   apikey:    "..."                              # unchanged
   certfile:  ...
   keyfile:   ...
   socket:      /var/run/tdns/tdns-auth.sock     # required when access-file is set
   access-file: /etc/tdns/tdns-auth-access.yaml  # unset = key only, as today
```

```yaml
# the access file. Owned by tdns-ncli; plain YAML, so a hand edit still works
# for recovery. Notes go in comment: (YAML comments do not survive a rewrite).
keyauth: true            # false = client certificates only
clients:
   - name: anna
     pin: "<base64 sha256>"
     role: read-write    # read-only | read-write. admin is refused (section 3.4)
     comment: "laptop"
   - name: nightly-report
     pin: "<base64 sha256>"
     role: read-only
     disabled: true      # keeps the entry, refuses the client
```

When `access-file` is set the daemon asks for a client certificate on its TCP
listener (always, while TLS is on) and its middleware decides. The certificate's
pin is looked up among the enabled clients. A request authenticated by the API
key has the identity `apikey` and the role **read-write** (with `access-file`
unset it stays admin, as today).

`ping` answers with who the daemon thinks the caller is: "authenticated as anna
(read-write) by certificate", "by api key (read-write)" or "on the local socket
(admin)". That is the diagnostic when something does not work.

The access file is read by its own loader, not decoded as part of the daemon
config, so a refused reload cannot leave half of it behind (section 4, rule 4).
`config status` reports what is *running*: the socket, `keyauth`, the client
names, roles and whether each is enabled. `client list` compares that with the
file and says "pending reload" when they differ.

**Enrollment** needs one line from each side and only public data:

```
tdns-ncli client init                  # on the operator's machine. Prints the
                                       # name, the pin and the exact line below.
tdns-ncli auth client add anna --pin <pin> --role read-write   # on the daemon host, as root
```

For a remote operator the printed line is sent to an admin, who runs it on the
daemon host (over ssh). There is deliberately no network path that changes the
access file.

### 3.4 Three roles

A ladder: read-only < read-write < admin. One role per client.

| role | may | may not | available on |
|---|---|---|---|
| read-only | everything that only reports: list, show, status, queries, debug reads | change anything; touch key material | network API |
| read-write | all of that, plus operate: zones, config reload, sync, catalog, resolver flush and forwarders, key *lifecycle* operations (rollover, roll-key) | read, write or delete stored key material; change what is trusted; issue credentials; stop the daemon | network API |
| admin | everything | | **the local socket only** |

**Admin never crosses the network.** A TCP client, loopback included, has at most
read-write. An access-file entry with `role: admin` is a load error ("admin is
available only on the local socket"), so there is no run-time address check to
get wrong and nothing for a proxy or an `ssh -L` tunnel to confuse. A command
that needs admin, asked over TCP, is answered 403 with a message that names the
socket.

**Default deny.** The classification is a table of (route, command) mapped to
`read-only` or `read-write`. Anything not in it (a new command, an unknown
command, a new route) requires `admin`. A forgotten entry makes something too
strict, never too open.

The rule for "keys": whatever *reads, writes or deletes stored key material or
decides what is trusted* is admin. Whatever runs the key lifecycle through the
zone machinery is an operation, and read-write. Classification by command name
(each to be confirmed against its handler during implementation):

| route | read-only | read-write | admin (socket) |
|---|---|---|---|
| `/command` | status, api | | stop |
| `/config` | status, transport-signal | reload, reload-zones, transport-signal-release | reload-tsig (touches the TSIG keystore) |
| `/debug` | rrset, validate-rrset, lav, show-ta | | |
| `/zone` | list-zones, get-name, get-delegation, journal, show-nsec-chain, zonemd, proxy-key, list-dynamic | bump, write-zone, sync, update, sign-zone, resign-zone, policy-set, change-policy, policy-reset, freeze, thaw, reload, add, delete, modify | |
| `/zone/parentsync` | status, inquire | bootstrap, roll-key, publish, unpublish | |
| `/delegation` | status, export | sync | |
| `/catalog` | zone-list, group-list | the rest | |
| `/rollover/*` | status, when | asap, cancel, reset, unstick | |
| `/scanner/poll` | | all | |
| `/imr` | query, show, dump-*, resolve, forward/stub list·status·probe, client-stats, auth-transports, transport-stats | flush, reset | |
| `/keystore` | | | all (DNSSEC, SIG(0) and TSIG material, key lifecycle) |
| `/truststore` | | | all |
| `/dsync-api/*credential` | | | all |

`keystore list` is admin too: "no access to keys" is applied literally.
`rollover status` is what a read-only operator uses to see key state.

### 3.5 Enforcement

One middleware on the **root router** (`rtr.Use`, not on the `/api/v1`
subrouter), installed by both router builders (`SetupAPIRouter` and
`SetupSimpleAPIRouter`):

1. identity, in this order:
   - the connection came in on the socket → `local`, admin;
   - TCP, `access-file` set but no valid snapshot (section 4, rule 5) → 503 for
     everything, with a generic body ("management API disabled by a
     configuration error; see the daemon log or use the local socket");
   - TCP, certificate pin among the enabled clients → that client and its role;
   - TCP, valid API key → `apikey`, read-write when `access-file` is set (and
     `keyauth` is on), admin when it is not;
   - otherwise 403;
2. read `Command` and `SubCommand` from the body (buffer it, restore it for the
   handler, cap its size; the same `encoding/json` the handlers use);
3. look up the required role, compare, deny with 403;
4. log every request: `client`, `role`, `route`, `command`.

On the root router it covers every route registered later, by
`RegisterAPIRoute` callbacks or by tdns-mp's `Setup*Routes`, each of which makes
its own `/api/v1` subrouter (section 1). tdns-mp's routes are not classified in
the role table, so with `access-file` set they would need admin, which is the
socket only; a small registration hook lets tdns-mp declare the class of its own
routes (in step 3 of section 5).

Guard tests:

- a route registered on a second `/api/v1` subrouter, after the builder returns,
  is refused without credentials;
- a parse-based test (the technique of the tdns-ncli tree-parity tests)
  enumerates every route and every command `case` in the handlers and requires
  each to be in the table or in an explicit admin-by-default list; a table entry
  naming a command no handler has fails;
- a TCP request, with any identity, never reaches a command classified admin;
  the same request on the socket does;
- with a broken access file the TCP API answers 503 and the socket answers 200.

### 3.6 TLS on the TCP listener

- `MinVersion` TLS 1.3, `ClientAuth: RequestClientCert`. Never
  `RequireAnyClientCert` while `keyauth` is on, so key-only clients keep working.
- Pin comparison in constant time, against the snapshot described in section 4.
- `usetls: false` makes certificate authentication impossible: clients in the
  access file are then ignored, with a warning. (`keyauth: false` together with
  `usetls: false` closes the TCP API for everyone; that is a legitimate
  socket-only configuration, not an error.)

### 3.7 What a local tdns-ncli may change

The tool runs with the invoking user's file permissions, which already let that
user do anything to the daemon's files by hand. So the limit on the tool is not a
security boundary. It is a safety boundary: it limits what a *mistake* can
break.

**The tool may change one thing: the access file.** It never touches the main
daemon config, `apikey`, the daemon's certificate or any other file. Its `client`
commands edit files on this host, so they work on an entry that names a local
daemon and refuse a remote one ("run this on the daemon host").

```
tdns-ncli client init                                  # a remote operator's key pair
tdns-ncli <instance> client add <name> (--pin P | --cert F) --role R
tdns-ncli <instance> client list                       # file vs running daemon
tdns-ncli <instance> client disable|enable <name>
tdns-ncli <instance> client set-role <name> R
tdns-ncli <instance> client keyauth on|off
```

- `R` is `read-only` or `read-write`; `admin` is refused with the reason in
  section 3.4.
- There is no `remove`: `disable` is the revocation and it stays visible in the
  file. Deleting an entry is a one-line hand edit for the day it is wanted.
- `add` takes a pin or a public certificate, never a private key, so it works
  under `sudo`.
- The daemon is found as `config add` finds it: the instance's `config-file:`
  names the daemon config, which names the access file. If the daemon config
  has no `access-file:` yet, `add` creates the file at the suggested path and
  prints the one line to add (and the `socket:` line if that is missing too);
  until those lines are there the daemon does not read the file, so added clients
  do nothing. `client list` and `ping` say why.

**Every write follows the same steps:**

1. Validate the resulting file with the shared validator (`ValidateAccessFile`,
   section 4).
2. Write atomically (temporary file and rename, following symlinks), keeping
   owner and mode, and keep the previous file as `<name>.prev`.
3. Reload through the socket, which needs no credentials. A refused reload
   changes nothing; `--no-reload` skips it.
4. Say what was done and what the running daemon now has.

`--dry-run` shows the resulting file and writes nothing. A test requires that
whatever the tool writes passes the offline `config check`.

`client keyauth off` needs no gate: it cannot lock anyone out, because the
socket does not depend on it. The tool says what it means ("remote access will
then need a client certificate") and, if no enabled client exists, that the TCP
API will then be unusable for everyone but the socket.

**What stays a hand edit:** the `socket:` and `access-file:` lines in the daemon
config, once per daemon (the sample configs carry them). Everything an operator
does day to day goes through the tool.

## 4. No lock-out

1. **Additive.** `socket` and `access-file` both unset: the daemon behaves as
   today. A socket alone changes nothing for the network API. `access-file` set,
   with `keyauth: true` (the default in the file): the key keeps working, as
   read-write, and certificates are accepted in addition.
2. **The socket is the way in nothing else can take away.** It depends on
   neither the access file, the key nor any certificate, so root on the host can
   always get in, fix the file and reload. Lock-out of the *system* is
   impossible; what a bad access file can do is cut off *remote* operators until
   root fixes it.
3. **`access-file` requires `socket`.** Without the socket nothing could be
   admin once the key is capped at read-write. A main config that sets the one
   without the other is a config error, like any other.
4. **A refused reload changes nothing.** `reloadConfig` decodes into `conf`
   *before* validating and puts back a hand-picked list of fields on failure;
   `apiserver` is not on it. So the middleware must not read `conf.ApiServer`.
   The client list and the key mode are read by their own loader into an
   immutable snapshot, published atomically only when the parse and validation
   succeed (as `publishRuntimeConfig` does), and a test shows that a bad access
   file in a reload leaves the previous snapshot in force.
5. **A broken access file at start-up costs the TCP API, not DNS.** There is no
   snapshot to keep. The daemon starts, serves DNS and the socket, logs the file
   and the error, lists it among the active server errors (so `config status`
   shows the daemon as degraded), and answers 503 on the TCP API until a reload
   publishes a valid snapshot: `tdns-ncli <instance> config reload` over the
   socket. It never falls back to key-only, which would be a security downgrade
   exactly when something has gone wrong.
6. **One validator.** `ValidateAccessFile` is run by the offline `config check`
   (an error), by the tool (it refuses to write), and by the daemon at start
   (rule 5) and reload (rule 4). The four cannot disagree. It checks: `name`,
   `pin` and `role` present; names and pins unique; the role one of the two
   network roles (`admin` gets the message from section 3.4); a pin that parses;
   an unknown key is an error, not ignored.
7. **Recovery is a file edit on the host.** Set `keyauth: true` in the access
   file (or restore `<name>.prev`), then reload over the socket. No database and
   no network call is needed.
8. **Revocation stays visible.** `disabled: true` keeps the entry in the file, so
   a revocation shows up in a diff and re-enabling is one word.
9. **The tool is held to the same rules** (section 3.7): it writes only the
   access file, only a file the shared validator accepts, atomically, with a
   `.prev`.

## 5. Rollout

Each step ships on its own.

0. **Redact `apikey` in `config status`** (`SensitiveString` marshals as
   `"[REDACTED]"`, as does `ApiServerAppConf`; with a test). Independent of
   the rest; do it first.
1. **The key check on the root router** (section 3.5), so that routes added
   later cannot escape it, with the guard test. A bug fix, independent of the
   rest. It makes tdns-mp's management routes require the key, which the shared
   client already sends.
2. **The socket.** The listener (permissions, directory check, stale-socket
   handling), `unix://` in `NewClient`, `config add` writing a socket entry, and
   `config status` reporting the socket. Valuable alone: a local daemon needs no
   secret in any CLI config. The key still works exactly as before.
3. **Daemon, network side:** `access-file`, the loader and `ValidateAccessFile`,
   the snapshot, the middleware, the role table and the hook that lets tdns-mp
   classify its own routes, the logging, `ping` naming the caller, the 503 state,
   and `config status` reporting the running access state. The key is still
   accepted (as read-write once `access-file` is set).
4. **tdns-ncli:** pin verification, the client key pair and certificate
   (`client init`), the `client` commands, `config add` writing pins, and
   `config list --check` reporting the auth mode, the identity the daemon sees,
   the pin match and whether the access file is pending reload, and flagging two
   entries that pin the same key.
5. **Per daemon, when ready:** `client keyauth off`.

tdns-cli keeps working with the key throughout; with `unix://` in the shared
`NewClient` it can use the socket too, once its config names it. It stops working
against a daemon over TCP at step 5, by design.

## 6. Alternatives considered

- **Root as a built-in user, only from 127.0.0.1.** A loopback address is a
  location, not a credential: with no credential any local process, a web
  application with an SSRF or any local user, is admin, which is worse than
  today. With a credential (a root certificate in `/etc/tdns/`, an entry marked
  local-only) it needs a key and an enrollment per host and a run-time source
  check, and an `ssh -L` tunnel or a local proxy makes remote connections look
  like loopback. The socket gives the same local root with no secret at all.
- **Admin over TCP with an address check.** The same ambiguity, and a check that
  can be got wrong. Admin on the socket only is a rule with nothing to check.
- **Root on the host gets a lower role by default and asks for admin with
  `--admin`.** Rejected, for now. The flag would be a speed bump, not a boundary:
  root can already read the keystore database and every config file, and the
  socket authenticates exactly "root on this host". Giving root normal access
  over TCP brings back a key, a pin and an enrollment per host; doing it on the
  socket with the client choosing a lower role cannot be enforced by the daemon.
  `tdns-cli` has no such flag and would lose keystore access on a socket entry,
  and root scripts would break. Nothing is closed off: an optional "at most role
  X" request header on the socket can be added later, with its absence still
  meaning admin, and `tdns-ncli` could then default to read-write and take
  `--admin`. The case that would justify it is letting unattended automation run
  read-write commands as root without touching keys.
- **PKIX with client certificates from one CA.** Needs a CA to protect,
  distribute and rotate, and revocation is hard. It fits a fleet, not 1–3
  operators. Kept as `tlsauth: pkix` for server verification.
- **A client table in the database, managed through the API.** The first admin
  has no way in, changing it needs the very API it protects, and recovery means
  database surgery. Rejected in favour of a file.
- **The daemon rewrites the access file when asked over the network.** A
  network request would change who may get in. Rejected: changes come from the
  host, by someone with file permissions.
- **`clients:` inline in the daemon config.** The tool would have to edit a
  hand-written file with comments, includes and templates, which is where an
  edit goes wrong. A separate file the tool owns needs no splicing.
- **An `include:` fragment instead of `access-file`.** Lists are replaced, not
  merged, so two places could define clients and one would silently win.
- **Several roles or capability sets per client.** More than the need.
- **Requiring key and certificate together.** Doubles the lock-out surface; the
  certificate already removes the replay problem.
- **TLSA.** A DNS dependency in the channel that manages DNS.

## 7. Decisions, things to verify

Decided (2026-11-20):

- An operator's key is per user, one key pair for every daemon; for root it is in
  `/etc/tdns/`, not `/root/.config/`.
- `reload-tsig` is admin; `stop` is admin.
- A local tdns-ncli may change the access file and nothing else, as in 3.7.
- A broken access file at start-up: DNS starts, the TCP API is down (503), the
  socket works.
- The access file lives at `/etc/tdns/<daemon>-access.yaml`, next to the daemon
  config.
- Root on the host uses a unix socket and no key; admin exists only on that
  socket; with `access-file` set the API key is capped at read-write.
- The socket path in the samples is `/var/run/tdns/<daemon>.sock`, in a directory
  only root (and the daemon's own user) can enter.
- Root's use of the socket is admin by default, with no `--admin` flag (section
  6). There are no open questions.

To verify before or during implementation:

- that tdns-mp's management routes really answer without a key on a running
  daemon (section 1);
- how NetBSD enforces the permissions of a socket file (the root-only directory
  makes it moot, but it is the platform most daemons here run on);
- that `config status` really returns the key from a running daemon;
- each command's class against its handler, not only its name;
- whether the `validate:"required"` tags on `ApiDetails` are enforced for CLI
  entries.

## 8. Scope

Calibration: the three tdns-ncli pull requests (#1159, #1160, #1161) are 3,836
added lines: 1,967 of code, 1,398 of tests and 471 of docs.

Measured on main (9da5f34d): the router builder is 356 lines with 41 route
registrations; the handlers behind them are about 4,000 lines with about 100
command `case`s (`/zone` 35, `/keystore` and the others in `apihandler_funcs.go`
27, `/imr` 17, `/catalog` 13); the daemons that build a router are tdns-auth,
tdns-agent, tdns-imr and tdns-signer here, and four tdns-mp daemons.

| step | what | size | lines (code + tests + docs) |
|---|---|---|---|
| 0 | redact the key in `config status` | S | ~80 |
| 1 | key check on the root router, guard test | S | ~180 |
| 2 | the socket: listener, `unix://` client, `config add` entry, status | M | ~800 |
| 3 | daemon network side: access file, validator, snapshot, middleware, role table, tdns-mp hook, `ping`, 503 state | L | ~1,950 |
| 4 | tdns-ncli: pin verification, client certificate, `client init` and the six `client` commands, `config list --check` | L | ~1,950 |
| 5 | per daemon: turn the key off | no code | one host per daemon type to check |

About 5,000 lines, roughly 45% of them tests: 1.3 times the ncli batch in size.
It is denser (authentication, the reload path), so budget 1.5 to 2 times the
effort. Steps 3 and 4 are each a little smaller than ncli PR 1; step 2 is about
the size of ncli PR 3. Sample configs for the four daemons and a guide chapter
travel with the steps that change them.

**Order and dependencies.** Steps 0 and 1 are independent of everything and go
first (step 1 closes a hole). Step 2's `config add` entry and all of step 4
build on the unmerged ncli PRs (#1159 to #1161), which therefore merge first. The
daemon parts of steps 2 and 3 do not depend on them.

**The largest review burden** is the role table: about 100 (route, command) rows
classified against their handlers, which the parse-based guard test keeps
honest but cannot judge.

**Risks.** (1) The tdns-mp daemons share `SetupAPIRouter`: after step 1 their
routes need the key, and after step 3 they are admin-only (socket) until
tdns-mp classifies them through the hook. (2) The reload path is intricate (it
decodes before it validates and restores a hand-picked list of fields), so the
snapshot publication needs the test in section 4, rule 4. (3) The shared
`NewClient` is used by tdns-cli, tdns-ncli and tdns-debug; pin verification and
the unix dial must not change what existing entries do. (4) The socket on NetBSD
(section 7).

**What could be cut.** The `client` commands could be a hand edit of the access
file in a first version (about 600 lines less), at the price of exactly the
cumbersomeness this design is meant to remove. Nothing else is separable.

## 9. Amendments

**2026-11-20, implementing steps 0 to 2.**

- **Step 0 had two consumers the design did not list.** `config status` printed
  three characters from each end of the key; it now says whether a key is set.
  `config check` compared the file's key with the running server's to spot a
  key changed without a restart. It now compares the file's key with the key
  the status request was sent with: the reply came back, so the running server
  accepted that key. That is also the more accurate comparison, because the
  running server keeps the key it started with while `conf.ApiServer.ApiKey` is
  re-decoded on reload.
- **Step 1 as designed.** The KDC and KRS routes already carry their own
  `X-API-Key` header matcher, so the root-router check changes nothing for
  them.
- **Step 2, `config add`.** It writes a socket entry only when run as root,
  because nobody else can open the socket; anyone else gets the TCP entry with a
  note, and `--tcp` forces TCP. A daemon that already has a TCP entry is the
  same daemon: `config add` reports it as known and says which lines to change
  to use the socket. A socket entry has no `apikey:` line and says
  `authmethod: none`.
- **Step 2, the daemon.** The socket is served even when `apiserver.addresses`
  is empty. `apiserver.apikey` is still required by the router builders; that
  changes with the access file in step 3. `apiserver.certfile` and `keyfile`
  are required only with `apiserver.addresses`: the socket uses no TLS. A
  stale socket is removed only when connecting to it is refused; any other
  probe failure leaves it alone. A daemon removes its own socket on the way
  out (MainLoop, Shutdowner), after a signal as well as after an API stop. A socket that cannot be served is a
  server error (Transport/ApiSocket), so `config status` shows the daemon as
  degraded, and the daemon keeps running.
- **Things to verify, settled.** The `required` tags on `ApiDetails` are not
  enforced (the CLI validates no sections of its own config), so a socket entry
  without a key loads. `config status` did return the key: a test drives the
  real handler and fails without step 0. The tdns-mp routes did escape the key
  check: a test builds the real routers, adds routes as tdns-mp does, and fails
  eight times without step 1. Still not tried against a running tdns-mp daemon.
  How NetBSD enforces a socket file's permissions is still open; the 0700
  directory is what the design relies on.

**2026-11-20, implementing step 3.**

- **The role table, settled against the handlers.** The guard test found what
  the table in 3.4 had wrong or missed: `/zone/parentsync` has no publish or
  unpublish (they are `/zone/childsync`'s, with advert and reconcile,
  read-write, and proxy-status, read-only); `/catalog` also has
  notify-add, notify-remove (read-write) and notify-list (read-only); `/debug`
  also has show-rrsetcache and zone-txlog (read-only); `/scanner` has status
  (read-only) and scan (read-write); `/scanner/delete` is read-write. Every
  command of every handler is now listed explicitly; a non-admin `*` is kept
  only for routes whose handler has no command (the rollover POSTs, `ping`).
- **A certificate is the identity.** An unknown or disabled certificate is
  refused even if the API key comes with it; it does not fall back to the key.
- **A body too long to read (over 64 MiB)** has a command that cannot be
  checked: a network client gets 413, saying so. The local socket is admin and
  needs no check, so its handler gets the whole body. (The first build capped
  this at 1 MiB and answered "needs admin", which refused a large write to
  every network client; changed after the external review.)
- **Commands are matched lower-cased and trimmed.** Matching only ever makes a
  check stricter or equal: a command the handler does not know is refused by the
  handler, and an unknown one needs admin here.
- **Logging.** Every request needing read-write or admin is logged at info
  with client, role, route and command; read-only ones at debug, so a polling
  client does not fill the log. Refusals are logged at info.
- **`apiserver.apikey` stays required.** `keyauth: false` turns it off; the key
  itself is not made optional.
- **Taking `access-file` out of the config** and reloading returns the TCP API
  to key-as-admin, and the reload says so.
- **TLS.** The TCP listeners always ask for a client certificate (never
  require one); with an access file they are TLS 1.3 only.
- **tdns-mp.** `RegisterApiRouteRoles` lets code outside the package declare
  the roles of its routes; until tdns-mp does, its routes need admin when an
  access file is set.
