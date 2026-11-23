# cli-access: the management API's access changes, end to end

Real `tdns-ncli` (and `tdns-cli`) commands against real tdns daemons run as
root, on two hosts, for the stack that changes how the CLI reaches the
daemons: the local admin socket (#1165), the access file and its roles
(#1167), and the CLI's pins and client certificates (#1168). Design:
`docs/2026-11-20-api-pinning-mtls-roles-design.md` on those branches.

## Scenarios, by PR

Each line is one scenario and the case IDs that check it. A suite runs
against one build; #1165 is verdicted on the socket suite alone.

### #1165, the local socket: `run.sh verify socket`

| Scenario | Cases |
|---|---|
| Root gets admin over the socket with no key (tdns-auth and tdns-imr; an admin command; stop) | S1a S1b S1c S12 |
| The socket is 0600 root's in a 0700 directory | S2 |
| The socket file is gone after a stop over the socket, and after SIGTERM | S12b S12c |
| A non-root user cannot open the socket and gets an error naming it, not a silent fall-back to TCP | S3a S3b |
| TCP without a key, or with a wrong one, gets 403 (loopback and from the CLI host, both daemons) | S4a–S4e (S4f is the control: with the key it answers) |
| Nothing sent over TCP passes as a socket request (spoofed headers, absolute-form URL) | S5a S5b S5c |
| `config status -v` shows the socket | S6a S6b |
| `config add` picks the socket entry for root, the TCP entry with `--tcp` or as non-root, and the entries work. From #1168 6afcc580 (a build with `tdns-ncli --tcp`): it writes the TCP entry with `config-file:` for everyone; root's ping over it goes over the socket, and over TCP with `--tcp` | S7a–S7e, S7f (#1168) |
| From #1184 (config add sets up the client certificate): as root a certificate entry with no key, its pin enrolled in a new access file, one `access-file:` line added to the daemon config, reloaded; the same pair is not enrolled twice; tdns-imr (no TLS) is refused; a non-root user is refused with the `client add` line as the fix, and once root runs it, config add gives the user a working certificate entry. The seeded config is put back after | S7a–S7g (#1184) |
| A stale socket file is replaced at start | S8 |
| A socket that cannot be served (a regular file in the way, a directory open to others) leaves the daemon running and shows as a server error (`config status -v`) | S9a S9b |
| A relative or too-long socket path is refused, the daemon keeps running, `config add` warns | S10a S10b S10c |
| A daemon with no `apiserver.addresses` still serves the socket (tdns-auth, tdns-imr) | S11a S11b S11c S11d |
| A socket-only config needs the key but no certfile/keyfile (no `addresses` line, or `addresses: []`); with addresses it needs both (from #1182: with addresses and neither, the daemon writes its default pair) | S13a–S13d |
| A socket entry sends no key, whatever its authmethod says | S14 |
| `config add` refuses a TCP entry (`--tcp`, or non-root) when the daemon config has no key; root still gets the socket entry (from #1168 6afcc580: root is refused too, as it gets the TCP entry; so it stays with #1184, as the daemon requires the key) | S15a–S15c |
| `config check`: a socket-only config with a relative or too-long socket path fails, with addresses it warns; no certificate is needed without addresses; tdns-imr needs the key in every case | S16a–S16e |

### #1167, access roles: `run.sh verify roles`

| Scenario | Cases |
|---|---|
| The daemon runs the access file: the key is read-write | R0 R2a |
| A read-only client can read and gets 403 on writes and on stop | R1a R1b R1c |
| The key (read-write) operates, and gets 403 on admin commands (stop, reload-tsig); so does a read-write certificate | R2b–R2e |
| Admin works only over the socket; loopback TCP is not the socket | R3a R3b R3c |
| A certificate is the identity: unknown or disabled is refused even with a valid key | R4a R4b |
| A body over 64 MiB gets 413 below admin | R5 |
| `keyauth: false` turns the key off; certificates keep working | R6a R6b |
| A broken access file at a reload changes nothing | R7a R7b |
| A broken access file at start leaves DNS and the socket running, with TCP answering 503 (key or certificate), until a reload over the socket fixes it | R8a–R8e |
| `access-file` without `socket` is refused. From #1168 6afcc580 no `socket` line is the default socket, which the daemon serves; `socket: none` with an access file is refused | R9, R9b (#1168) |
| The access file is managed by a local tdns-ncli | in the pins suite (P3a–P3h): the `client` commands ship in #1168 |

### #1168, client pins: `run.sh verify pins`

| Scenario | Cases |
|---|---|
| The right SPKI pin on the server cert is accepted, a wrong one is refused (and gets no key) | P1a P1b P1c |
| `tlsauth: pkix` works; an https entry that verifies nothing is refused | P1d P1e |
| A client certificate works with `authmethod: certificate`, and only such entries present it | P2a–P2d |
| An unknown client certificate is refused, even with a valid key | P2e P2f |
| A local tdns-ncli manages the access file: list, set-role, disable, enable, keyauth; admin refused; no change from a remote host | P3a–P3h |
| `config add` writes the daemon's pin | P4 |
| Root's TCP entry with `config-file:` goes over the daemon's socket (admin), and over TCP with `--tcp` (read-write); `--tcp` on a `unix://` entry is refused | P8a P8b P8c |
| It stays on TCP when the entry's address is not one the daemon config lists, or when the daemon on the socket runs another config (said); the daemon refuses a socket request naming another config (412) | P8d P8e P8f |
| `config add` pins a known entry that has no pin (drops `rootca:`, changes nothing else); run again it changes nothing | P9a P9b |
| Every daemon serves a socket by default, named after its config path, gone after a stop; `socket: none` serves none and root's entry uses TCP (from #1184 a new entry for it is refused: no socket, no access file) | P10a P10b P10c |
| #1182: with neither `certfile` nor `keyfile`, `config check` says the daemon will write `{confdir}/certs/{name}-api.crt`; `config add` before the first start makes the pair (key 0600) and pins it; the daemon uses it and writes none; the entry works; a restart keeps the pair; half a pair is refused and not rewritten; a `certfile:` the config names that is missing is refused by `config add` | P11a–P11g |
| `http://` to a non-loopback host warns once; loopback stays quiet | P5a P5b |
| `config list` warns about duplicate pins | P6 |
| tdns-cli's behaviour is unchanged | P7 |

An `INFO` line is an observation, not an assertion (for example the socket
file that outlives a stop, which the design notes as cosmetic).

## Shape

Two hosts on one network, both with root:

- **the daemon host** runs tdns-auth (TLS API on 8991, DNS on 5391) and
  tdns-imr (plain-http API on 8992, DNS on 5392) as root, each with its
  socket in `/var/run/tdns/<daemon>.sock`. tdns-ncli runs here as root (over
  the socket) and as an ordinary user, `cliacc` (over loopback TCP with the
  key). `run.sh` runs here, as root, and drives the other host.
- **the CLI host** runs tdns-ncli and tdns-cli as `cliacc`, over the
  network: every pin and client-certificate case runs from here, never over
  loopback.

The certificate clients that tdns-ncli of a build cannot be (before #1168),
and the requests it would never send (no key, spoofed headers, a 64 MiB
body), are sent by `raw.sh` with `openssl s_client`.

Files: `tdns-auth.yaml`, `tdns-imr.yaml` (the daemons), `access.yaml` (the
roles suite's access file), `ncli-*.yaml` and `cli-remote.yaml` (the CLI
configs: root and the user on the daemon host, the user on the CLI host),
`lib.sh`, `ncli.sh`, `raw.sh`, `suites/*.sh`, `setup.sh`, `run.sh`,
`build-arm.sh`.

## Running it

1. **Build** the commit under test on a build host, with make (never on
   either rig host):

        sh tests/cli-access/build-arm.sh /path/to/checkout /path/to/arm-1165 pr1165-<sha>

   and copy the arm directory to the daemon host.

2. **Daemon host, as root:** copy this directory there from a commit, with
   its revision in a `REVISION` file (a run without one says it is not a
   verdict):

        git archive --prefix=cli-access/ <rev>:tests/cli-access | tar xf -
        echo <rev> > cli-access/REVISION

   then

        sh cli-access/run.sh use /path/to/arm-1165      # installs into /var/tmp/cli-access/bin
        sh cli-access/setup.sh <daemon-addr>             # the address the CLI host reaches
        export CLI_SSH='ssh -o BatchMode=yes root@<cli-host>'
        cd /var/tmp/cli-access/src
        sh run.sh ship                                   # rig, client binaries, certs, configs
        sh run.sh verify socket                          # roles, pins, or all

   `setup.sh` creates the user `cliacc` if missing, mints the CA and
   certificates (no key material is committed) and writes the configs with
   the address and pins filled in. A new build needs `use` and `ship` again,
   not `setup.sh`. `CLI_SSH` must work without a password; without it the
   CLI-host cases are SKIP and the result is not a verdict.

3. **Read** the last line: `PASS`, `FAIL` or `INCOMPLETE` (something was
   skipped), with the counts. `verify` exits 0 only when everything passed
   and nothing was skipped. Each run keeps its evidence in
   `/var/tmp/cli-access/runs/<time>-<suites>-<tag>/`: `results.txt` (one
   line per assertion, a FAIL followed by its evidence), one `.out` file per
   command, and the daemons' logs.

`run.sh status` shows the build and the daemons; `run.sh clean` stops them
and removes the state and the sockets (binaries, `src/` and `runs/` stay).

Nothing outside `/var/tmp/cli-access/`, `/var/run/tdns/tdns-{auth,imr}.sock`
and `/var/run/cli-access-rig/` is written, except the `cliacc` user. The
rig's daemons are found by their `--config /var/tmp/cli-access/...`
argument, so other tdns daemons on the host are left alone; if another
daemon already answers on `/var/run/tdns/tdns-auth.sock` (or the imr one),
`verify` stops before it starts anything.
