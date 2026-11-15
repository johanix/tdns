# tests/oots — the OOTS transport-signal rig

End-to-end suites for the `_dns.<ns>` SVCB transport signal (`oots`
SvcParam): tdns-auth publishes it, a tdns secondary re-serves it, tdns-imr
acts on it. Each suite runs real daemons over real sockets, prints one
PASS/FAIL line per assertion, and carries the negative cases that show its
checks are switched on.

The Go tests in each change pin the rules one function at a time. These suites
show the same rules hold between running daemons, and across versions: any
role can run another build, so a suite run on a change's base shows the red
that its run on the change shows green.

## Where it runs

Linux, with unprivileged user namespaces (Debian 12 allows them by default;
Ubuntu 24.04 needs `kernel.apparmor_restrict_unprivileged_userns=0`).
`run.sh` enters a network namespace of its own (`unshare -rn`), as
`tests/deckard` does. Inside it the whole of 127.0.0.0/8 is local and port 53
needs no privilege, so every nameserver gets an address of its own on port 53
and no root is needed. Every daemon dies with the namespace when the command
ends, so each suite starts from nothing, and suites run in any order, any
number of times.

Needs: `unshare`, `ip`, `python3` (to read the CLI's JSON), and a tdns build:
`tdns-auth`, `tdns-imr`, `tdns-cli`, `dog`. The rig needs no PQ algorithms.

## Running it

    BIN=/path/to/bin sh run.sh setup        # certificates, keys, the rig root
    BIN=/path/to/bin sh run.sh list
    BIN=/path/to/bin sh run.sh suite ports tiebreak
    BIN=/path/to/bin sh run.sh all

`BIN` is a directory holding the four binaries. Each role can point elsewhere:

| Variable | Role |
|---|---|
| `AUTH_PUB` | the publishing primaries, whose signal is under test |
| `AUTH_SEC` | secondaries that re-serve a transferred zone |
| `AUTH_INFRA` | the rig's own root server |
| `AUTH_BASE` | the base build for byte-identity checks (suite `published`) |
| `PUB_DO53` | what the publisher does with a do53 its config does not name: `written` (default, builds before OOTS S5) or `omitted` (S5 and later) |
| `IMR` | the resolver under test |
| `CLI`, `DOG` | the observers |
| `CLI_IMR`, `CLI_PUB` | the CLIs that talk to the resolver and to the publishers; each defaults to the `tdns-cli` beside its daemon, since an older CLI drops a newer daemon's fields |

Red against green, for a resolver change:

    BIN=/path/to/change-build sh run.sh suite ignore          # green
    BIN=/path/to/change-build IMR=/path/to/base/tdns-imr \
        sh run.sh suite ignore                                 # red

`setup` is needed once per work root (`/var/tmp/oots-rig`, or `WORK=`). Keys
stay in each party's database under it; `clean` removes it.

## The rig world

A signed rig root at 127.0.0.2 delegates one zone per party, each to an address
of its own (the table at the top of `run.sh`). Signed children get their DS
from `setup`. The resolver runs at 127.0.0.100 with the root's KSK as its trust
anchor, `always-query-for-transport` (it looks up `_dns.<ns>` for every new
server) and `allow-loopback-nameservers`. A suite starts its own servers and a
fresh resolver, so no signal learnt in one suite reaches another.

The resolver's view is `tdns-cli imr stats auth-transports --json`: the signal
and its ports as held, answers and failures per transport.

A suite proves where a query went by where the servers listen: a server listens
for a transport only where the right answer is, and, where it matters, also
where a wrong resolver would go (a trap). A resolver that ignores a port fails
on the standard port and falls back to Do53; one that misapplies a record
succeeds at the trap. Either shows in the counts.

## Suites

Each suite file starts with its scenario: the parties, what is done, what is
observed, and the negative case.

| Suite | Scenarios | Shows | Red on |
|---|---|---|---|
| `ports` | K2, P1, P2, P6 | a port on a `.` record moves the transport on the server's own address: from `ports:` config, from one record naming two transports, from an ALPN-only record | a resolver without port support; P2, P6 on #994's head |
| `published` | K1, M3 | what `service.transport` publishes: one record per ported transport, never do53 beside udp or tcp, an empty signal with a udp port as `udp:100` with that port (`PUB_DO53=omitted`); a default config byte-identical to the base build, or (`PUB_DO53=omitted`) identical but for the default do53 | a publisher that ignores `ports`, changes the default, or writes the default do53 against `PUB_DO53` |
| `ignore` | P3, P4 | a record with a target, and the ServiceMode siblings of an AliasMode record, are not applied | a resolver that applies them (trap) |
| `tiebreak` | P5 | a transport named twice takes the same record in both RR orders | a resolver where the last record wins |
| `lossless` | C1 | a tdns secondary re-serves every oots value byte for byte: unknown tokens, only-unknown values, odd identifiers, a weight octet above 100; the resolver validates each | a secondary or resolver whose codec drops or clamps |
| `customer` | Z1–Z7 | a server includes signals by zone data and writes one only into its own zone: a customer's alias to the provider's signal, two customers' aliases to one target asked together, an NS named in the provider's zone, an alias to a target it does not hold; nothing written into a customer zone, with or without an identity; the resolver follows the alias on a Secure path | a publisher that writes into a zone it hosts for someone else, or injects by identity; a resolver that does not follow the alias |
| `bridge` | B1–B4 | tdns-cli's bridge from a synthesized signal to a provisioned one: the printed records are the served ones; pasted and released, they stay once the name leaves `service.identities` and a changed `service.transport` does not reach them | a release that does nothing; without the release the records are withdrawn (the suite's own red, B4) |

Scenario ids keep verdict tables narrow: B bridge, C codec, K config, M versions,
P ports and records, Z zone data.
