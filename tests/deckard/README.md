# deckard/ — Deckard's resolver scenarios against tdns-imr

[Deckard](https://gitlab.nic.cz/knot/deckard) is CZ.NIC's black-box test
harness for recursive resolvers. It runs the resolver in a Linux network
namespace, answers its queries from a scripted scenario, and checks its
answers to a scripted client. This directory lets it drive tdns-imr. The
design, and what tdns-imr still needs for more coverage, is
`docs/2026-09-28-imr-deckard-test-clock-and-switches.md`.

| File | What |
|---|---|
| `configs/tdns-imr.yaml` | Deckard's program config: how to start tdns-imr |
| `template/tdns-imr.yaml.j2` | the tdns-imr config Deckard renders per scenario |
| `template/tdns-imr-ta.j2` | the trust-anchor file, one DS or DNSKEY per line |
| `DECKARD_COMMIT` | the Deckard commit the harness is written against |
| `skip.txt` | scenarios not run, each with its reason |
| `run.sh` | selects scenarios and runs Deckard |

Unlike the other rigs here it has no fixed work root. Deckard makes a
temporary directory per scenario, renders the templates into it, and keeps it
when the scenario fails.

## Requirements

- **Linux, with unprivileged user namespaces.** Debian 12 allows them by
  default. On Ubuntu 24.04, set
  `sysctl kernel.apparmor_restrict_unprivileged_userns=0`. Deckard does not
  run on macOS.
- **Deckard at `DECKARD_COMMIT`:**

  ```sh
  git clone https://gitlab.nic.cz/knot/deckard.git
  git -C deckard checkout "$(cat DECKARD_COMMIT)"
  ```

- **Deckard's Python modules, faketime and dumpcap.** On Debian 12:

  ```sh
  apt-get install --no-install-recommends python3 python3-venv python3-pip \
      python3-dnspython python3-jinja2 python3-yaml python3-augeas \
      python3-pytest python3-pytest-xdist python3-pytest-forked \
      python3-pyroute2 python3-dpkt faketime libfaketime wireshark-common \
      augeas-lenses git
  python3 -m venv --system-site-packages ~/deckard-venv
  ~/deckard-venv/bin/pip install lief          # not packaged in Debian 12
  ```

- **A tdns-imr binary for Linux.** Without `algs.list` the build links only the
  algorithms every tdns binary has, and needs no C libraries. So it can be
  cross-compiled on a Mac:

  ```sh
  cd cmdv2/imr            # in a scratch tree: the build deletes algs.list
  rm algs.list && make version
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o tdns-imr.linux-amd64 .
  ```

## Running

```sh
source ~/deckard-venv/bin/activate
DECKARD=~/deckard TDNS_IMR=/path/to/tdns-imr ./run.sh
```

- `SET` chooses the scenarios. Every set is taken from Deckard's
  `sets/resolver` minus `skip.txt`:
  - `SET=clock-free` (the default): scenarios with no trust anchor and no
    TIME_PASSES, so they need no fake clock;
  - `SET=all`: everything;
  - `SET=<name>.rpl`: one scenario.
- Anything after the environment goes to pytest: `-k iter_cname`, `-x`,
  `-n 2` for parallel runs.
- Don't pass `--retries`: Deckard at this commit compares it as a string and
  fails.
- A failed scenario leaves its working directory, which Deckard names in the
  log (`inspect working directory /tmp/tmpdeckard...`). In it:
  - `tdns-imr/`: the rendered config, `tdns-imr.log` and `server.log`;
  - a pcap of the whole exchange.

## What tdns-imr needs first

Deckard starts the resolver, waits up to 5 s for it to accept TCP on port 53,
and only then starts the scenario's servers. tdns-imr primes at start-up and
opens its listeners only once priming succeeds, so without the priming switch
(S4 in the design) it never becomes ready, and every scenario fails at
start-up.

## Results

See `RESULTS.md` for the recorded runs.
