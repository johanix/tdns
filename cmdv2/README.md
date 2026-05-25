# tdns cmdv2 — building

The five applications under this directory share `utils/Makefile.common`.

## Default build (no liboqs needed)

```
cd cmdv2 && make
```

Produces `tdns-auth`, `tdns-agent`, `tdns-imr`, `tdns-cli`, and `dog`.
Pure-Go post-quantum algorithms (ML-DSA-44, SLH-DSA-128s) are wired in;
the liboqs-backed ones (Falcon-512, MAYO-1, SNOVA-24_5_4) are present
as metadata only — recognized by name but not usable for sign/verify.

## Full PQ build (`WITH_LIBOQS=1`)

To enable Falcon-512, MAYO-1, and SNOVA-24_5_4, the build host needs
liboqs installed and reachable via pkg-config.

```
# one-time per shell session — auto-detects liboqs install
. ../../dnssec-algorithms/liboqs/liboqs-env.sh

cd cmdv2 && make WITH_LIBOQS=1
```

The env script probes well-known prefixes (`/opt/local` for MacPorts,
`/opt/homebrew` for Homebrew on Apple Silicon, `/usr/pkg` for NetBSD
pkgsrc, `/usr/local`, `/usr` for Linux distro packages). Override with
`LIBOQS_PREFIX=/your/path` or set `LIBOQS_INCLUDE_DIR` +
`LIBOQS_LIB_DIR` explicitly.

If `make WITH_LIBOQS=1` is run without the env sourced, the build
fails fast with a pointer back to the env script. No silent fallback.

See `dnssec-algorithms/README.md` for per-platform liboqs install
notes (MacPorts, Homebrew, pkgsrc; Linux template still pending).

## Adding a liboqs algorithm to a binary

Each server binary has two files declaring its PQ algorithm bindings:

- `pq_algorithms_liboqs.go` — built only with `-tags liboqs`. Real
  registrations via `algs.Register`.
- `pq_algorithms_noliboqs.go` — built by default. Metadata-only via
  `algs.RegisterMetadata`.

The split keeps the default-build dependency graph free of CGO/liboqs.
`dog` and `tdns-cli` never need liboqs (they don't sign/verify with
the relevant algorithms) — they have no `_liboqs.go` file at all.
