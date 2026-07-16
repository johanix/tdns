# tdns cmdv2 — building

The five applications under this directory share `utils/Makefile.common`.
Algorithm selection is per-app via `algs.list` + `tdns-genalgs` (not make
flags). See `guide/pq-dnssec.md`.

## Default build

```
cd cmdv2 && make
```

Builds `tdns-genalgs` first, then `tdns-auth`, `tdns-agent`, `tdns-imr`,
`tdns-cli`, and `dog`. Each app links the algorithms named in its
`algs.list`; C-backed libraries are detected at generate time and recorded
in that app's `algs-libs.mk`. The shared `algs-env.mk` caches
`ALGREPO` (path to the `dnssec-algorithms` checkout).

**First build** on a host (no `algs-env.mk` yet):

```
cd cmdv2
make -C genalgs
cd auth
../genalgs/tdns-genalgs --algrepo <path-to-dnssec-algorithms> --list algs.list --out .
cd .. && make
```

Thereafter a plain `make` regenerates as needed when an `algs.list` changes.

## Adding / enabling an algorithm

Edit the app's `algs.list` (one NAME per line). If the algorithm needs a
C library (liboqs / sqisign / qruov), install it first — see
`dnssec-algorithms/BUILDING.md` and the per-library `*-env.sh` scripts.
`make` re-runs genalgs; if a required library is missing, generation fails
loudly (no silent skip).
