# TDNS Reference

Exhaustive, lookup-oriented documentation — one entry per CLI command and (over
time) per config key. This is the **reference** half of the docs; the curated
**how-to / explanation** half lives in [`../guide/`](../guide/README.md).

Where the guide teaches a task ("set up a TSIG-authenticated secondary"), the
reference is where you look up the exact flag, default, or key.

## Contents

- [`cli/`](cli/tdns-cli.md) — **generated** CLI reference: one markdown page per
  `tdns-cli` command, with flags, defaults, inherited flags, and cross-links.
  Start at [`cli/tdns-cli.md`](cli/tdns-cli.md).

For the **config reference**, the annotated sample configs are canonical — see
[`cmdv2/auth/tdns-auth.sample.yaml`](../cmdv2/auth/tdns-auth.sample.yaml) (every
key is commented). A generated config-key reference may be added later.

## Regenerating the CLI reference

`cli/` is generated from the live cobra command tree, so it never drifts from
the binary. **Do not hand-edit the files under `cli/`** — edit the command
definitions in `v2/cli/` and regenerate:

```sh
cd cmdv2/cli && make docs
# equivalently: ./tdns-cli gen-docs --dir ../../reference/cli
```

The generator (`tdns-cli gen-docs`, a hidden command) suppresses cobra's
auto-gen date footer, so output is stable: re-running produces no diff unless
the command tree actually changed. That makes it a usable CI drift check:

```sh
make docs && git diff --exit-code reference/cli
```
