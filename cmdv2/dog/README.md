# DOG

**DOG** is a DNS query tool: an independent Go reimplementation of *dig* (from
the BIND distribution), aiming to be as close to CLI-identical to dig as
possible. It is not a fork of dig, nor of the Rust tool of the same name.

What it adds over dig is the parts of DNS that TDNS implements: the
experimental record types (DSYNC, DELEG, HSYNC3, HSYNCPARAM, CHUNK, JWK), the
post-quantum DNSSEC algorithms — including *validating* RRSIGs made with them —
`+sigchase` chain walking, and the encrypted transports DoT, DoH and DoQ.

`dog -h` lists every `+option`. The long form, with worked examples, is
[guide/app-dog.md](../../guide/app-dog.md).

Both are kept honest by `optiondocs_test.go`, which fails if an option is
accepted without appearing in each of them, or documented without being
accepted.
