# DOG

**DOG** is a DNS query tool: an independent Go reimplementation of *dig* (from
the BIND distribution), aiming to be as close to CLI-identical to dig as
possible. It is not a fork of dig, nor of the Rust tool of the same name.

dog has no configuration file.

What dog adds over dig is support for the parts of DNS that TDNS implements and
that dig does not know about:

- the **experimental record types** TDNS defines (DSYNC, DELEG, HSYNC3,
  HSYNCPARAM, CHUNK, JWK, and the obsolete HSYNC/HSYNC2/TSYNC/MSIGNER/NOTIFY),
  usable as query types and printed in presentation format;
- the **post-quantum DNSSEC algorithms** TDNS registers (codepoints 199–214:
  ML-DSA, SLH-DSA, Falcon, MAYO, SNOVA, SQIsign, QR-UOV, CROSS), including
  actually *validating* RRSIGs made with them;
- **`+sigchase`**, a DNSSEC chain walk that reports a per-zone-cut verdict;
- **encrypted transports** — DoT, DoH and DoQ — alongside Do53 UDP and TCP.

On an error response, **DOG** reports the DNS rcode by name
(REFUSED, SERVFAIL, NOTAUTH, ...) rather than a bare numeric code --
for example, a transfer refused by a `downstreams:` ACL prints
"server returned REFUSED" instead of "rcode 5".

## dig compatibility

Arguments are case-insensitive and may appear in any order:

```console
$ dog @ns1.example.com www.example.com AAAA +dnssec +multi
```

- **`@server`** accepts `@host`, `@host:port`, `@[ipv6]`, `@[ipv6]:port`, and
  also URL forms — `dns://`, `tcp://`, `tls://`, `dot://`, `https://`, `doh://`,
  `quic://`, `doq://` — which select the transport directly.
- **The query type** is any name dog knows, including the experimental types
  above. Default is `A`.
- **`IXFR=<serial>`** requests an IXFR from that serial. `AXFR` and `IXFR` are
  Do53-only.
- **DNS classes are not supported.** There is no `IN`/`CH`/`HS` positional
  argument; queries are always class IN.

Flags: `-v`/`--verbose`, `-d`/`--debug`, `--version`, `--short`, `-p`/`--port`,
`-k`/`--trust-anchor <file>`, and `-y [algorithm:]name:secret` for TSIG
(dig-compatible; algorithm defaults to `hmac-sha256`, and TSIG works on Do53,
Do53-TCP and DoT only).

## `+options`

| Option | Effect |
|--------|--------|
| `+DNSSEC`, `+DO` | Set the DO (DNSSEC OK) bit |
| `+CD` | Set the CD (Checking Disabled) bit |
| `+COMPACT`, `+CO` | Set the CO bit (compact denial of existence) |
| `+DELEG`, `+DE` | Set the DE (Delegation Extension) EDNS bit |
| `+PRIVACY`, `+PR` | Set the PR (Privacy Requested) EDNS bit |
| `+MULTI` | Multi-line RR output |
| `+WIDTH=N` | Right margin for `+MULTI` |
| `+SHORT` | Print only the answer RDATA (same as `--short`) |
| `+SIGCHASE`, `+SIGCHA`, `+SC` | Walk and validate the DNSSEC chain |
| `+ALGCHASE`, `+ALGCHA`, `+AC` | As `+sigchase`, annotating each algorithm number with its name |
| `+TCP` | Force Do53 over TCP |
| `+TLS`, `+DOT` | DoT (default port 853) |
| `+HTTPS`, `+DOH` | DoH (default port 443) |
| `+QUIC`, `+DOQ` | DoQ (default port 853) |
| `+OPCODE=QUERY\|NOTIFY\|UPDATE` | Set the opcode (numeric 0/4/5 also accepted) |
| `+OTS`, `+OTS=opt_in\|opt_out` | EDNS(0) transport-signaling option |
| `+ER=<agent.domain>` | EDNS(0) Error Reporting, RFC 9567 |

Anything else is rejected as an unknown option. A truncated UDP response is
retried over TCP automatically.

## DNSSEC chain validation

`+sigchase` bypasses the ordinary query path: dog resolves through a recursive
resolver with DO=1, walks the delegation chain, and prints a per-link verdict of
secure, insecure, indeterminate or bogus.

```console
$ dog www.iis.se A +sigchase
$ dog www.iis.se A +algchase          # same, with alg=214 (CROSSRSDPG128SMALL)
```

Trust anchors are taken, in order of priority, from `--trust-anchor <file>`, the
IMR config file, and finally the compiled-in root KSK DS.

## Post-quantum algorithms

dog is built with `CGO_ENABLED=1` so that the C-backed implementations
(liboqs, sqisign, qruov) are linked in and RRSIGs across the full algorithm
range can actually be verified, not merely displayed.

`dog --version` prints the table of algorithms the binary supports, with their
codepoints and whether each is usable for SIG(0), DNSSEC, KSK and ZSK.

## Experimental record types

The types dog can query and print are registered by the shared `tdns/v2/core`
package; see [NEW-RRTYPES.md](../NEW-RRTYPES.md) for what each one means.
Current types are **DSYNC** (RFC 9859 generalized notifications), **DELEG**,
**HSYNC3** and **HSYNCPARAM** (multi-provider enrollment and policy), **CHUNK**
(chunked payloads), and **JWK** (RFC 7517 keys). **HSYNC**, **HSYNC2**,
**TSYNC**, **MSIGNER** and the old private **NOTIFY** type are obsolete but
still registered, so dog will still parse and print them.
