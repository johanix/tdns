# XoT interop rig — tdns vs NSD, BIND9 and Knot

RFC 9103 XFR-over-TLS in both transfer roles, against three other
implementations, over the certificate authentication mechanisms they share.

Findings from the run this rig was built from:
`docs/2026-08-25-xot-interop-testing.md`.

## Running

```
./setup.sh          # mints the CA and five leaf certs, seeds /var/tmp/xotinterop
./run.sh start
./run.sh verify     # 10 assertions; non-zero exit on failure
./run.sh stop
```

`setup.sh -k` keeps the existing CA and certificates. Override `RIG`, `TDNS`,
`KNOT`, `NSD` or `NAMED` to run elsewhere.

Requires `tdns-auth`, `tdns-agent` and `tdns-cli` built in `cmdv2/`, plus
`nsd`, `named` and a Knot build tree.

## Layout

Everything is on 127.0.0.1, separated by port rather than by address: loopback
aliases need root, and the mechanisms under test do not care.

| Daemon | Do53 | DoT | Role |
|---|---|---|---|
| tdns-auth | 5301 | 5401 | primary for `a.xot.test` and the `neg*` zones |
| tdns-agent | 5302 | 5402 | secondary for the three `b-*` zones |
| NSD | 5303 | 5403 | secondary for `a.`, primary for `b-nsd.` |
| BIND9 | 5304 | 5404 | secondary for `a.`, primary for `b-bind.` |
| Knot | 5305 | 5405 | secondary for `a.`, primary for `b-knot.` |

Each daemon gets one Ed25519 leaf from a shared CA, carrying a DNS SAN
(`ns-<impl>.xot.test`) and the IP SAN 127.0.0.1, so both name-based and
IP-literal verification are reachable. All are issued `--client` too, so the
rig is ready for mTLS coverage without re-minting.

## What `verify` asserts

**A — tdns-auth primary → secondaries.** Each of NSD, BIND9 and Knot pulls
`a.xot.test` over XoT, PKIX-authenticated, and its zone must be identical to
what tdns serves.

**B — primaries → tdns-agent secondary.** tdns pulls one zone from each of the
three, authenticating their certificates by **SPKI pin**, and each must match
its source. (Switching those three upstreams to `tls-auth: pkix` + `ca-file:`
covers the other mechanism; both were run.)

**C — the negative zones must stay empty.** Four zones are configured to be
pulled with deliberately wrong credentials: wrong expected hostname (on NSD,
BIND9, Knot and tdns), a CA that signed nothing (tdns), and a pin matching no
certificate (Knot and tdns). Each carries a `canary` TXT record that must
never appear. Without these, a green A and B would not tell you whether any
certificate checking happened at all.

## Known behaviour worth not re-diagnosing

- **Knot as a secondary of tdns fails every second transfer.** Not a rig
  fault. Knot offers TLS 1.3 0-RTT early data on resumed connections and Go's
  TLS server rejects the extension outright. Assertion A still passes because
  the zone does arrive on the alternate attempts. Full diagnosis, including
  the ClientHello capture, in `docs/2026-08-25-xot-interop-testing.md` §5 and
  Appendix A.
- **tdns-auth publishes a serial one higher than its zone file's** after the
  file changes, by design (serial floor,
  `docs/2026-08-17-zonefile-journal-reconciliation.md` §8). Comparisons in
  `verify` are between servers, never against the file, so this does not
  disturb them.
- **tdns-agent REFUSEs ordinary queries** — it is not a nameserver
  (`v2/defaultqueryhandlers.go`). Its zones carry a `downstreams:` ACL purely
  so `verify` can AXFR them back out to compare.
- **Knot's control socket path must stay short** (`sun_path` caps near 104
  bytes), which is one reason the work root is `/var/tmp/xotinterop` and not
  something deeper.
