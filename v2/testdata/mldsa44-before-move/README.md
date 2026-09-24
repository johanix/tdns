# ML-DSA-44 key minted before the move

A throwaway test key. `TestMLDSA44KeyMintedBeforeTheMove` checks that a key
made, and data signed, by the package tdns used before ML-DSA-44 was built in
still work with `v2/algorithms/mldsa44`.

Made with `github.com/johanix/dnssec-algorithms/mldsa44` at `4d74f08`
(module version `v0.0.0-20260916121050-4d74f086374b`), miekg/dns replaced by
`github.com/johanix/dns v1.1.72-johanix.2`, by the program in
`mkfixture.go.txt`:

- `private.pem`: the private key as PKCS#8 PEM, as the keystore stores it.
- `private.bind`: the same key in BIND private-key format.
- `dnskey.txt`: its DNSKEY (algorithm 18, key tag 16984).
- `signed.txt`: a TXT record and its RRSIG by that key.
