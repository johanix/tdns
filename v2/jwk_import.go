/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Importing DNSSEC JWKs (draft-schlyter-dnsop-dnssec-jwk) into the
 * keystore: the single-key `keystore <class> add/import` of a .jwk file,
 * and the manifest's jwk_file entries in bulk-import and pre-load.
 *
 * Unlike a PEM bulk-import, which stores the private key without parsing
 * it, a JWK is always parsed, in the daemon: the keystore column holds
 * PKCS#8 PEM, so the key has to be rebuilt, and the draft's import rules
 * (rule 5 among them: the private key must give the public key) are only
 * worth anything if they run. That needs the algorithm, so a JWK whose
 * algorithm is not linked into this daemon is refused rather than stored
 * unchecked.
 */
package tdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/johanix/tdns/v2/algorithms"
	core "github.com/johanix/tdns/v2/core"
)

// ErrJWKKindMismatch: a JWK of one kind offered to the other store -- a
// DNSSEC key ("dnskey") to the SIG(0) keystore or a SIG(0) key ("sig0key")
// to the DNSSEC keystore. Keeping the two apart is what "sig0key" is for.
var ErrJWKKindMismatch = errors.New("JWK is for the other keystore")

// ErrJWKAlgorithmNotLinked: the JWK's algorithm has no implementation in
// this binary, so its private key can neither be checked nor stored.
var ErrJWKAlgorithmNotLinked = errors.New("JWK algorithm is not linked into this daemon")

// ErrJWKSet: a JWK Set ({"keys":[...]}) given where one key is expected.
// The import paths take one key per file; the generic "neither dnskey nor
// sig0key" would send the operator looking for a missing member.
var ErrJWKSet = errors.New("a JWK Set is not accepted")

// jwkImportTTL is the TTL given to a key RR rebuilt from a JWK, which has
// none; the same one GenerateKeypair gives a new key.
const jwkImportTTL = 3600

// nativeJWKAlgorithms are the algorithms miekg/dns implements itself, which
// tdns's algorithm registry does not list (RSASHA1 and its NSEC3 alias).
var nativeJWKAlgorithms = map[uint8]bool{
	dns.RSASHA1: true, dns.RSASHA1NSEC3SHA1: true, dns.RSASHA256: true, dns.RSASHA512: true,
	dns.ECDSAP256SHA256: true, dns.ECDSAP384SHA384: true, dns.ED25519: true,
}

func jwkAlgorithmLinked(alg uint8) bool {
	if nativeJWKAlgorithms[alg] {
		return true
	}
	_, ok := algorithms.CapsReal(alg)
	return ok
}

func storeName(wantType uint16) string {
	if wantType == dns.TypeKEY {
		return "SIG(0)"
	}
	return "DNSSEC"
}

// checkJWKKind refuses a JWK that is not of the kind wantType's store
// holds, before anything else is looked at, so the operator is told the
// mismatch rather than some later rule that happens to fail. It returns
// the parameter's algorithm when it can read one.
func checkJWKKind(data []byte, wantType uint16) (alg uint8, haveAlg bool, err error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return 0, false, fmt.Errorf("%w: not a JSON object", core.ErrJWKMalformed)
	}
	if raw, ok := top["keys"]; ok {
		var set []json.RawMessage
		if json.Unmarshal(raw, &set) == nil {
			return 0, false, fmt.Errorf("%w: the file holds a JWK Set (a top-level \"keys\" array of %d); "+
				"import takes one key per file, and bulk-import one jwk_file per key", ErrJWKSet, len(set))
		}
	}
	rawDK, hasDK := top["dnskey"]
	rawS0, hasS0 := top["sig0key"]
	switch {
	case hasDK && hasS0:
		return 0, false, core.ErrBothKeyParams
	case !hasDK && !hasS0:
		return 0, false, core.ErrNoKeyParam
	case wantType == dns.TypeKEY && hasDK:
		return 0, false, fmt.Errorf("%w: the JWK carries \"dnskey\", so it is a DNSSEC key; "+
			"the SIG(0) keystore takes only \"sig0key\" JWKs (import it with 'keystore dnssec import')", ErrJWKKindMismatch)
	case wantType == dns.TypeDNSKEY && hasS0:
		return 0, false, fmt.Errorf("%w: the JWK carries \"sig0key\", so it is a SIG(0) key; "+
			"the DNSSEC keystore takes only \"dnskey\" JWKs (import it with 'keystore sig0 import')", ErrJWKKindMismatch)
	}
	raw := rawDK
	if hasS0 {
		raw = rawS0
	}
	var p struct {
		Algorithm *uint8 `json:"algorithm"`
	}
	if json.Unmarshal(raw, &p) == nil && p.Algorithm != nil {
		return *p.Algorithm, true, nil
	}
	return 0, false, nil
}

// JWKImport is a JWK made ready for a keystore row.
type JWKImport struct {
	PrivateKeyPEM string      // PKCS#8 PEM, seed form for ML-DSA
	KeyRR         string      // DNSKEY or KEY RR text
	RR            *dns.DNSKEY // the DNSKEY, or the DNSKEY inside the KEY
}

// ImportJWK turns a private JWK into what the keystore stores, for the
// store wantType names (dns.TypeDNSKEY or dns.TypeKEY). All five of the
// draft's import rules apply, rule 5 included, and any failure rejects
// the key; so do a kind mismatch, a public-only JWK and an algorithm this
// daemon does not link.
//
// keyRR, when not empty, is the key's RR as it came with the JWK (the
// .key file of an export). It must be the RR the JWK rebuilds, and its
// text is kept, TTL included, so an export -> import round trip leaves the
// row as it was. Without one, the rebuilt RR gets jwkImportTTL.
func ImportJWK(wantType uint16, data, keyRR string) (*JWKImport, error) {
	alg, haveAlg, err := checkJWKKind([]byte(data), wantType)
	if err != nil {
		return nil, err
	}
	if haveAlg && core.HasJWKRepresentation(alg) && !jwkAlgorithmLinked(alg) {
		return nil, fmt.Errorf("%w: algorithm %d (%s) has no implementation in this daemon, which therefore "+
			"cannot check the key against its public half or sign with it", ErrJWKAlgorithmNotLinked,
			alg, dns.AlgorithmToString[alg])
	}
	d, rr, err := parseKeyJWKAs([]byte(data), wantType)
	if err != nil {
		return nil, err
	}
	if !d.Key.IsPrivate() {
		return nil, fmt.Errorf("the JWK is a public key; the keystore needs the private key")
	}
	if !jwkAlgorithmLinked(rr.Algorithm) {
		return nil, fmt.Errorf("%w: algorithm %d (%s)", ErrJWKAlgorithmNotLinked, rr.Algorithm, dns.AlgorithmToString[rr.Algorithm])
	}
	priv, err := privateKeyFromJWK(d.Key)
	if err != nil {
		return nil, err
	}
	privPEM, err := PrivateKeyToPEM(priv)
	if err != nil {
		return nil, fmt.Errorf("cannot store the JWK's private key as PKCS#8: %v", err)
	}

	rr.Hdr.Ttl = jwkImportTTL
	text := rr.String()
	if wantType == dns.TypeKEY {
		text = (&dns.KEY{DNSKEY: *rr}).String()
	}
	if strings.TrimSpace(keyRR) != "" {
		given, err := parseStoredKeyRR(keyRR, wantType)
		if err != nil {
			return nil, fmt.Errorf("public key RR given with the JWK: %v", err)
		}
		if !sameKeyRR(given, rr) {
			return nil, fmt.Errorf("the public key RR given with the JWK (%s) is not the key the JWK holds (%s)",
				given.String(), text)
		}
		rr.Hdr.Ttl = given.Hdr.Ttl
		text = strings.TrimSpace(keyRR)
		if r, err := dns.NewRR(text); err == nil {
			text = r.String()
		}
	}
	return &JWKImport{PrivateKeyPEM: privPEM, KeyRR: text, RR: rr}, nil
}

// jwkKeyCache builds the PrivateKeyCache the single-key add path takes,
// from a JWK. zone, when set, must be the key's owner, as the CLI checks
// for the other formats; for a JWK only the daemon can read the owner.
func jwkKeyCache(wantType uint16, data, keyRR, zone string) (*PrivateKeyCache, error) {
	imp, err := ImportJWK(wantType, data, keyRR)
	if err != nil {
		return nil, err
	}
	if zone != "" && !core.EqualNames(imp.RR.Hdr.Name, zone) {
		return nil, fmt.Errorf("name of zone (%s) and name of key (%s) do not match", zone, imp.RR.Hdr.Name)
	}
	return PrepareKeyCache(imp.PrivateKeyPEM, imp.KeyRR)
}

// resolveBulkJWK fills a bulk key's PEM and RR from its JWK, for the
// manifest's jwk_file entries. The rest of the bulk path then checks and
// stores the key as it does a PEM one.
func resolveBulkJWK(wantType uint16, jwk string, privPEM, keyRR *string) error {
	if jwk == "" {
		return nil
	}
	if strings.TrimSpace(*privPEM) != "" {
		return fmt.Errorf("the key carries both a JWK and a PEM private key; a manifest entry names one of jwk_file and private_file")
	}
	imp, err := ImportJWK(wantType, jwk, *keyRR)
	if err != nil {
		return fmt.Errorf("JWK: %w", err)
	}
	*privPEM, *keyRR = imp.PrivateKeyPEM, imp.KeyRR
	return nil
}
