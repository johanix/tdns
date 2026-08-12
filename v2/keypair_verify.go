/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Proving that a private key belongs to the public key filed with it.
 *
 * Everything else in the bulk/pre-load path checks a key's METADATA -- that the
 * DNSKEY's keytag matches the recorded keyid, that its owner matches the zone,
 * that the algorithm names agree. None of that touches the key material, so
 * none of it notices when zone A's public key is filed beside zone B's private
 * key. That combination imports cleanly, and the zone then publishes DNSKEY A
 * while signing with key B: every signature bogus, discovered by somebody
 * else's validator rather than at import time.
 *
 * The check is a signature round trip rather than a structural comparison of
 * key parameters. crypto.Signer only promises Public(), and comparing that
 * against a DNSKEY's wire encoding needs per-algorithm knowledge that miekg
 * does not export -- and would have to be extended for every registered PQ
 * algorithm. Signing something and verifying it with the published key needs no
 * such knowledge: it works for anything that can sign at all, which is exactly
 * the set of keys worth checking.
 */

package tdns

import (
	"crypto"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// keypairProbeTTL and the inception/expiration window below are arbitrary: the
// RRSIG never leaves this function. They only have to be self-consistent enough
// for Sign and Verify to agree.
const keypairProbeTTL = 3600

// VerifyKeyPairCorrespondence signs a synthetic RRset with signer and verifies
// it with pub, returning nil only if the two are halves of the same keypair.
//
// pub is the DNSKEY form of the published key. For a SIG(0) KEY RR, pass
// &keyrr.DNSKEY -- dns.KEY embeds it, and the signature maths is identical.
func VerifyKeyPairCorrespondence(signer crypto.Signer, pub *dns.DNSKEY) error {
	if signer == nil {
		return fmt.Errorf("no private key to check")
	}
	if pub == nil {
		return fmt.Errorf("no public key to check against")
	}

	owner := dns.Fqdn(pub.Header().Name)

	// Verify against a synthetic ZONE key carrying the same public material,
	// not against pub itself.
	//
	// This probe uses RRSIG.Sign/Verify, and RRSIG.Verify requires the ZONE
	// flag (dnssec.go: "if k.Flags&ZONE == 0 { return ErrKey }") -- correctly,
	// per RFC 4034 2.1.1: a DNSKEY without bit 7 MUST NOT be used to verify
	// RRSIGs covering RRsets. A SIG(0) KEY has flags 512 and no ZONE bit, so
	// handing it to RRSIG.Verify fails for every such key regardless of
	// correspondence.
	//
	// To be clear about what that is NOT: SIG(0) validation elsewhere in the
	// tree goes through SIG.Verify (sig0.go), a different method on a different
	// type, which takes a *KEY and a message buffer and has no ZONE
	// requirement. Nothing about real SIG(0) handling is affected by this; the
	// constraint belongs to the RRset-signing path this probe happens to
	// borrow.
	//
	// Borrowing it is deliberate, and the alternative was considered: a SIG(0)
	// key could be checked with SIG.Sign/SIG.Verify instead, which needs no
	// probe at all. That would be the more faithful test -- it exercises the key
	// in the mode it is actually used -- but it means building and signing a
	// whole dns.Msg, and then a second code path to maintain beside this one.
	// Signing a three-record RRset is markedly simpler, and the question being
	// asked is about key material rather than about message framing.
	//
	// So: one code path for both classes and for every algorithm that can sign
	// at all, the registered PQ ones included. The flags play no part in the
	// signature maths -- they are metadata, validated elsewhere -- so copying
	// the public key onto a ZONE-flagged DNSKEY asks exactly the question worth
	// asking: does this private key correspond to this public key material?
	//
	// If this ever needs to become a genuine "can this key do SIG(0)" check
	// rather than a correspondence check, SIG.Sign/SIG.Verify is the route.
	probe := &dns.DNSKEY{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: keypairProbeTTL},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: pub.Algorithm,
		PublicKey: pub.PublicKey,
	}

	rrset := []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: keypairProbeTTL},
		Txt: []string{"tdns keypair correspondence probe"},
	}}

	now := time.Now().UTC()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG,
			Class: dns.ClassINET, Ttl: keypairProbeTTL},
		TypeCovered: dns.TypeTXT,
		Algorithm:   probe.Algorithm,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     keypairProbeTTL,
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		Expiration:  uint32(now.Add(time.Hour).Unix()),
		KeyTag:      probe.KeyTag(),
		SignerName:  owner,
	}

	if err := sig.Sign(signer, rrset); err != nil {
		return fmt.Errorf("the private key could not sign with algorithm %s: %v",
			dns.AlgorithmToString[pub.Algorithm], err)
	}
	// The keytag reported is the REAL key's, not the probe's: that is the one
	// the operator sees in filenames, manifests and the keystore.
	if err := sig.Verify(probe, rrset); err != nil {
		return fmt.Errorf("the private key does not match the public key it is filed with "+
			"(%s keytag %d): %v", owner, pub.KeyTag(), err)
	}
	return nil
}

// VerifyStoredKeyPair is the opportunistic form used on the import path, where
// the private half is a PKCS#8 PEM string straight out of a manifest.
//
// checked=false means "this binary cannot load that algorithm", NOT "the key is
// fine". That distinction is load-bearing: BulkImport* deliberately never parses
// private keys, so that a key whose algorithm this binary does not link still
// restores correctly and pre-load stays safe to run before any zone is bound.
// Verifying opportunistically keeps that property while still catching the
// mismatch for every algorithm we CAN load -- which is all of them, on a build
// that could actually serve the zone.
func VerifyStoredKeyPair(privPEM string, pub *dns.DNSKEY) (checked bool, err error) {
	if privPEM == "" || pub == nil {
		return false, nil
	}
	signer, perr := ParsePrivateKeyPEM([]byte(privPEM))
	if perr != nil || signer == nil {
		// Logged, not swallowed. Two very different inputs land here -- a key
		// whose algorithm this binary does not link, and a .private that is
		// corrupt -- and only the first is benign. Returning a bare false for
		// both makes the second invisible until the zone fails to sign, long
		// after the import that accepted it.
		lgSigner.Warn("could not verify that a stored private key matches its public key",
			"zone", pub.Header().Name, "keytag", pub.KeyTag(),
			"algorithm", dns.AlgorithmToString[pub.Algorithm], "reason", perr,
			"consequence", "key imported unverified; if this is a corrupt key rather than "+
				"an algorithm this build does not link, it will fail at signing time")
		return false, nil
	}
	if verr := VerifyKeyPairCorrespondence(signer, pub); verr != nil {
		return true, verr
	}
	return true, nil
}
