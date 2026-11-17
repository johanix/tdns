/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bytes"
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// rawRW is a transport's writer that kept the request (dns.RawRequester).
type rawRW struct {
	fakeRW
	wire []byte
}

func (w *rawRW) RawRequest() []byte { return w.wire }

func TestRequestWireLooksThroughWrappers(t *testing.T) {
	wire := []byte{0x12, 0x34, 0x28, 0x00}

	// Do53's chain: udpTruncate inside TsigSigningHandler, over the server's writer.
	chain := &truncatingResponseWriter{ResponseWriter: &tsigSignResponseWriter{ResponseWriter: &rawRW{wire: wire}}}
	if got := requestWire(chain); !bytes.Equal(got, wire) {
		t.Errorf("requestWire through the Do53 wrappers = %x, want %x", got, wire)
	}
	if got := requestWire(&dohResponseWriter{wire: wire}); !bytes.Equal(got, wire) {
		t.Errorf("requestWire of a DoH writer = %x, want %x", got, wire)
	}
	if got := requestWire(&doqResponseWriter{wire: wire}); !bytes.Equal(got, wire) {
		t.Errorf("requestWire of a DoQ writer = %x, want %x", got, wire)
	}
	if got := requestWire(&truncatingResponseWriter{ResponseWriter: &fakeRW{}}); got != nil {
		t.Errorf("requestWire with no writer that kept the request = %x, want nil", got)
	}
}

// A SIG(0) from a sender that compresses names, as BIND's nsupdate does, is
// verified over the request as received. Packing the parsed message again
// drops the compression, and the signature does not cover that (tdns #1028).
func TestValidateUpdateVerifiesTheRequestAsReceived(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)

	key := new(dns.KEY)
	key.Hdr = dns.RR_Header{Name: cuChild, Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600}
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = dns.ED25519
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generating the child's key: %v", err)
	}
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(), Validated: true,
	}); err != nil {
		t.Fatalf("storing the child's key: %v", err)
	}

	m := new(dns.Msg)
	m.SetUpdate(cuParent)
	m.Ns = []dns.RR{
		mustRR(t, "child.example. 3600 IN NS ns2.child.example."),
		mustRR(t, "ns2.child.example. 3600 IN A 192.0.2.2"),
	}
	m.Compress = true
	sig := new(dns.SIG)
	sig.RRSIG.Algorithm = dns.ED25519
	sig.RRSIG.KeyTag = key.KeyTag()
	sig.RRSIG.SignerName = key.Hdr.Name
	sig.RRSIG.Inception = uint32(time.Now().Add(-time.Minute).Unix())
	sig.RRSIG.Expiration = uint32(time.Now().Add(time.Hour).Unix())
	wire, err := sig.Sign(priv.(crypto.Signer), m)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	parsed := func() *dns.Msg {
		r := new(dns.Msg)
		if err := r.Unpack(wire); err != nil {
			t.Fatalf("unpacking the signed update: %v", err)
		}
		return r
	}

	var verifiedOver [][]byte
	orig := sig0Verify
	t.Cleanup(func() { sig0Verify = orig })
	sig0Verify = func(s *dns.SIG, k *dns.KEY, buf []byte) error {
		verifiedOver = append(verifiedOver, buf)
		return orig(s, k, buf)
	}

	us := &UpdateStatus{}
	if err := zd.ValidateUpdate(context.Background(), parsed(), wire, us); err != nil {
		t.Fatalf("ValidateUpdate over the request as received: %v", err)
	}
	// ValidateUpdate records the verdict; TrustUpdate acts on it.
	if us.ValidationRcode != dns.RcodeSuccess || len(us.Signers) != 1 || !us.Signers[0].Validated {
		t.Errorf("ValidationRcode %s, signers %d: want NOERROR and the one signer validated",
			dns.RcodeToString[int(us.ValidationRcode)], len(us.Signers))
	}
	if len(verifiedOver) != 1 || !bytes.Equal(verifiedOver[0], wire) {
		t.Errorf("verified over %d buffer(s), want exactly the request as received", len(verifiedOver))
	}

	// Without the request as received, the fallback packs the message again,
	// which is what failed for nsupdate.
	repacked := &UpdateStatus{}
	if err := zd.ValidateUpdate(context.Background(), parsed(), nil, repacked); err != nil {
		t.Fatalf("ValidateUpdate over a re-pack: %v", err)
	}
	if repacked.ValidationRcode == dns.RcodeSuccess || (len(repacked.Signers) == 1 && repacked.Signers[0].Validated) {
		t.Error("a compressed request verified over a re-pack; the test no longer shows the difference")
	}
}
