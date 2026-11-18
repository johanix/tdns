/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

// Test helpers the resolver's tests share with tdns's root package tests. The
// root package keeps its own copies; a test package cannot import another's.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return rr
}

func rrs(t *testing.T, lines ...string) []dns.RR {
	t.Helper()
	out := make([]dns.RR, 0, len(lines))
	for _, l := range lines {
		out = append(out, mustRR(t, l))
	}
	return out
}

func mustSVCB(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse SVCB %q: %v", s, err)
	}
	return rr
}

func copyRRs(in []dns.RR) []dns.RR {
	if len(in) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(in))
	for _, rr := range in {
		out = append(out, dns.Copy(rr))
	}
	return out
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// captureWriter is a dns.ResponseWriter that records the message the responder
// wrote instead of putting it on a wire.
type captureWriter struct {
	got *dns.Msg
}

func (c *captureWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (c *captureWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4711}
}

func (c *captureWriter) WriteMsg(m *dns.Msg) error {
	c.got = m
	return nil
}

func (c *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (c *captureWriter) Close() error                { return nil }
func (c *captureWriter) TsigStatus() error           { return nil }
func (c *captureWriter) TsigTimersOnly(bool)         {}
func (c *captureWriter) Hijack()                     {}

// fakeResponseWriter captures the written message.
type fakeResponseWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error { f.msg = m; return nil }

// signingKey is a DNSKEY or a KEY (which embeds one).
type signingKey interface {
	Generate(bits int) (crypto.PrivateKey, error)
	KeyTag() uint16
}

// generateSigningKey generates k's key pair, again until its key tag is not 0.
// A random key gets tag 0 about once in 65,536 tries, and the dns library will
// not sign with such a key (RRSIG.Sign returns ErrKey, "bad key").
func generateSigningKey(k signingKey, bits int) (crypto.PrivateKey, error) {
	for {
		priv, err := k.Generate(bits)
		if err != nil || k.KeyTag() != 0 {
			return priv, err
		}
	}
}

// signerTestDnskeyCache gives one test its own process-wide DnskeyCache, which
// other tests fill.
func signerTestDnskeyCache(t *testing.T) *cache.DnskeyCacheT {
	t.Helper()
	saved := cache.DnskeyCache
	cache.DnskeyCache = cache.NewDnskeyCache()
	t.Cleanup(func() { cache.DnskeyCache = saved })
	return cache.DnskeyCache
}

type signerTestKey struct {
	dnskey *dns.DNSKEY
	priv   crypto.Signer
}

// newSignerTestKey makes an ED25519 key for zone.
func newSignerTestKey(t *testing.T, zone string, flags uint16) *signerTestKey {
	t.Helper()
	dk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := generateSigningKey(dk, 256)
	if err != nil {
		t.Fatalf("Generate(%s): %v", zone, err)
	}
	return &signerTestKey{dnskey: dk, priv: priv.(crypto.Signer)}
}

// holdSecure puts k in dkc as a validated delegation would.
func (k *signerTestKey) holdSecure(dkc *cache.DnskeyCacheT) {
	zone := k.dnskey.Header().Name
	dkc.Set(zone, k.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
		Name: zone, Keyid: k.dnskey.KeyTag(), State: cache.ValidationStateSecure,
		Dnskey: *k.dnskey, Expiration: time.Now().Add(time.Hour),
	})
}

// sign returns rrs as an RRset carrying k's signature over them.
func (k *signerTestKey) sign(t *testing.T, rrs ...dns.RR) *core.RRset {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: rrs[0].Header().Ttl},
		Algorithm:  k.dnskey.Algorithm,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix()),
		KeyTag:     k.dnskey.KeyTag(),
		SignerName: k.dnskey.Header().Name,
	}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: h.Class, RRtype: h.Rrtype, RRs: rrs, RRSIGs: []dns.RR{sig}}
}

// validatorImr is a resolver that holds a trust anchor for each of zones. sign
// signs an RRset with the named zone's key, so a test can hand it proofs that
// its own validator judges. (Root's validatorScanner, without the scanner.)
func validatorImr(t *testing.T, zones ...string) (*Imr, func(zone string, set []dns.RR) dns.RR) {
	t.Helper()
	imr := newTestImr(t)

	type zoneKey struct {
		key  *dns.DNSKEY
		priv crypto.Signer
	}
	keys := map[string]zoneKey{}
	for _, zone := range zones {
		key := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     257,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		priv, err := generateSigningKey(key, 256)
		if err != nil {
			t.Fatal(err)
		}
		imr.Cache.DnskeyCache.Set(zone, key.KeyTag(), &cache.CachedDnskeyRRset{
			Name: zone, Keyid: key.KeyTag(), State: cache.ValidationStateSecure, TrustAnchor: true,
			Dnskey: *key, Expiration: time.Now().Add(time.Hour),
		})
		keys[zone] = zoneKey{key, priv.(crypto.Signer)}
	}
	sign := func(zone string, set []dns.RR) dns.RR {
		t.Helper()
		zk := keys[zone]
		h := set[0].Header()
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
			TypeCovered: h.Rrtype,
			Algorithm:   zk.key.Algorithm,
			Labels:      uint8(dns.CountLabel(h.Name)),
			OrigTtl:     h.Ttl,
			Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
			Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
			KeyTag:      zk.key.KeyTag(),
			SignerName:  zone,
		}
		if err := sig.Sign(zk.priv, set); err != nil {
			t.Fatal(err)
		}
		return sig
	}
	return imr, sign
}

// signedSet is set followed by its RRSIG from zone's key.
func signedSet(sign func(string, []dns.RR) dns.RR, zone string, set []dns.RR) []dns.RR {
	return append(append([]dns.RR{}, set...), sign(zone, set))
}

// restoreProcessWideTuning puts back what NewImr sets for the whole process.
func restoreProcessWideTuning(t *testing.T) {
	t.Helper()
	policy, limits := cache.GetBackoffPolicy(), cache.GetTTLLimits()
	t.Cleanup(func() {
		cache.SetBackoffPolicy(policy)
		cache.SetTTLLimits(limits)
	})
}

const (
	stubFlushParent = "parent.example."
	stubFlushChild  = "kid.parent.example."
)

// testErrorSink is an ErrorSink that keeps the conditions as tdns's
// ServerErrorRegistry does: one entry per category and subtype, listed in
// that order. Its methods are nil-safe, as the registry's are.
type testErrorSink struct {
	mu   sync.Mutex
	errs map[[2]int]ServerError
}

func newTestErrorSink() *testErrorSink {
	return &testErrorSink{errs: map[[2]int]ServerError{}}
}

func (s *testErrorSink) set(cat ErrorCategory, sub ErrorSubtype, msg string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]int{int(cat), int(sub)}
	now := time.Now()
	e, ok := s.errs[k]
	if !ok {
		e = ServerError{Category: cat, Subtype: sub, FirstSeen: now}
	}
	e.Message = msg
	e.LastSeen = now
	s.errs[k] = e
}

func (s *testErrorSink) clear(cat ErrorCategory, sub ErrorSubtype) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.errs, [2]int{int(cat), int(sub)})
}

func (s *testErrorSink) SetImrForwardZoneError(msg string) {
	s.set(ErrCatConfig, ErrSubImrForwardZone, msg)
}
func (s *testErrorSink) ClearImrForwardZoneError() { s.clear(ErrCatConfig, ErrSubImrForwardZone) }
func (s *testErrorSink) SetImrForwardUpstreamError(msg string) {
	s.set(ErrCatUpstream, ErrSubImrForward, msg)
}
func (s *testErrorSink) ClearImrForwardUpstreamError() { s.clear(ErrCatUpstream, ErrSubImrForward) }
func (s *testErrorSink) SetImrForwardUpstreamConfigError(msg string) {
	s.set(ErrCatConfig, ErrSubImrForwardUpstream, msg)
}
func (s *testErrorSink) ClearImrForwardUpstreamConfigError() {
	s.clear(ErrCatConfig, ErrSubImrForwardUpstream)
}

func (s *testErrorSink) List() []ServerError {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ServerError, 0, len(s.errs))
	for _, e := range s.errs {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Subtype < out[j].Subtype
	})
	return out
}

// testCACertPEM is a self-signed CA certificate, PEM encoded, as a ca-file
// holds one. (Root's tests make theirs with CreateCA.)
func testCACertPEM(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
