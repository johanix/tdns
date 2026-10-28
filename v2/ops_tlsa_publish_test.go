package tdns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tlsaTestCertPEM is a self-signed certificate with a key of its own.
func tlsaTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.example."},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Publishing a TLSA for a new certificate replaces the RRset: the record for
// the last certificate is gone. A certificate passes when it matches any
// record of the set, so one left beside the new would stay trusted.
func TestPublishTlsaRRReplacesTheRRset(t *testing.T) {
	zd, kdb := signalsRig(t)
	const owner = "_443._tcp.api.example."
	for i := 0; i < 2; i++ {
		if err := zd.PublishTlsaRR("api.example.", 443, tlsaTestCertPEM(t)); err != nil {
			t.Fatalf("PublishTlsaRR %d: %v", i, err)
		}
		ur := <-kdb.UpdateQ
		if len(ur.Actions) != 2 {
			t.Fatalf("publication %d sends %d actions, want the RRset delete and the record", i, len(ur.Actions))
		}
		del, rec := ur.Actions[0].Header(), ur.Actions[1]
		if del.Name != owner || del.Rrtype != dns.TypeTLSA || del.Class != dns.ClassANY {
			t.Fatalf("publication %d's first action is %v, want the delete of the TLSA RRset at %s", i, ur.Actions[0], owner)
		}
		if res := runUpdaterForResult(t, kdb, ur); res.Err != nil {
			t.Fatalf("applying publication %d: %v", i, res.Err)
		}
		served := ovServed(t, zd, owner, dns.TypeTLSA)
		if len(served) != 1 || !ovHas(served, rec) {
			t.Fatalf("after publication %d the zone serves %v at %s, want only %v", i, served, owner, rec)
		}
	}
}

// Publishing the record the set already holds, alone, sends no update: the
// signed RRset stays as it is.
func TestPublishTlsaRRLeavesAnUnchangedSet(t *testing.T) {
	zd, kdb := signalsRig(t)
	cert := tlsaTestCertPEM(t)
	if err := zd.PublishTlsaRR("api.example.", 443, cert); err != nil {
		t.Fatal(err)
	}
	if res := runUpdaterForResult(t, kdb, <-kdb.UpdateQ); res.Err != nil {
		t.Fatalf("applying the first publication: %v", res.Err)
	}
	if err := zd.PublishTlsaRR("api.example.", 443, cert); err != nil {
		t.Fatal(err)
	}
	select {
	case ur := <-kdb.UpdateQ:
		t.Errorf("publishing the record the set already holds sent an update: %v", ur.Actions)
	default:
	}
}

// The set already holding the record with its hex in upper case, as one
// read from a zone file may, is unchanged too.
func TestPublishTlsaRRLeavesASetSpelledInAnotherCase(t *testing.T) {
	zd, kdb := signalsRig(t)
	cert := tlsaTestCertPEM(t)
	if err := zd.PublishTlsaRR("api.example.", 443, cert); err != nil {
		t.Fatal(err)
	}
	ur := <-kdb.UpdateQ
	if res := runUpdaterForResult(t, kdb, ur); res.Err != nil {
		t.Fatalf("applying the first publication: %v", res.Err)
	}
	upper := dns.Copy(ur.Actions[1]).(*dns.TLSA)
	upper.Certificate = strings.ToUpper(upper.Certificate)
	if res := runUpdaterForResult(t, kdb, UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName,
		Actions: []dns.RR{tlsaDeleteRR(upper.Hdr.Name), upper}, InternalUpdate: true}); res.Err != nil {
		t.Fatalf("serving the record in upper case: %v", res.Err)
	}
	if err := zd.PublishTlsaRR("api.example.", 443, cert); err != nil {
		t.Fatal(err)
	}
	select {
	case ur := <-kdb.UpdateQ:
		t.Errorf("publishing the record the set holds in upper case sent an update: %v", ur.Actions)
	default:
	}
}

// In a zone that signs, a set served unsigned is published again, which
// signs it: an unchanged record does not keep it unsigned.
func TestPublishTlsaRRRepublishesAnUnsignedSetInASigningZone(t *testing.T) {
	zd, kdb := signalsRig(t)
	cert := tlsaTestCertPEM(t)
	if err := zd.PublishTlsaRR("api.example.", 443, cert); err != nil {
		t.Fatal(err)
	}
	if res := runUpdaterForResult(t, kdb, <-kdb.UpdateQ); res.Err != nil {
		t.Fatalf("applying the first publication: %v", res.Err)
	}
	zd.Options[OptOnlineSigning] = true
	if err := zd.PublishTlsaRR("api.example.", 443, cert); err != nil {
		t.Fatal(err)
	}
	select {
	case <-kdb.UpdateQ:
	default:
		t.Error("an unsigned set in a signing zone was left unsigned")
	}
}

// The signing flags are read under zd.mu, which a reload and SetOption
// write them under: a publication while the options change is no race.
func TestPublishTlsaRRReadsTheOptionsUnderTheLock(t *testing.T) {
	zd, kdb := signalsRig(t)
	cert := tlsaTestCertPEM(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			zd.SetOption(OptOnlineSigning, i%2 == 0)
		}
	}()
	for i := 0; i < 200; i++ {
		if err := zd.PublishTlsaRR("api.example.", 443, cert); err != nil {
			t.Fatal(err)
		}
		select {
		case <-kdb.UpdateQ:
		default:
		}
	}
	<-done
}

// A record asked for while another, asked for before it, is still queued is
// published, though the zone serves it now: the queued one would otherwise
// land after it and the record last asked for would be gone.
func TestPublishTlsaRRSendsARecordAskedForWhileAnotherIsQueued(t *testing.T) {
	zd, kdb := signalsRig(t)
	a, b := tlsaTestCertPEM(t), tlsaTestCertPEM(t)
	if err := zd.PublishTlsaRR("api.example.", 443, a); err != nil {
		t.Fatal(err)
	}
	first := <-kdb.UpdateQ
	if res := runUpdaterForResult(t, kdb, first); res.Err != nil {
		t.Fatalf("applying a: %v", res.Err)
	}
	if err := zd.PublishTlsaRR("api.example.", 443, b); err != nil {
		t.Fatal(err)
	}
	queued := <-kdb.UpdateQ // b, not yet applied
	if err := zd.PublishTlsaRR("api.example.", 443, a); err != nil {
		t.Fatal(err)
	}
	var again UpdateRequest
	select {
	case again = <-kdb.UpdateQ:
	default:
		t.Fatal("a, asked for again while b is queued, was not published")
	}
	for _, ur := range []UpdateRequest{queued, again} {
		if res := runUpdaterForResult(t, kdb, ur); res.Err != nil {
			t.Fatalf("applying: %v", res.Err)
		}
	}
	served := ovServed(t, zd, "_443._tcp.api.example.", dns.TypeTLSA)
	if len(served) != 1 || !ovHas(served, first.Actions[1]) {
		t.Errorf("the zone serves %v, want only a, the record last asked for", served)
	}
}

// Publications reach the queue in the order they were asked for: the
// publication lock is held from noting the record asked for until its
// update is queued, so a later request waits while an earlier one waits on
// a full queue.
func TestPublishTlsaRRQueuesInTheOrderAskedFor(t *testing.T) {
	zd, kdb := signalsRig(t)
	for len(kdb.UpdateQ) < cap(kdb.UpdateQ) {
		kdb.UpdateQ <- UpdateRequest{}
	}
	a, b := tlsaTestCertPEM(t), tlsaTestCertPEM(t)
	errs := make(chan error, 2)
	go func() { errs <- zd.PublishTlsaRR("api.example.", 443, a) }()
	deadline := time.Now().Add(2 * time.Second)
	for zd.tlsaPublishMu.TryLock() {
		zd.tlsaPublishMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("a publication waiting on a full queue does not hold the publication lock")
		}
		time.Sleep(time.Millisecond)
	}
	go func() { errs <- zd.PublishTlsaRR("api.example.", 443, b) }()
	for i := 0; i < cap(kdb.UpdateQ); i++ {
		<-kdb.UpdateQ
	}
	want := func(certPEM string) *dns.TLSA {
		cert, err := parseCertificate(certPEM)
		if err != nil {
			t.Fatal(err)
		}
		rr, err := NewTlsaRR("api.example.", 443, cert)
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	for _, w := range []*dns.TLSA{want(a), want(b)} {
		ur := <-kdb.UpdateQ
		if len(ur.Actions) != 2 || !core.IsDuplicate(ur.Actions[1], w) {
			t.Fatalf("queued %v, want the publication of %v next", ur.Actions, w)
		}
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// A publication asked for while a withdrawal is queued is sent, though the
// zone still serves the record: the withdrawal would otherwise land after
// it and leave no record.
func TestPublishTlsaRRSendsARecordAskedForWhileAWithdrawalIsQueued(t *testing.T) {
	zd, kdb := signalsRig(t)
	cert := tlsaTestCertPEM(t)
	if err := zd.PublishTlsaRR(zd.ZoneName, 443, cert); err != nil {
		t.Fatal(err)
	}
	if res := runUpdaterForResult(t, kdb, <-kdb.UpdateQ); res.Err != nil {
		t.Fatalf("applying the publication: %v", res.Err)
	}
	if err := zd.UnpublishTlsaRR(443); err != nil {
		t.Fatal(err)
	}
	<-kdb.UpdateQ // the withdrawal, not yet applied
	if err := zd.PublishTlsaRR(zd.ZoneName, 443, cert); err != nil {
		t.Fatal(err)
	}
	select {
	case <-kdb.UpdateQ:
	default:
		t.Error("a publication asked for while a withdrawal is queued was skipped")
	}
}
