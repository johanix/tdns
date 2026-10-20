package tdns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

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
