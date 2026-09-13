/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// tdns publishes JWK records itself (ops_jwk.go): a multi-provider agent's
// long-term encryption key, which its peers look up before they will talk to
// it. The query path has to answer for them. JWK used to be missing from the
// qtype sets, so a JWK query fell through to the REFUSED catch-all and every
// identity served by tdns-auth was undiscoverable.
func TestQueryResponderAnswersJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, _, err := core.EncodePublicKeyToJWK(&key.PublicKey, "")
	if err != nil {
		t.Fatalf("EncodePublicKeyToJWK: %v", err)
	}
	zd := testSnapshotZone(t, "example.", fmt.Sprintf(`example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 10.0.0.1
dns.agent.example. 3600 IN JWK %q
`, jwk))
	kdb := newTestKeyDB(t)

	const qname = "dns.agent.example."
	req := new(dns.Msg)
	req.SetQuestion(qname, core.TypeJWK)
	req.SetEdns0(4096, false)
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	rw := &fakeRW{}
	if err := zd.QueryResponder(context.Background(), rw, req, qname, core.TypeJWK, msgo, kdb, nil); err != nil {
		t.Fatalf("QueryResponder: %v", err)
	}
	m := rw.written
	if m == nil {
		t.Fatal("no response written")
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != core.TypeJWK {
		t.Fatalf("answer = %v, want the one JWK record", m.Answer)
	}
}
