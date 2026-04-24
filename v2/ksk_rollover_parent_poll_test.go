package tdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func sha256DigestHex() string {
	return strings.Repeat("ab", 32)
}

func mustDS(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestObservedDSSetMatchesExpected(t *testing.T) {
	dhex := sha256DigestHex()
	exp := mustDS(t, fmt.Sprintf("child.example. 3600 IN DS 11111 8 2 %s", dhex))
	obsMatch := mustDS(t, fmt.Sprintf("child.example. 3600 IN DS 11111 8 2 %s", dhex))
	if !ObservedDSSetMatchesExpected([]dns.RR{obsMatch}, []dns.RR{exp}) {
		t.Fatal("expected match for identical DS")
	}
	wrongDig := mustDS(t, fmt.Sprintf("child.example. 3600 IN DS 11111 8 2 %s", strings.Repeat("cd", 32)))
	if ObservedDSSetMatchesExpected([]dns.RR{wrongDig}, []dns.RR{exp}) {
		t.Fatal("expected mismatch for wrong digest on managed keytag")
	}
	foreign := mustDS(t, fmt.Sprintf("child.example. 3600 IN DS 44444 8 2 %s", strings.Repeat("01", 32)))
	if !ObservedDSSetMatchesExpected([]dns.RR{obsMatch, foreign}, []dns.RR{exp}) {
		t.Fatal("foreign DS (unmanaged keytag) should be ignored")
	}
	if ObservedDSSetMatchesExpected([]dns.RR{foreign}, []dns.RR{exp}) {
		t.Fatal("missing expected DS should not match")
	}
}

func TestNormalizeParentAgentAddr(t *testing.T) {
	a, err := NormalizeParentAgentAddr("192.0.2.1")
	if err != nil || a != "192.0.2.1:53" {
		t.Fatalf("got %q %v", a, err)
	}
	b, err := NormalizeParentAgentAddr("192.0.2.1:5353")
	if err != nil || b != "192.0.2.1:5353" {
		t.Fatalf("got %q %v", b, err)
	}
	_, err = NormalizeParentAgentAddr("")
	if err == nil {
		t.Fatal("want error on empty")
	}
}
