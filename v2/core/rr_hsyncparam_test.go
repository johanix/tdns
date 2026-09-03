package core

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The HSYNCPARAM key numbers are wire format: a receiver decodes the RDATA by
// them, so an implementation that disagrees with
// draft-leon-dnsop-signaling-zone-owner-intent reads every record wrong. They
// had drifted from the draft once (the roles and the policy keys were
// swapped), which nothing caught because no test named a number.
//
// This is that test. It is the reason the constants must not be renumbered or
// reordered for readability.
func TestHsyncparamKeyNumbersMatchTheDraft(t *testing.T) {
	// draft-leon-dnsop-signaling-zone-owner-intent-01, "A New Registry for
	// HSYNCPARAM Keys": roles first, then auxiliary policy.
	for _, tc := range []struct {
		want HSYNCPARAMKey
		key  HSYNCPARAMKey
		name string
	}{
		{0, HSYNCPARAM_SERVERS, "servers"},
		{1, HSYNCPARAM_SIGNERS, "signers"},
		{2, HSYNCPARAM_AUDITORS, "auditors"},
		{3, HSYNCPARAM_NSMGMT, "nsmgmt"},
		{4, HSYNCPARAM_PARENTSYNC, "parentsync"},
		{5, HSYNCPARAM_SUFFIX, "suffix"},
		{6, HSYNCPARAM_PUBKEY, "pubkey"},
		{7, HSYNCPARAM_PUBCDS, "pubcds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.key != tc.want {
				t.Errorf("key number for %s is %d, the draft assigns %d", tc.name, tc.key, tc.want)
			}
			if got := tc.key.String(); got != tc.name {
				t.Errorf("key %d renders as %q, want %q", tc.key, got, tc.name)
			}
			if got := hsyncparamStringToKey(tc.name); got != tc.want {
				t.Errorf("%q parses to key %d, want %d", tc.name, got, tc.want)
			}
		})
	}

	// 65535 is reserved and MUST NOT be assigned, which is what lets this
	// package use it as its "no such key" sentinel.
	if hsyncparam_RESERVED != 65535 {
		t.Errorf("reserved key is %d, want 65535", hsyncparam_RESERVED)
	}
	if hsyncparamKeyToStringMap[hsyncparam_RESERVED] != "" {
		t.Error("the reserved key number must not have a name")
	}
}

// The wire encoding, byte for byte, with the key numbers visible. A renumbering
// that slipped past the table above would still have to get past this.
func TestHsyncparamWireEncoding(t *testing.T) {
	rr := &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{
		&HSYNCPARAMNSmgmt{Value: HsyncNSmgmtAGENT},
		&HSYNCPARAMServers{Servers: []string{"fox", "hare"}},
		NewHsyncparamPubkeyFlag(),
	}}

	buf := make([]byte, 256)
	n, err := rr.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	want := []byte{
		0, 0, 0, 8, 'f', 'o', 'x', ',', 'h', 'a', 'r', 'e', // key 0 servers, len 8
		0, 3, 0, 1, HsyncNSmgmtAGENT, //                       key 3 nsmgmt,  len 1
		0, 6, 0, 0, //                                         key 6 pubkey,  len 0 (flag)
	}
	if got := buf[:n]; string(got) != string(want) {
		t.Fatalf("wire bytes\n got %v\nwant %v", got, want)
	}

	// Pack sorts by key number regardless of the order the values were
	// supplied in (nsmgmt was first above, servers is first on the wire), and
	// Unpack requires that order -- so the encoding is canonical.
	var back HSYNCPARAM
	if _, err := back.Unpack(buf[:n]); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if got := back.GetNSmgmt(); got != HsyncNSmgmtAGENT {
		t.Errorf("nsmgmt survived as %d, want %d", got, HsyncNSmgmtAGENT)
	}
	if got := strings.Join(back.GetServers(), ","); got != "fox,hare" {
		t.Errorf("servers survived as %q, want \"fox,hare\"", got)
	}
	if !back.HasPubkey() {
		t.Error("pubkey flag did not survive the round trip")
	}
	if back.HasPubcds() {
		t.Error("pubcds appeared out of nowhere -- key numbers are off by one somewhere")
	}
}

// Keys out of ascending order on the wire are refused rather than accepted and
// silently reordered: two encodings of one record would otherwise both be
// valid, and this RR ends up inside signed zones.
func TestHsyncparamUnpackRejectsUnorderedKeys(t *testing.T) {
	var rr HSYNCPARAM
	_, err := rr.Unpack([]byte{
		0, 3, 0, 1, HsyncNSmgmtAGENT, // key 3 first
		0, 0, 0, 3, 'f', 'o', 'x', //   key 0 second
	})
	if err == nil {
		t.Fatal("out-of-order keys were accepted")
	}
	if !strings.Contains(err.Error(), "increasing order") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Presentation round trip through the real zone-file parser, which is how
// operators actually write these records.
func TestHsyncparamPresentationRoundTrip(t *testing.T) {
	if err := RegisterHsyncparamRR(); err != nil {
		t.Fatalf("RegisterHsyncparamRR: %v", err)
	}

	const text = `example.com.	3600	IN	HSYNCPARAM	servers="fox,hare" signers="fox" auditors="audit" nsmgmt="agent" parentsync="agent" suffix="ns" pubkey pubcds`

	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	hp, ok := rr.(*dns.PrivateRR).Data.(*HSYNCPARAM)
	if !ok {
		t.Fatalf("parsed to %T, want *HSYNCPARAM", rr.(*dns.PrivateRR).Data)
	}

	if got := strings.Join(hp.GetServers(), ","); got != "fox,hare" {
		t.Errorf("servers = %q", got)
	}
	if got := strings.Join(hp.GetSigners(), ","); got != "fox" {
		t.Errorf("signers = %q", got)
	}
	if got := strings.Join(hp.GetAuditors(), ","); got != "audit" {
		t.Errorf("auditors = %q", got)
	}
	if got := hp.GetNSmgmt(); got != HsyncNSmgmtAGENT {
		t.Errorf("nsmgmt = %d", got)
	}
	if got := hp.GetParentSync(); got != HsyncParentSyncAgent {
		t.Errorf("parentsync = %d", got)
	}
	if got := hp.GetSuffix(); got != "ns" {
		t.Errorf("suffix = %q", got)
	}
	if !hp.HasPubkey() || !hp.HasPubcds() {
		t.Errorf("flags: pubkey=%v pubcds=%v, want both true", hp.HasPubkey(), hp.HasPubcds())
	}

	// Every key must come back out, and re-parsing what we printed must give
	// the same record.
	printed := hp.String()
	for _, name := range []string{"servers=", "signers=", "auditors=", "nsmgmt=", "parentsync=", "suffix=", "pubkey", "pubcds"} {
		if !strings.Contains(printed, name) {
			t.Errorf("String() lost %q: %s", name, printed)
		}
	}
	again, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + printed)
	if err != nil {
		t.Fatalf("re-parsing String() output failed: %v (output was %q)", err, printed)
	}
	if got := again.(*dns.PrivateRR).Data.(*HSYNCPARAM).String(); got != printed {
		t.Errorf("presentation is not stable:\nfirst  %q\nsecond %q", printed, got)
	}
}

// An unregistered key is preserved on read-back and written as keyN, per the
// draft's "Unknown Keys and Private Use". Acting on it is the caller's problem;
// losing it is this package's.
func TestHsyncparamUnknownKeyIsPreserved(t *testing.T) {
	// 32768 is in the Private Use range, so nothing will ever register it.
	wire := []byte{128, 0, 0, 4, 'b', 'l', 'a', 'h'}

	var rr HSYNCPARAM
	if _, err := rr.Unpack(wire); err != nil {
		t.Fatalf("Unpack of an unknown key failed: %v", err)
	}
	if len(rr.Value) != 1 {
		t.Fatalf("expected 1 value, got %d", len(rr.Value))
	}
	if got := rr.Value[0].Key(); got != 32768 {
		t.Errorf("key = %d, want 32768", got)
	}
	if got := rr.String(); got != `key32768="blah"` {
		t.Errorf("String() = %q, want `key32768=\"blah\"`", got)
	}

	buf := make([]byte, 64)
	n, err := rr.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if string(buf[:n]) != string(wire) {
		t.Errorf("re-packed %v, want %v", buf[:n], wire)
	}

	// A registered key's number may not be spelled keyN -- there is exactly
	// one presentation form per key.
	if got := hsyncparamStringToKey("key0"); got != hsyncparam_RESERVED {
		t.Errorf("key0 parsed to %d; a registered key must be written by name", got)
	}
}
