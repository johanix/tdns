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
		{8, HSYNCPARAM_SERIAL, "serial"},
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

// The wire encoding, byte for byte, with the key numbers as literal bytes.
//
// This is the pin that matters. The table in
// TestHsyncparamKeyNumbersMatchTheDraft compares a constant against a literal
// in the same file, so an edit that changed both would still pass it. Here the
// numbers appear as RDATA bytes produced by Pack, and every one of the nine
// registered keys is present, so no renumbering can survive.
func TestHsyncparamWireEncoding(t *testing.T) {
	// Deliberately supplied in an order that is neither the draft's registry
	// order nor the wire order, to show Pack imposes the canonical one.
	rr := &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{
		NewHsyncparamPubkeyFlag(),
		&HSYNCPARAMSerial{Value: 7},
		&HSYNCPARAMNSmgmt{Value: HsyncNSmgmtAGENT},
		&HSYNCPARAMSuffix{Label: "ns"},
		&HSYNCPARAMServers{Servers: []string{"fox", "hare"}},
		&HSYNCPARAMFlag{code: HSYNCPARAM_PUBCDS},
		&HSYNCPARAMAuditors{Auditors: []string{"aud"}},
		&HSYNCPARAMParentSync{Value: HsyncParentSyncAgent},
		&HSYNCPARAMSigners{Signers: []string{"fox"}},
	}}

	buf := make([]byte, 256)
	n, err := rr.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	want := []byte{
		0, 0, 0, 8, 'f', 'o', 'x', ',', 'h', 'a', 'r', 'e', // 0 servers
		0, 1, 0, 3, 'f', 'o', 'x', //                          1 signers
		0, 2, 0, 3, 'a', 'u', 'd', //                          2 auditors
		0, 3, 0, 1, HsyncNSmgmtAGENT, //                       3 nsmgmt
		0, 4, 0, 1, HsyncParentSyncAgent, //                   4 parentsync
		0, 5, 0, 2, 'n', 's', //                               5 suffix
		0, 6, 0, 0, //                                         6 pubkey  (flag)
		0, 7, 0, 0, //                                         7 pubcds  (flag)
		0, 8, 0, 4, 0, 0, 0, 7, //                             8 serial
	}
	if got := buf[:n]; string(got) != string(want) {
		t.Fatalf("wire bytes\n got %v\nwant %v", got, want)
	}
	if got := rr.Len(); got != n {
		t.Errorf("Len() = %d, Pack wrote %d octets", got, n)
	}

	// Pack sorted by key number despite the scrambled input above, and Unpack
	// requires that order -- so the encoding is canonical, and every key came
	// back as itself rather than as its neighbour.
	var back HSYNCPARAM
	if _, err := back.Unpack(buf[:n]); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if got := strings.Join(back.GetServers(), ","); got != "fox,hare" {
		t.Errorf("servers survived as %q, want \"fox,hare\"", got)
	}
	if got := strings.Join(back.GetSigners(), ","); got != "fox" {
		t.Errorf("signers survived as %q, want \"fox\"", got)
	}
	if got := strings.Join(back.GetAuditors(), ","); got != "aud" {
		t.Errorf("auditors survived as %q, want \"aud\"", got)
	}
	if got := back.GetNSmgmt(); got != HsyncNSmgmtAGENT {
		t.Errorf("nsmgmt survived as %d, want %d", got, HsyncNSmgmtAGENT)
	}
	if got := back.GetParentSync(); got != HsyncParentSyncAgent {
		t.Errorf("parentsync survived as %d, want %d", got, HsyncParentSyncAgent)
	}
	if got := back.GetSuffix(); got != "ns" {
		t.Errorf("suffix survived as %q, want \"ns\"", got)
	}
	if !back.HasPubkey() || !back.HasPubcds() {
		t.Errorf("flags survived as pubkey=%v pubcds=%v, want both true",
			back.HasPubkey(), back.HasPubcds())
	}
	if got, ok := back.GetSerial(); !ok || got != 7 {
		t.Errorf("serial survived as %d (present %v), want 7", got, ok)
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

	// serial is written unquoted here; String() quotes it, so the re-parse
	// below covers the quoted form.
	const text = `example.com.	3600	IN	HSYNCPARAM	servers="fox,hare" signers="fox" auditors="audit" nsmgmt="agent" parentsync="agent" suffix="ns" pubkey pubcds serial=7`

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
	if got, ok := hp.GetSerial(); !ok || got != 7 {
		t.Errorf("serial = %d (present %v), want 7", got, ok)
	}

	// Every key must come back out, and re-parsing what we printed must give
	// the same record.
	printed := hp.String()
	for _, name := range []string{"servers=", "signers=", "auditors=", "nsmgmt=", "parentsync=", "suffix=", "pubkey", "pubcds", `serial="7"`} {
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
}

// keyN for a registered key is what code that did not know the key wrote.
// The draft has unknown keys written as keyN so that tools updated with the
// key's definition can read them, and RFC 9460 lets any SVCB key be written
// so, with the decoded value used as its wire form. So it is read here as
// that key, its value checked as that key's wire form, and written back by
// name.
func TestHsyncparamGenericFormOfRegisteredKey(t *testing.T) {
	if err := RegisterHsyncparamRR(); err != nil {
		t.Fatalf("RegisterHsyncparamRR: %v", err)
	}

	// What code from before serial was registered prints for serial=7: key 8
	// had no name there, so it went out as keyN with its bytes escaped.
	older := `key8="` + hsyncparamParamToStr([]byte{0, 0, 0, 7}) + `"`
	if older != `key8="\000\000\000\007"` {
		t.Fatalf("the escaping changed: %s", older)
	}

	for _, tc := range []struct {
		rdata string
		want  string // String() of the result
	}{
		{older, `serial="7"`},
		{`key0="fox,hare"`, `servers="fox,hare"`},
		{`key3="\002"`, `nsmgmt="agent"`},
		{`key5="ns"`, `suffix="ns"`},
		{`key6`, `pubkey`},
		{`key7=""`, `pubcds`},
		{`key4="\002"`, `key4="\002"`}, // no name for this value: stays generic
	} {
		rr, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + tc.rdata)
		if err != nil {
			t.Errorf("%s refused: %v", tc.rdata, err)
			continue
		}
		hp := rr.(*dns.PrivateRR).Data.(*HSYNCPARAM)
		if got := hp.String(); got != tc.want {
			t.Errorf("%s reads back as %s, want %s", tc.rdata, got, tc.want)
		}
		if _, ok := hp.Value[0].(*HSYNCPARAMLocal); ok {
			t.Errorf("%s was kept as an unknown key", tc.rdata)
		}
	}
	if rr, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + older); err == nil {
		if got, ok := rr.(*dns.PrivateRR).Data.(*HSYNCPARAM).GetSerial(); !ok || got != 7 {
			t.Errorf("GetSerial() = (%d, %v), want (7, true)", got, ok)
		}
	}

	// The value must be valid wire form for the key: the key's own unpack
	// decides, so a serial is four octets and a flag none.
	for _, tokens := range [][]string{
		{"key8=", `\000\000\007`}, // three octets
		{"key8=7"},                // one octet, the character '7'
		{"key8"},                  // no octets
		{"key6=x"},                // a flag with a value
		{"key3=", `\001\001`},     // nsmgmt is one octet
		{"key5=", "-ns"},          // not a DNS label
		{"key8=", `\00`},          // a broken escape
	} {
		var rr HSYNCPARAM
		if err := rr.Parse(tokens); err == nil {
			t.Errorf("%v accepted as %s", tokens, rr.String())
		}
	}

	// Leading zeros and the reserved number are not keyN spellings.
	for _, key := range []string{"key08", "key00", "key65535", "key", "key-1", "key+8"} {
		if _, ok := hsyncparamRegisteredKeyN(key); ok {
			t.Errorf("%q taken as a registered key", key)
		}
	}
}

// serial is decimal digits only, 0 to 2^32-1. Everything else is refused,
// rather than read as some number the owner did not write.
func TestHsyncparamSerialPresentationValues(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint32
	}{
		{"0", 0},
		{"7", 7},
		{"007", 7},
		{"4294967295", 4294967295},
	} {
		var s HSYNCPARAMSerial
		if err := s.parse(tc.in); err != nil {
			t.Errorf("parse(%q) refused: %v", tc.in, err)
			continue
		}
		if s.Value != tc.want {
			t.Errorf("parse(%q) = %d, want %d", tc.in, s.Value, tc.want)
		}
	}

	for _, bad := range []string{
		// empty
		"",
		// a sign
		"-1", "+7",
		// a fraction
		"7.0", "7.5",
		// hex
		"0x7", "0X1F", "1f",
		// spaces
		"7 8", " 7", "7 ",
		// above 2^32-1
		"4294967296", "18446744073709551616",
		// other spellings of a number
		"1_000", "1e3", "seven",
	} {
		var s HSYNCPARAMSerial
		if err := s.parse(bad); err == nil {
			t.Errorf("parse(%q) accepted as %d", bad, s.Value)
		}
	}

	// The same refusals through the zone-file parser, including a bare key
	// and a quoted value with a space inside.
	if err := RegisterHsyncparamRR(); err != nil {
		t.Fatalf("RegisterHsyncparamRR: %v", err)
	}
	for _, text := range []string{
		`example.com. 3600 IN HSYNCPARAM serial`,
		`example.com. 3600 IN HSYNCPARAM serial=""`,
		`example.com. 3600 IN HSYNCPARAM serial="7 8"`,
		`example.com. 3600 IN HSYNCPARAM serial=-1`,
		`example.com. 3600 IN HSYNCPARAM serial=4294967296`,
	} {
		if _, err := dns.NewRR(text); err == nil {
			t.Errorf("NewRR accepted %q", text)
		}
	}
}

// An nsmgmt or parentsync value this code does not define is kept, as an
// unknown key is, rather than failing the whole record: a later draft may
// define it, and a zone transfer must not stop over it. It is neither owner
// nor agent, so nothing acts on it, and it is written in the generic keyN
// form, which loads again as the same value. The two keys number owner and
// agent differently.
func TestHsyncparamUndefinedPolicyValuesAreKept(t *testing.T) {
	if err := RegisterHsyncparamRR(); err != nil {
		t.Fatalf("RegisterHsyncparamRR: %v", err)
	}
	for _, tc := range []struct {
		wire []byte
		text string
	}{
		{[]byte{0, 3, 0, 1, HsyncNSmgmtOWNER}, `nsmgmt="owner"`},
		{[]byte{0, 3, 0, 1, HsyncNSmgmtAGENT}, `nsmgmt="agent"`},
		{[]byte{0, 3, 0, 1, 0}, `key3="\000"`},
		{[]byte{0, 3, 0, 1, 3}, `key3="\003"`},
		{[]byte{0, 4, 0, 1, HsyncParentSyncOwner}, `parentsync="owner"`},
		{[]byte{0, 4, 0, 1, HsyncParentSyncAgent}, `parentsync="agent"`},
		{[]byte{0, 4, 0, 1, 2}, `key4="\002"`},
		{[]byte{0, 4, 0, 1, 255}, `key4="\255"`},
	} {
		var rr HSYNCPARAM
		if _, err := rr.Unpack(tc.wire); err != nil {
			t.Errorf("%v refused: %v", tc.wire, err)
			continue
		}
		if got := rr.String(); got != tc.text {
			t.Errorf("%v prints as %s, want %s", tc.wire, got, tc.text)
		}
		again, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + rr.String())
		if err != nil {
			t.Errorf("%s does not load: %v", rr.String(), err)
			continue
		}
		buf := make([]byte, 16)
		n, err := again.(*dns.PrivateRR).Data.(*HSYNCPARAM).Pack(buf)
		if err != nil || string(buf[:n]) != string(tc.wire) {
			t.Errorf("%s packs to %v (err %v), want %v", tc.text, buf[:n], err, tc.wire)
		}
	}

	// Not acted on: an undefined value is neither of the defined ones.
	var rr HSYNCPARAM
	if _, err := rr.Unpack([]byte{0, 3, 0, 1, 7, 0, 4, 0, 1, 7}); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if v := rr.GetNSmgmt(); v == HsyncNSmgmtAGENT || v == HsyncNSmgmtOWNER {
		t.Errorf("an undefined nsmgmt reads as %d", v)
	}
	if v := rr.GetParentSync(); v == HsyncParentSyncAgent || v == HsyncParentSyncOwner {
		t.Errorf("an undefined parentsync reads as %d", v)
	}

	// The named form takes names only; a number is not a name.
	for _, text := range []string{`nsmgmt="3"`, `parentsync="2"`} {
		if _, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + text); err == nil {
			t.Errorf("%s accepted", text)
		}
	}
}

// servers, signers and auditors hold HSYNC Labels: 1 to 16 characters, each
// a lowercase ASCII letter, a digit or a hyphen, so that Labels compare octet
// by octet with no case folding. A list is Labels separated by commas and
// nothing else, the same on the wire and in presentation format. Anything
// else is refused on unpack, on parse and on pack, so a list reads one way
// only and a record saved as text loads with the RDATA it had.
func TestHsyncparamListItemsAreLabels(t *testing.T) {
	if err := RegisterHsyncparamRR(); err != nil {
		t.Fatalf("RegisterHsyncparamRR: %v", err)
	}
	keys := []struct {
		code byte
		name string
		make func([]string) HSYNCPARAMKeyValue
	}{
		{0, "servers", func(l []string) HSYNCPARAMKeyValue { return &HSYNCPARAMServers{Servers: l} }},
		{1, "signers", func(l []string) HSYNCPARAMKeyValue { return &HSYNCPARAMSigners{Signers: l} }},
		{2, "auditors", func(l []string) HSYNCPARAMKeyValue { return &HSYNCPARAMAuditors{Auditors: l} }},
	}

	good := []string{
		"fox", "fox,hare", "a", "p1", "0", "a-b", "-",
		"abcdefghijklmnop", // 16 characters
		"",                 // the empty list, written as the bare key
	}
	bad := []string{
		"fox,,hare", ",fox", "fox,", // an empty item
		" fox", "fox, hare", "a b", // a space
		"Fox", "FOX", // uppercase
		"abcdefghijklmnopq", // 17 characters
		"fox_1", "a.b", "fox.example.",
		`a"b`, `a\b`, "a;b", "a\x00b", "a\xffb",
	}

	for _, k := range keys {
		for _, v := range good {
			wire := append([]byte{0, k.code, 0, byte(len(v))}, v...)
			var rr HSYNCPARAM
			if _, err := rr.Unpack(wire); err != nil {
				t.Errorf("%s %q refused on the wire: %v", k.name, v, err)
				continue
			}
			again, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + rr.String())
			if err != nil {
				t.Errorf("%s does not load: %v", rr.String(), err)
				continue
			}
			buf := make([]byte, 64)
			n, err := again.(*dns.PrivateRR).Data.(*HSYNCPARAM).Pack(buf)
			if err != nil || string(buf[:n]) != string(wire) {
				t.Errorf("%s packs to %q (err %v), want %q", rr.String(), buf[:n], err, wire)
			}
		}

		for _, v := range bad {
			wire := append([]byte{0, k.code, 0, byte(len(v))}, v...)
			var rr HSYNCPARAM
			if _, err := rr.Unpack(wire); err == nil {
				t.Errorf("%s %q accepted on the wire", k.name, v)
			}
			var parsed HSYNCPARAM
			if err := parsed.Parse([]string{k.name + "=", v}); err == nil {
				t.Errorf("%s=%q accepted in presentation format", k.name, v)
			}
			items := strings.Split(v, ",")
			out := &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{k.make(items)}}
			if _, err := out.Pack(make([]byte, 64)); err == nil {
				t.Errorf("%s %q packed", k.name, items)
			}
		}
	}
}

// An empty value reaches Parse as "key=" with no token after it for the
// value, so it must not swallow the next key's token: an empty value is the
// empty list wherever the key stands, not only last.
func TestHsyncparamEmptyValueBeforeAnotherKey(t *testing.T) {
	if err := RegisterHsyncparamRR(); err != nil {
		t.Fatalf("RegisterHsyncparamRR: %v", err)
	}
	for _, tc := range []struct {
		rdata string
		want  string // String() of the parsed record
	}{
		{`servers="" nsmgmt="agent" parentsync="agent"`, `servers nsmgmt="agent" parentsync="agent"`},
		{`servers= nsmgmt="agent" parentsync="agent"`, `servers nsmgmt="agent" parentsync="agent"`},
		{`signers="" servers="p1"`, `signers servers="p1"`},
		{`nsmgmt="agent" parentsync="agent" servers=""`, `nsmgmt="agent" parentsync="agent" servers`},
		{`servers="" signers="" auditors=""`, `servers signers auditors`},
		{`auditors="" serial=7`, `auditors serial="7"`},
		{`servers=fox signers= serial="7"`, `servers="fox" signers serial="7"`},
		{`pubkey="" servers="fox"`, `pubkey servers="fox"`},
		{`servers="" key32768="blah"`, `servers key32768="blah"`},
		// A keyN value may hold "=", so keyN= takes the next token whatever
		// it holds.
		{`key32768="nsmgmt=agent"`, `key32768="nsmgmt=agent"`},
		// servers="" pubkey reaches Parse as the same tokens as this record,
		// which String writes for the one-Label list "pubkey". It keeps that
		// reading; an empty list before a bare key is written bare.
		{`servers="pubkey"`, `servers="pubkey"`},
		{`servers pubkey`, `servers pubkey`},
	} {
		rr, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + tc.rdata)
		if err != nil {
			t.Errorf("%s does not load: %v", tc.rdata, err)
			continue
		}
		got := rr.(*dns.PrivateRR).Data.(*HSYNCPARAM).String()
		if got != tc.want {
			t.Errorf("%s reads as %s, want %s", tc.rdata, got, tc.want)
			continue
		}
		again, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + got)
		if err != nil {
			t.Errorf("%s (from %s) does not load: %v", got, tc.rdata, err)
		} else if s := again.(*dns.PrivateRR).Data.(*HSYNCPARAM).String(); s != got {
			t.Errorf("presentation is not stable:\nfirst  %s\nsecond %s", got, s)
		}
	}

	// A bad value after an empty one is refused, and the error names its key.
	// (The zone-file parser drops the reason, so this calls Parse directly.)
	for _, tc := range []struct {
		tokens []string
		want   string // in the error
	}{
		{[]string{"servers=", "nsmgmt=", "bogus"}, "hsyncparam nsmgmt:"},       // servers="" nsmgmt="bogus"
		{[]string{"signers=", "servers=", "Fox"}, `hsyncparam servers: "Fox"`}, // signers="" servers="Fox"
		{[]string{"servers=", "bogus=", "x"}, `unknown key "bogus"`},           // servers="" bogus="x"
		{[]string{"servers=", "serial=", "x"}, "hsyncparam serial:"},           // servers="" serial="x"
	} {
		var rr HSYNCPARAM
		err := rr.Parse(tc.tokens)
		if err == nil {
			t.Errorf("%v accepted", tc.tokens)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: error %q does not say %q", tc.tokens, err, tc.want)
		}
	}
}

// On the wire serial is exactly four octets; any other length is refused.
func TestHsyncparamSerialRefusesBadWireLength(t *testing.T) {
	for _, value := range [][]byte{
		{},
		{7},
		{0, 0, 7},
		{0, 0, 0, 0, 7},
		{0, 0, 0, 0, 0, 0, 0, 7},
	} {
		wire := append([]byte{0, 8, 0, byte(len(value))}, value...)
		var rr HSYNCPARAM
		if _, err := rr.Unpack(wire); err == nil {
			t.Errorf("a %d-octet serial was accepted as %v", len(value), rr.Value)
		}
	}
}

// Pack refuses a repeated key, so Parse must too: otherwise a zone file with
// one loads, and fails only at its first outgoing transfer.
func TestHsyncparamParseRefusesRepeatedKey(t *testing.T) {
	if err := RegisterHsyncparamRR(); err != nil {
		t.Fatalf("RegisterHsyncparamRR: %v", err)
	}
	for _, tc := range []struct {
		tokens  []string // as the zone-file parser hands them to Parse
		without string   // the same record minus the repeat, which loads
	}{
		{[]string{"servers=fox", "servers=hare"}, "servers=fox"},
		{[]string{"servers=fox", "signers=fox", "servers=fox"}, "servers=fox signers=fox"},
		{[]string{"pubkey", "pubkey"}, "pubkey"},
		{[]string{"serial=1", "serial=2"}, "serial=1"},
		{[]string{"serial=1", "serial=", "1"}, "serial=1"}, // serial="1"
		{[]string{"key32768=a", "key32768=b"}, "key32768=a"},
		{[]string{"serial=1", "key8=", `\000\000\000\001`}, "serial=1"}, // two spellings of key 8
		{[]string{"key6", "pubkey"}, "pubkey"},
	} {
		var rr HSYNCPARAM
		err := rr.Parse(tc.tokens)
		if err == nil {
			t.Errorf("repeated key accepted: %v", tc.tokens)
		} else if !strings.Contains(err.Error(), "repeated") {
			t.Errorf("%v: unexpected error: %v", tc.tokens, err)
		}

		// The same through the zone-file parser (which drops the reason
		// from its error, hence the control record).
		if _, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + tc.without); err != nil {
			t.Errorf("control record %q refused: %v", tc.without, err)
		}
		if _, err := dns.NewRR("example.com. 3600 IN HSYNCPARAM " + strings.Join(tc.tokens, " ")); err == nil {
			t.Errorf("NewRR accepted a repeated key: %v", tc.tokens)
		}
	}
}

// Code from before serial was registered decodes key 8 as an unknown key and
// keeps its bytes. Those bytes, written back out by such code, must read as
// the serial here; and what this code writes must survive a trip through such
// code unchanged.
func TestHsyncparamSerialPassesThroughOlderCode(t *testing.T) {
	want := []byte{0, 8, 0, 4, 0, 0, 0, 7}

	// An older writer: key 8 held as an unknown key.
	older := &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{
		&HSYNCPARAMLocal{KeyCode: 8, Data: []byte{0, 0, 0, 7}},
	}}
	buf := make([]byte, 64)
	n, err := older.Pack(buf)
	if err != nil {
		t.Fatalf("Pack of the older record: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("older writer packed %v, want %v", buf[:n], want)
	}

	var back HSYNCPARAM
	if _, err := back.Unpack(buf[:n]); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if _, ok := back.Value[0].(*HSYNCPARAMSerial); !ok {
		t.Errorf("key 8 decoded as %T, want *HSYNCPARAMSerial", back.Value[0])
	}
	if got, ok := back.GetSerial(); !ok || got != 7 {
		t.Errorf("serial = %d (present %v), want 7", got, ok)
	}

	// The other direction: this code's bytes, kept by an older reader as an
	// unknown key and packed again, come out identical.
	n, err = back.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	kept := &HSYNCPARAMLocal{KeyCode: 8}
	if err := kept.unpack(buf[4:n]); err != nil {
		t.Fatalf("unknown-key unpack: %v", err)
	}
	again := &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{kept}}
	m, err := again.Pack(buf)
	if err != nil {
		t.Fatalf("Pack of the kept record: %v", err)
	}
	if string(buf[:m]) != string(want) {
		t.Errorf("after an older reader: %v, want %v", buf[:m], want)
	}
}

// GetSerial tells an absent key from serial=0; callers read absent as 0.
func TestHsyncparamGetSerial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rr      *HSYNCPARAM
		want    uint32
		present bool
	}{
		{"absent", &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{NewHsyncparamPubkeyFlag()}}, 0, false},
		{"empty record", &HSYNCPARAM{}, 0, false},
		{"zero", &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{&HSYNCPARAMSerial{Value: 0}}}, 0, true},
		{"seven", &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{
			NewHsyncparamPubkeyFlag(), &HSYNCPARAMSerial{Value: 7},
		}}, 7, true},
		{"max", &HSYNCPARAM{Value: []HSYNCPARAMKeyValue{&HSYNCPARAMSerial{Value: 4294967295}}}, 4294967295, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.rr.GetSerial()
			if got != tc.want || ok != tc.present {
				t.Errorf("GetSerial() = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.present)
			}
			var cp HSYNCPARAM
			if err := tc.rr.Copy(&cp); err != nil {
				t.Fatalf("Copy: %v", err)
			}
			if got, ok := cp.GetSerial(); got != tc.want || ok != tc.present {
				t.Errorf("after Copy: GetSerial() = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.present)
			}
		})
	}
}
