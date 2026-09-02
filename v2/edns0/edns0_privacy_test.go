package edns0

import (
	"testing"

	"github.com/miekg/dns"
)

func queryWithPrivacy(t *testing.T, payload []byte) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(4096, false)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: EDNS0_PRIVACY_OPTION_CODE,
		Data: payload,
	})
	return m
}

// The option must survive a pack/unpack round trip: an option that only works
// in-process is not a wire signal.
func TestPrivacyOptionRoundTrip(t *testing.T) {
	for _, level := range []PrivacyLevel{PrivacyNone, PrivacyOpportunistic, PrivacyStrict} {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		if err := AddPrivacyLevelToMessage(m, level); err != nil {
			t.Fatalf("AddPrivacyLevelToMessage(%s): %v", level, err)
		}
		wire, err := m.Pack()
		if err != nil {
			t.Fatalf("Pack: %v", err)
		}
		var got dns.Msg
		if err := got.Unpack(wire); err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		msgoptions, err := ExtractFlagsAndEDNS0Options(&got)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		if !msgoptions.HasPrivacy {
			t.Errorf("level %s: option lost in round trip", level)
		}
		if msgoptions.Privacy != level {
			t.Errorf("level %s: got %s after round trip", level, msgoptions.Privacy)
		}
	}
}

// The payload is exactly one octet. Anything else is not a signal we can act
// on, and must read as absent rather than as some guessed level.
func TestPrivacyOptionRejectsWrongLength(t *testing.T) {
	for _, payload := range [][]byte{{}, {1, 2}, {0, 0, 0}} {
		m := queryWithPrivacy(t, payload)
		if _, found := ExtractPrivacyPayload(m.IsEdns0()); found {
			t.Errorf("payload %v: reported present, want absent", payload)
		}
		msgoptions, err := ExtractFlagsAndEDNS0Options(m)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		if msgoptions.HasPrivacy || msgoptions.Privacy != PrivacyNone {
			t.Errorf("payload %v: got HasPrivacy=%v Privacy=%s, want absent/none",
				payload, msgoptions.HasPrivacy, msgoptions.Privacy)
		}
	}
}

// A level we do not know must not be promoted to "at least strict": that would
// hand an unknown future value the power to SERVFAIL queries.
func TestPrivacyLevelUnknownIsNoOpinion(t *testing.T) {
	m := queryWithPrivacy(t, []byte{7})
	level, found := ExtractPrivacyLevel(m.IsEdns0())
	if !found {
		t.Fatal("unknown level: option reported absent, want present")
	}
	if level != PrivacyNone {
		t.Errorf("unknown level: got %s, want %s", level, PrivacyNone)
	}
	// The response direction keeps the raw value, since it is diagnostic.
	status, found := ExtractPrivacyStatus(m.IsEdns0())
	if !found || uint8(status) != 7 {
		t.Errorf("unknown status: got %d/%v, want raw 7 present", uint8(status), found)
	}
}

// Two PRIVACY options on one OPT would be a contradiction the receiver cannot
// resolve, so adding one replaces any that is already there.
func TestAddPrivacyOptionReplaces(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if err := AddPrivacyLevelToMessage(m, PrivacyOpportunistic); err != nil {
		t.Fatalf("AddPrivacyLevelToMessage: %v", err)
	}
	if err := AddPrivacyLevelToMessage(m, PrivacyStrict); err != nil {
		t.Fatalf("AddPrivacyLevelToMessage: %v", err)
	}
	opt := m.IsEdns0()
	count := 0
	for _, o := range opt.Option {
		if lo, ok := o.(*dns.EDNS0_LOCAL); ok && lo.Code == EDNS0_PRIVACY_OPTION_CODE {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d PRIVACY options, want 1", count)
	}
	if level, _ := ExtractPrivacyLevel(opt); level != PrivacyStrict {
		t.Errorf("got %s, want %s", level, PrivacyStrict)
	}
}

func TestParsePrivacyLevel(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want PrivacyLevel
	}{
		{"0", PrivacyNone}, {"none", PrivacyNone},
		{"1", PrivacyOpportunistic}, {"opportunistic", PrivacyOpportunistic}, {"OPP", PrivacyOpportunistic},
		{"2", PrivacyStrict}, {"Strict", PrivacyStrict}, {" strict ", PrivacyStrict},
	} {
		got, err := ParsePrivacyLevel(tc.in)
		if err != nil {
			t.Errorf("ParsePrivacyLevel(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParsePrivacyLevel(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
	if _, err := ParsePrivacyLevel("maybe"); err == nil {
		t.Error("ParsePrivacyLevel(\"maybe\"): want error, got nil")
	}
}

// The status values are a separate vocabulary from the levels; "from cache" in
// particular has no counterpart on the query side.
func TestPrivacyStatusRoundTrip(t *testing.T) {
	for _, status := range []PrivacyStatus{PrivacyCleartext, PrivacyEncrypted, PrivacyCached} {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		m.Response = true
		if err := AddPrivacyStatusToMessage(m, status); err != nil {
			t.Fatalf("AddPrivacyStatusToMessage(%s): %v", status, err)
		}
		got, found := ExtractPrivacyStatus(m.IsEdns0())
		if !found || got != status {
			t.Errorf("status %s: got %s/%v", status, got, found)
		}
	}
}

// A malformed PRIVACY option must not mask a well-formed one behind it. This
// is the direction that matters: reading a valid strict request as "no
// request" lets the resolver use cleartext for a client that forbade it, so
// the scan skips what it cannot parse rather than stopping there.
func TestPrivacyOptionMalformedDoesNotMaskValid(t *testing.T) {
	m := queryWithPrivacy(t, []byte{}) // malformed: OPTION-LENGTH 0
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: EDNS0_PRIVACY_OPTION_CODE,
		Data: []byte{uint8(PrivacyStrict)},
	})

	level, found := ExtractPrivacyLevel(opt)
	if !found || level != PrivacyStrict {
		t.Errorf("got %s/%v, want %s present", level, found, PrivacyStrict)
	}

	msgoptions, err := ExtractFlagsAndEDNS0Options(m)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	if !msgoptions.HasPrivacy || msgoptions.Privacy != PrivacyStrict {
		t.Errorf("got HasPrivacy=%v Privacy=%s, want true/%s",
			msgoptions.HasPrivacy, msgoptions.Privacy, PrivacyStrict)
	}
}
