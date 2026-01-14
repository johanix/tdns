package edns0

import (
	"testing"

	"github.com/miekg/dns"
)

// TestExtractFlagsAndEDNS0Options tests extraction of flags and EDNS0 options from a DNS message
func TestExtractFlagsAndEDNS0Options(t *testing.T) {
	t.Run("NoEDNS0", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.MsgHdr.RecursionDesired = true
		msg.MsgHdr.CheckingDisabled = false

		opts, err := ExtractFlagsAndEDNS0Options(msg)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options() failed: %v", err)
		}
		if opts == nil {
			t.Fatal("ExtractFlagsAndEDNS0Options() returned nil")
		}
		if !opts.RD {
			t.Error("RD flag should be true")
		}
		if opts.CD {
			t.Error("CD flag should be false")
		}
		if opts.DO {
			t.Error("DO flag should be false (no EDNS0)")
		}
	})

	t.Run("WithEDNS0DO", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.SetEdns0(4096, true) // DO bit set

		opts, err := ExtractFlagsAndEDNS0Options(msg)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options() failed: %v", err)
		}
		if opts == nil {
			t.Fatal("ExtractFlagsAndEDNS0Options() returned nil")
		}
		if !opts.DO {
			t.Error("DO flag should be true")
		}
	})

	t.Run("WithEROption", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.SetEdns0(4096, false)
		optRR := msg.IsEdns0()

		// Add ER option
		erOpt := &dns.EDNS0_LOCAL{
			Code: EDNS0_ER_OPTION_CODE,
			Data: []byte{3, 'e', 'r', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		}
		optRR.Option = append(optRR.Option, erOpt)

		opts, err := ExtractFlagsAndEDNS0Options(msg)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options() failed: %v", err)
		}
		if opts == nil {
			t.Fatal("ExtractFlagsAndEDNS0Options() returned nil")
		}
		if !opts.HasEROption {
			t.Error("HasEROption should be true")
		}
		if opts.ErAgentDomain != "erp.example.com." {
			t.Errorf("ErAgentDomain should be 'erp.example.com.', got %s", opts.ErAgentDomain)
		}
	})
}

// TestCreateKeyStateOption tests creation of a KeyState EDNS0 option
func TestCreateKeyStateOption(t *testing.T) {
	keyID := uint16(12345)
	keyState := uint8(KeyStateTrusted)
	extraText := "test extra text"

	opt := CreateKeyStateOption(keyID, keyState, extraText)
	if opt == nil {
		t.Fatal("CreateKeyStateOption() returned nil")
	}
	if opt.Code != EDNS0_KEYSTATE_OPTION_CODE {
		t.Errorf("CreateKeyStateOption() returned wrong code: got %d, want %d", opt.Code, EDNS0_KEYSTATE_OPTION_CODE)
	}
	if len(opt.Data) < 3 {
		t.Fatalf("CreateKeyStateOption() returned data too short: got %d bytes, want at least 3", len(opt.Data))
	}

	// Verify keyID encoding (big-endian)
	expectedKeyID := (uint16(opt.Data[0]) << 8) | uint16(opt.Data[1])
	if expectedKeyID != keyID {
		t.Errorf("CreateKeyStateOption() encoded wrong keyID: got %d, want %d", expectedKeyID, keyID)
	}

	// Verify keyState
	if opt.Data[2] != byte(keyState) {
		t.Errorf("CreateKeyStateOption() encoded wrong keyState: got %d, want %d", opt.Data[2], keyState)
	}

	// Verify extraText
	if string(opt.Data[3:]) != extraText {
		t.Errorf("CreateKeyStateOption() encoded wrong extraText: got %s, want %s", string(opt.Data[3:]), extraText)
	}
}

// TestParseKeyStateOption tests parsing of a KeyState EDNS0 option
func TestParseKeyStateOption(t *testing.T) {
	t.Run("ValidOption", func(t *testing.T) {
		keyID := uint16(12345)
		keyState := uint8(KeyStateTrusted)
		extraText := "test extra text"

		opt := CreateKeyStateOption(keyID, keyState, extraText)
		parsed, err := ParseKeyStateOption(opt)
		if err != nil {
			t.Fatalf("ParseKeyStateOption() failed: %v", err)
		}
		if parsed == nil {
			t.Fatal("ParseKeyStateOption() returned nil")
		}
		if parsed.KeyID != keyID {
			t.Errorf("ParseKeyStateOption() returned wrong KeyID: got %d, want %d", parsed.KeyID, keyID)
		}
		if parsed.KeyState != keyState {
			t.Errorf("ParseKeyStateOption() returned wrong KeyState: got %d, want %d", parsed.KeyState, keyState)
		}
		if parsed.ExtraText != extraText {
			t.Errorf("ParseKeyStateOption() returned wrong ExtraText: got %s, want %s", parsed.ExtraText, extraText)
		}
	})

	t.Run("InvalidLength", func(t *testing.T) {
		opt := &dns.EDNS0_LOCAL{
			Code: EDNS0_KEYSTATE_OPTION_CODE,
			Data: []byte{1, 2}, // Too short
		}
		parsed, err := ParseKeyStateOption(opt)
		if err == nil {
			t.Error("ParseKeyStateOption() should fail on short data")
		}
		if parsed != nil {
			t.Error("ParseKeyStateOption() should return nil on error")
		}
	})

	t.Run("RoundTrip", func(t *testing.T) {
		testCases := []struct {
			keyID     uint16
			keyState  uint8
			extraText string
		}{
			{12345, uint8(KeyStateTrusted), "test"},
			{0, uint8(KeyStateUnknown), ""},
			{65535, uint8(KeyStateInvalid), "long extra text with spaces"},
		}

		for _, tc := range testCases {
			opt := CreateKeyStateOption(tc.keyID, tc.keyState, tc.extraText)
			parsed, err := ParseKeyStateOption(opt)
			if err != nil {
				t.Fatalf("ParseKeyStateOption() failed for keyID=%d: %v", tc.keyID, err)
			}
			if parsed.KeyID != tc.keyID {
				t.Errorf("RoundTrip keyID mismatch: got %d, want %d", parsed.KeyID, tc.keyID)
			}
			if parsed.KeyState != tc.keyState {
				t.Errorf("RoundTrip keyState mismatch: got %d, want %d", parsed.KeyState, tc.keyState)
			}
			if parsed.ExtraText != tc.extraText {
				t.Errorf("RoundTrip extraText mismatch: got %q, want %q", parsed.ExtraText, tc.extraText)
			}
		}
	})
}

// TestExtractKeyStateOption tests extraction of KeyState option from OPT RR
func TestExtractKeyStateOption(t *testing.T) {
	t.Run("Present", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.SetEdns0(4096, false)
		optRR := msg.IsEdns0()

		keyStateOpt := CreateKeyStateOption(12345, uint8(KeyStateTrusted), "test")
		optRR.Option = append(optRR.Option, keyStateOpt)

		extracted, found := ExtractKeyStateOption(optRR)
		if !found {
			t.Error("ExtractKeyStateOption() should find the option")
		}
		if extracted == nil {
			t.Fatal("ExtractKeyStateOption() returned nil")
		}
		if extracted.KeyID != 12345 {
			t.Errorf("ExtractKeyStateOption() returned wrong KeyID: got %d, want 12345", extracted.KeyID)
		}
	})

	t.Run("NotPresent", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.SetEdns0(4096, false)
		optRR := msg.IsEdns0()

		extracted, found := ExtractKeyStateOption(optRR)
		if found {
			t.Error("ExtractKeyStateOption() should not find the option")
		}
		if extracted != nil {
			t.Error("ExtractKeyStateOption() should return nil when not found")
		}
	})

	t.Run("NilOPT", func(t *testing.T) {
		extracted, found := ExtractKeyStateOption(nil)
		if found {
			t.Error("ExtractKeyStateOption() should not find option in nil OPT")
		}
		if extracted != nil {
			t.Error("ExtractKeyStateOption() should return nil for nil OPT")
		}
	})
}
