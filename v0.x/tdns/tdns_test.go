package tdns

import (
	"net"
	"net/url"
	"testing"
)

// TestGlobalStuffValidate tests the Validate method of GlobalStuff
func TestGlobalStuffValidate(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		gs := GlobalStuff{
			Port:    53,
			Address: "127.0.0.1",
			BaseUri: "https://example.com",
		}
		if err := gs.Validate(); err != nil {
			t.Errorf("Validate() on valid GlobalStuff failed: %v", err)
		}
	})

	t.Run("InvalidPort", func(t *testing.T) {
		// Note: Port is uint16, so we can't directly test overflow at compile time
		// But we can test the validation logic with a value that would fail if we could set it
		// Since uint16 max is 65535, we'll test with max+1 conceptually
		// In practice, we'll test with a value that's just over the limit if validation checks for it
		// For now, we'll skip this test as the type system prevents the invalid value
		// and Validate() only checks if Port > 65535, which can't happen with uint16
		t.Skip("Cannot test invalid port > 65535 with uint16 type")
	})

	t.Run("InvalidAddress", func(t *testing.T) {
		gs := GlobalStuff{
			Port:    53,
			Address: "not.an.ip.address",
		}
		if err := gs.Validate(); err == nil {
			t.Error("Validate() should fail on invalid address")
		}
	})

	t.Run("ValidIPv6Address", func(t *testing.T) {
		gs := GlobalStuff{
			Port:    53,
			Address: "2001:db8::1",
		}
		if err := gs.Validate(); err != nil {
			t.Errorf("Validate() failed on valid IPv6 address: %v", err)
		}
	})

	t.Run("InvalidBaseUri", func(t *testing.T) {
		gs := GlobalStuff{
			Port:    53,
			BaseUri: "not a valid uri",
		}
		if err := gs.Validate(); err == nil {
			t.Error("Validate() should fail on invalid BaseUri")
		}
	})

	t.Run("EmptyFields", func(t *testing.T) {
		gs := GlobalStuff{
			Port: 0, // Zero is valid (not set)
		}
		if err := gs.Validate(); err != nil {
			t.Errorf("Validate() should pass with empty fields: %v", err)
		}
	})
}

// TestGlobalStuffValidateEdgeCases tests edge cases for Validate
func TestGlobalStuffValidateEdgeCases(t *testing.T) {
	t.Run("MaxValidPort", func(t *testing.T) {
		gs := GlobalStuff{
			Port: 65535,
		}
		if err := gs.Validate(); err != nil {
			t.Errorf("Validate() should pass for max valid port: %v", err)
		}
	})

	t.Run("ValidBaseUri", func(t *testing.T) {
		testURIs := []string{
			"http://example.com",
			"https://example.com:8080/path",
			"http://[2001:db8::1]:8080",
		}

		for _, uri := range testURIs {
			gs := GlobalStuff{
				BaseUri: uri,
			}
			if err := gs.Validate(); err != nil {
				t.Errorf("Validate() failed on valid URI %q: %v", uri, err)
			}
		}
	})
}

// Helper function to verify that Validate correctly uses net.ParseIP
func TestGlobalStuffValidateUsesNetParseIP(t *testing.T) {
	// Test that Validate uses the same logic as net.ParseIP
	testCases := []struct {
		address string
		valid   bool
	}{
		{"127.0.0.1", true},
		{"192.168.1.1", true},
		{"2001:db8::1", true},
		{"::1", true},
		{"not.an.ip", false},
		{"", true}, // Empty is valid (not set)
	}

	for _, tc := range testCases {
		t.Run(tc.address, func(t *testing.T) {
			gs := GlobalStuff{
				Address: tc.address,
			}
			err := gs.Validate()
			if tc.valid && err != nil {
				t.Errorf("Address %q should be valid but Validate() failed: %v", tc.address, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("Address %q should be invalid but Validate() passed", tc.address)
			}
			// Verify our expectation matches net.ParseIP
			if tc.address != "" {
				parsed := net.ParseIP(tc.address)
				expectedValid := parsed != nil
				if expectedValid != tc.valid {
					t.Logf("Note: net.ParseIP(%q) = %v, but test expects %v", tc.address, expectedValid, tc.valid)
				}
			}
		})
	}
}

// Helper function to verify that Validate correctly uses url.Parse
func TestGlobalStuffValidateUsesURLParse(t *testing.T) {
	testCases := []struct {
		baseURI string
		valid   bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"https://example.com:8080/path", true},
		{"not a uri", false},
		{"", true}, // Empty is valid (not set)
	}

	for _, tc := range testCases {
		t.Run(tc.baseURI, func(t *testing.T) {
			gs := GlobalStuff{
				BaseUri: tc.baseURI,
			}
			err := gs.Validate()
			if tc.valid && err != nil {
				t.Errorf("BaseUri %q should be valid but Validate() failed: %v", tc.baseURI, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("BaseUri %q should be invalid but Validate() passed", tc.baseURI)
			}
			// Verify our expectation matches url.Parse
			if tc.baseURI != "" {
				parsed, parseErr := url.Parse(tc.baseURI)
				expectedValid := parseErr == nil && parsed.Scheme != "" && parsed.Host != ""
				if expectedValid != tc.valid {
					t.Logf("Note: url.Parse(%q) = %v (err: %v), but test expects %v", tc.baseURI, parsed, parseErr, tc.valid)
				}
			}
		})
	}
}
