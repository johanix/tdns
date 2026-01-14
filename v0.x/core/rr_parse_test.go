package core

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestCHUNKParseRoundTrip(t *testing.T) {
	t.Run("Manifest", func(t *testing.T) {
		// Create manifest CHUNK
		manifestHMAC := make([]byte, 32)
		if _, err := rand.Read(manifestHMAC); err != nil {
			t.Fatalf("failed to read manifest HMAC: %v", err)
		}

		manifestJSON := struct {
			ChunkCount uint16                 `json:"chunk_count"`
			ChunkSize  uint16                 `json:"chunk_size,omitempty"`
			Metadata   map[string]interface{} `json:"metadata,omitempty"`
			Payload    []byte                 `json:"payload,omitempty"`
		}{
			ChunkCount: 2,
			ChunkSize:  60000,
			Metadata: map[string]interface{}{
				"content":         "encrypted_keys",
				"distribution_id": "test123",
				"node_id":         "test.node.",
			},
			Payload: []byte("test payload"),
		}
		manifestJSONBytes, err := json.Marshal(manifestJSON)
		if err != nil {
			t.Fatalf("failed to marshal manifest JSON: %v", err)
		}

		original := &CHUNK{
			Format:     FormatJSON,
			HMACLen:    32,
			HMAC:       manifestHMAC,
			Sequence:   0,
			Total:      0, // 0 = manifest
			DataLength: uint16(len(manifestJSONBytes)),
			Data:       manifestJSONBytes,
		}

		testCHUNKRoundTrip(t, original, "CHUNK manifest")
	})

	t.Run("DataChunk", func(t *testing.T) {
		// Create data chunk CHUNK
		dataChunk := make([]byte, 100)
		if _, err := rand.Read(dataChunk); err != nil {
			t.Fatalf("failed to read data chunk: %v", err)
		}

		original := &CHUNK{
			Format:     FormatJSON,
			HMACLen:    0, // No HMAC for data chunks
			HMAC:       nil,
			Sequence:   1,
			Total:      3,
			DataLength: uint16(len(dataChunk)),
			Data:       dataChunk,
		}

		testCHUNKRoundTrip(t, original, "CHUNK data chunk")
	})
}

func testCHUNKRoundTrip(t *testing.T, original *CHUNK, name string) {
	// Get String() output
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	// Write to file (optional, for debugging)
	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}
	

	// Parse the string back
	tokens := parseCHUNKString(str)

	parsed := &CHUNK{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	// Compare
	if !compareCHUNK(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func parseCHUNKString(s string) []string {
	// String format: "Sequence Total Format HMAC Data"
	parts := strings.Fields(s)
	if len(parts) < 5 {
		return parts
	}

	// First 4 parts: Sequence, Total, Format, HMAC
	// Rest: Data (may contain spaces if JSON)
	tokens := make([]string, 5)
	tokens[0] = parts[0]                     // Sequence
	tokens[1] = parts[1]                     // Total
	tokens[2] = parts[2]                     // Format
	tokens[3] = parts[3]                     // HMAC
	tokens[4] = strings.Join(parts[4:], " ") // Data
	return tokens
}

func compareCHUNK(t *testing.T, a, b *CHUNK, name string) bool {
	if a.Format != b.Format {
		t.Errorf("%s: Format mismatch: %d != %d", name, a.Format, b.Format)
		return false
	}
	if a.HMACLen != b.HMACLen {
		t.Errorf("%s: HMACLen mismatch: %d != %d", name, a.HMACLen, b.HMACLen)
		return false
	}
	if !bytesEqual(a.HMAC, b.HMAC) {
		t.Errorf("%s: HMAC mismatch", name)
		return false
	}
	if a.Sequence != b.Sequence {
		t.Errorf("%s: Sequence mismatch: %d != %d", name, a.Sequence, b.Sequence)
		return false
	}
	if a.Total != b.Total {
		t.Errorf("%s: Total mismatch: %d != %d", name, a.Total, b.Total)
		return false
	}
	if a.DataLength != b.DataLength {
		t.Errorf("%s: DataLength mismatch: %d != %d", name, a.DataLength, b.DataLength)
		return false
	}
	if !bytesEqual(a.Data, b.Data) {
		t.Errorf("%s: Data mismatch (lengths: %d != %d)", name, len(a.Data), len(b.Data))
		return false
	}
	return true
}

func TestDSYNCParseRoundTrip(t *testing.T) {
	original := &DSYNC{
		Type:   dns.TypeA,
		Scheme: SchemeNotify,
		Port:   5353,
		Target: "example.com.",
	}

	testDSYNCRoundTrip(t, original, "DSYNC")
}

func TestNOTIFYParseRoundTrip(t *testing.T) {
	original := &NOTIFY{
		Type:   dns.TypeAAAA,
		Scheme: 1,
		Port:   53,
		Target: "ns.example.com.",
	}

	testNOTIFYRoundTrip(t, original, "NOTIFY")
}

func TestMSIGNERParseRoundTrip(t *testing.T) {
	original := &MSIGNER{
		State:  MsignerStateON,
		Method: MsignerMethodAPI,
		Target: "multisigner.example.com.",
	}

	testMSIGNERRoundTrip(t, original, "MSIGNER")
}

func TestHSYNCParseRoundTrip(t *testing.T) {
	original := &HSYNC{
		State:    HsyncStateON,
		NSmgmt:   HsyncNSmgmtAGENT,
		Sign:     HsyncSignYES,
		Identity: "identity.example.com.",
		Upstream: "upstream.example.com.",
	}

	testHSYNCRoundTrip(t, original, "HSYNC")
}

func TestHSYNC2ParseRoundTrip(t *testing.T) {
	original := &HSYNC2{
		State:    Hsync2StateON,
		Flags:    FlagNSmgmt | FlagSign, // Agent + Sign
		Identity: "identity.example.com.",
		Upstream: "upstream.example.com.",
	}

	testHSYNC2RoundTrip(t, original, "HSYNC2")
}

func TestTSYNCParseRoundTrip(t *testing.T) {
	original := &TSYNC{
		Type:       TypeTSYNC,
		Alias:      "alias.example.com.",
		Transports: "doq=30,dot=20",
		V4addr:     "192.0.2.1,192.0.2.2",
		V6addr:     "2001:db8::1,2001:db8::2",
	}

	testTSYNCRoundTrip(t, original, "TSYNC")
}

func testDSYNCRoundTrip(t *testing.T, original *DSYNC, name string) {
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}

	// String() uses tabs, but Parse() expects space-separated, so split on whitespace
	tokens := strings.Fields(str)

	parsed := &DSYNC{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	if !compareDSYNC(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func compareDSYNC(t *testing.T, a, b *DSYNC, name string) bool {
	if a.Type != b.Type {
		t.Errorf("%s: Type mismatch: %d != %d", name, a.Type, b.Type)
		return false
	}
	if a.Scheme != b.Scheme {
		t.Errorf("%s: Scheme mismatch: %d != %d", name, a.Scheme, b.Scheme)
		return false
	}
	if a.Port != b.Port {
		t.Errorf("%s: Port mismatch: %d != %d", name, a.Port, b.Port)
		return false
	}
	if a.Target != b.Target {
		t.Errorf("%s: Target mismatch: %s != %s", name, a.Target, b.Target)
		return false
	}
	return true
}

func testNOTIFYRoundTrip(t *testing.T, original *NOTIFY, name string) {
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}

	// String() uses tabs, but Parse() expects space-separated, so split on whitespace
	tokens := strings.Fields(str)

	parsed := &NOTIFY{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	if !compareNOTIFY(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func compareNOTIFY(t *testing.T, a, b *NOTIFY, name string) bool {
	if a.Type != b.Type {
		t.Errorf("%s: Type mismatch: %d != %d", name, a.Type, b.Type)
		return false
	}
	if a.Scheme != b.Scheme {
		t.Errorf("%s: Scheme mismatch: %d != %d", name, a.Scheme, b.Scheme)
		return false
	}
	if a.Port != b.Port {
		t.Errorf("%s: Port mismatch: %d != %d", name, a.Port, b.Port)
		return false
	}
	if a.Target != b.Target {
		t.Errorf("%s: Target mismatch: %s != %s", name, a.Target, b.Target)
		return false
	}
	return true
}

func testMSIGNERRoundTrip(t *testing.T, original *MSIGNER, name string) {
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}

	// String() uses tabs, but Parse() expects space-separated, so split on whitespace
	tokens := strings.Fields(str)

	parsed := &MSIGNER{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	if !compareMSIGNER(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func compareMSIGNER(t *testing.T, a, b *MSIGNER, name string) bool {
	if a.State != b.State {
		t.Errorf("%s: State mismatch: %d != %d", name, a.State, b.State)
		return false
	}
	if a.Method != b.Method {
		t.Errorf("%s: Method mismatch: %d != %d", name, a.Method, b.Method)
		return false
	}
	if a.Target != b.Target {
		t.Errorf("%s: Target mismatch: %s != %s", name, a.Target, b.Target)
		return false
	}
	return true
}

func testHSYNCRoundTrip(t *testing.T, original *HSYNC, name string) {
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}

	// String() uses formatted spacing, Parse() expects space-separated
	tokens := strings.Fields(str)

	parsed := &HSYNC{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	if !compareHSYNC(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func compareHSYNC(t *testing.T, a, b *HSYNC, name string) bool {
	if a.State != b.State {
		t.Errorf("%s: State mismatch: %d != %d", name, a.State, b.State)
		return false
	}
	if a.NSmgmt != b.NSmgmt {
		t.Errorf("%s: NSmgmt mismatch: %d != %d", name, a.NSmgmt, b.NSmgmt)
		return false
	}
	if a.Sign != b.Sign {
		t.Errorf("%s: Sign mismatch: %d != %d", name, a.Sign, b.Sign)
		return false
	}
	if a.Identity != b.Identity {
		t.Errorf("%s: Identity mismatch: %s != %s", name, a.Identity, b.Identity)
		return false
	}
	if a.Upstream != b.Upstream {
		t.Errorf("%s: Upstream mismatch: %s != %s", name, a.Upstream, b.Upstream)
		return false
	}
	return true
}

func testHSYNC2RoundTrip(t *testing.T, original *HSYNC2, name string) {
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}

	// String() format: "STATE \"flags\" IDENTITY UPSTREAM"
	// Parse expects: [STATE, flags-string, IDENTITY, UPSTREAM]
	// Need to handle quoted flags string
	tokens := parseHSYNC2String(str)

	parsed := &HSYNC2{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	if !compareHSYNC2(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func parseHSYNC2String(s string) []string {
	// String format: "STATE \"flags;flags;...\" IDENTITY UPSTREAM"
	// Need to preserve quoted flags string
	parts := make([]string, 0)
	inQuotes := false
	current := ""

	for _, r := range s {
		if r == '"' {
			if inQuotes {
				// End of quoted string
				parts = append(parts, current)
				current = ""
				inQuotes = false
			} else {
				// Start of quoted string
				inQuotes = true
			}
		} else if r == ' ' && !inQuotes {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

func compareHSYNC2(t *testing.T, a, b *HSYNC2, name string) bool {
	if a.State != b.State {
		t.Errorf("%s: State mismatch: %d != %d", name, a.State, b.State)
		return false
	}
	if a.Flags != b.Flags {
		t.Errorf("%s: Flags mismatch: %d != %d", name, a.Flags, b.Flags)
		return false
	}
	if a.Identity != b.Identity {
		t.Errorf("%s: Identity mismatch: %s != %s", name, a.Identity, b.Identity)
		return false
	}
	if a.Upstream != b.Upstream {
		t.Errorf("%s: Upstream mismatch: %s != %s", name, a.Upstream, b.Upstream)
		return false
	}
	return true
}

func testTSYNCRoundTrip(t *testing.T, original *TSYNC, name string) {
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}

	// String() format: "ALIAS \"transport=...\" \"v4=...\" \"v6=...\""
	// Parse() expects: [TYPE?, ALIAS, "transport=...", "v4=...", "v6=..."]
	// Need to handle quoted strings properly
	tokens := parseTSYNCString(str)

	parsed := &TSYNC{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	if !compareTSYNC(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func parseTSYNCString(s string) []string {
	// String format: "ALIAS \"transport=...\" \"v4=...\" \"v6=...\""
	// Parse() can handle this, but we need to preserve quoted strings
	parts := make([]string, 0)
	inQuotes := false
	current := ""

	for _, r := range s {
		if r == '"' {
			if inQuotes {
				// End of quoted string - add it
				parts = append(parts, current)
				current = ""
				inQuotes = false
			} else {
				// Start of quoted string
				inQuotes = true
			}
		} else if r == ' ' && !inQuotes {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

func compareTSYNC(t *testing.T, a, b *TSYNC, name string) bool {
	if a.Type != b.Type {
		t.Errorf("%s: Type mismatch: %d != %d", name, a.Type, b.Type)
		return false
	}
	if a.Alias != b.Alias {
		t.Errorf("%s: Alias mismatch: %s != %s", name, a.Alias, b.Alias)
		return false
	}
	if a.Transports != b.Transports {
		t.Errorf("%s: Transports mismatch: %s != %s", name, a.Transports, b.Transports)
		return false
	}
	if a.V4addr != b.V4addr {
		t.Errorf("%s: V4addr mismatch: %s != %s", name, a.V4addr, b.V4addr)
		return false
	}
	if a.V6addr != b.V6addr {
		t.Errorf("%s: V6addr mismatch: %s != %s", name, a.V6addr, b.V6addr)
		return false
	}
	return true
}

func TestDELEGParseRoundTrip(t *testing.T) {
	// DELEG is complex, so we'll do a simple test with just priority and target
	original := &DELEG{
		Priority: 1,
		Target:   "example.com.",
		Value:    []DELEGKeyValue{}, // Empty value list for simplicity
	}

	testDELEGRoundTrip(t, original, "DELEG")
}

func testDELEGRoundTrip(t *testing.T, original *DELEG, name string) {
	str := original.String()
	t.Logf("%s String() output: %s", name, str)

	filename := fmt.Sprintf("/tmp/test_%s.txt", strings.ReplaceAll(name, " ", "_"))
	if err := os.WriteFile(filename, []byte(str), 0644); err != nil {
		t.Logf("Warning: Failed to write file: %v", err)
	}

	// DELEG Parse() expects space-separated tokens
	tokens := strings.Fields(str)

	parsed := &DELEG{}
	if err := parsed.Parse(tokens); err != nil {
		t.Fatalf("%s Parse() failed: %v (tokens: %v)", name, err, tokens)
	}

	if !compareDELEG(t, original, parsed, name) {
		t.Errorf("%s: Parsed RR does not match original", name)
	}
}

func compareDELEG(t *testing.T, a, b *DELEG, name string) bool {
	if a.Priority != b.Priority {
		t.Errorf("%s: Priority mismatch: %d != %d", name, a.Priority, b.Priority)
		return false
	}
	if a.Target != b.Target {
		t.Errorf("%s: Target mismatch: %s != %s", name, a.Target, b.Target)
		return false
	}
	// Value comparison is complex, so we'll just check length for now
	if len(a.Value) != len(b.Value) {
		t.Errorf("%s: Value length mismatch: %d != %d", name, len(a.Value), len(b.Value))
		return false
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
