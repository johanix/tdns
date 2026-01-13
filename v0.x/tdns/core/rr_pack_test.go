package core

import (
	"crypto/rand"
	"encoding/json"
	"testing"
)

// TestPackUnpackRoundTrip tests that Pack() and Unpack() are inverse operations
// This tests the binary wire format, complementing the String()/Parse() tests

func TestCHUNK2PackUnpackRoundTrip(t *testing.T) {
	t.Run("Manifest", func(t *testing.T) {
		manifestHMAC := make([]byte, 32)
		rand.Read(manifestHMAC)

		manifestJSON := struct {
			ChunkCount uint16                 `json:"chunk_count"`
			ChunkSize  uint16                 `json:"chunk_size,omitempty"`
			Metadata   map[string]interface{} `json:"metadata,omitempty"`
			Payload    []byte                 `json:"payload,omitempty"`
		}{
			ChunkCount: 2,
			ChunkSize:  60000,
			Metadata: map[string]interface{}{
				"content":        "encrypted_keys",
				"distribution_id": "test123",
			},
			Payload: []byte("test payload"),
		}
		manifestJSONBytes, _ := json.Marshal(manifestJSON)

		original := &CHUNK2{
			Format:     FormatJSON,
			HMACLen:    32,
			HMAC:       manifestHMAC,
			Sequence:   0,
			Total:      0, // 0 = manifest
			DataLength: uint16(len(manifestJSONBytes)),
			Data:       manifestJSONBytes,
		}

		testPackUnpackRoundTrip(t, original, "CHUNK2 manifest")
	})

	t.Run("DataChunk", func(t *testing.T) {
		dataChunk := make([]byte, 100)
		rand.Read(dataChunk)

		original := &CHUNK2{
			Format:     FormatJSON,
			HMACLen:    0, // No HMAC for data chunks
			HMAC:       nil,
			Sequence:   1,
			Total:      3,
			DataLength: uint16(len(dataChunk)),
			Data:       dataChunk,
		}

		testPackUnpackRoundTrip(t, original, "CHUNK2 data chunk")
	})
}


func testPackUnpackRoundTrip(t *testing.T, original *CHUNK2, name string) {
	// Pack to binary
	buf := make([]byte, 65535)
	off, err := original.Pack(buf)
	if err != nil {
		t.Fatalf("%s Pack() failed: %v", name, err)
	}

	// Unpack from binary
	parsed := &CHUNK2{}
	off2, err := parsed.Unpack(buf[:off])
	if err != nil {
		t.Fatalf("%s Unpack() failed: %v", name, err)
	}

	if off != off2 {
		t.Errorf("%s: Pack offset %d != Unpack offset %d", name, off, off2)
	}

	// Compare
	if !compareCHUNK2(t, original, parsed, name) {
		t.Errorf("%s: Pack/Unpack round-trip failed", name)
	}
}


