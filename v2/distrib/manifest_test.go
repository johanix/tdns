package distrib

import (
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
)

func TestDistributionState(t *testing.T) {
	// Verify state constants have expected values
	tests := []struct {
		state    DistributionState
		expected string
	}{
		{StatePending, "pending"},
		{StateConfirmed, "confirmed"},
		{StateFailed, "failed"},
		{StateExpired, "expired"},
	}

	for _, tt := range tests {
		if string(tt.state) != tt.expected {
			t.Errorf("State %v should be %q, got %q", tt.state, tt.expected, string(tt.state))
		}
	}
}

func TestOperationType(t *testing.T) {
	// Verify operation type constants
	if OperationPing != "ping" {
		t.Errorf("OperationPing should be 'ping', got %q", OperationPing)
	}
	if OperationCustom != "custom" {
		t.Errorf("OperationCustom should be 'custom', got %q", OperationCustom)
	}
}

func TestOperationEntry(t *testing.T) {
	entry := OperationEntry{
		Operation: "test_op",
		TargetID:  "target-123",
		Payload:   []byte("test payload"),
		Metadata: map[string]interface{}{
			"key": "value",
		},
	}

	if entry.Operation != "test_op" {
		t.Errorf("Operation should be 'test_op', got %q", entry.Operation)
	}
	if entry.TargetID != "target-123" {
		t.Errorf("TargetID should be 'target-123', got %q", entry.TargetID)
	}
	if string(entry.Payload) != "test payload" {
		t.Errorf("Payload should be 'test payload', got %q", string(entry.Payload))
	}
	if entry.Metadata["key"] != "value" {
		t.Errorf("Metadata['key'] should be 'value', got %v", entry.Metadata["key"])
	}
}

func TestDistributionRecord(t *testing.T) {
	now := time.Now()
	record := DistributionRecord{
		ID:             "rec-123",
		DistributionID: "dist-456",
		SenderID:       "sender-1",
		ReceiverID:     "receiver-2",
		Operation:      "ping",
		ContentType:    "application/json",
		Status:         StatePending,
		CreatedAt:      now,
	}

	if record.Status != StatePending {
		t.Errorf("Status should be StatePending, got %v", record.Status)
	}
	if record.ConfirmedAt != nil {
		t.Error("ConfirmedAt should be nil for pending record")
	}
}

func TestConfirmationStatus(t *testing.T) {
	// Verify confirmation status constants
	tests := []struct {
		status   ConfirmationStatus
		expected string
	}{
		{ConfirmationSuccess, "success"},
		{ConfirmationPartial, "partial"},
		{ConfirmationFailed, "failed"},
		{ConfirmationRejected, "rejected"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("Status %v should be %q, got %q", tt.status, tt.expected, string(tt.status))
		}
	}
}

func TestDistributionFilter(t *testing.T) {
	pending := StatePending
	filter := DistributionFilter{
		SenderID:   "sender-1",
		ReceiverID: "receiver-2",
		Status:     &pending,
		Operation:  "ping",
		Limit:      10,
		Offset:     0,
	}

	if *filter.Status != StatePending {
		t.Errorf("Filter status should be StatePending, got %v", *filter.Status)
	}
	if filter.Limit != 10 {
		t.Errorf("Filter limit should be 10, got %d", filter.Limit)
	}
}

// Manifest operation tests

func TestCreateManifestMetadata(t *testing.T) {
	extra := map[string]interface{}{
		"zone_count": 5,
		"key_count":  10,
	}

	metadata := CreateManifestMetadata("key_operations", "dist-123", "node-456", extra)

	if metadata["content"] != "key_operations" {
		t.Errorf("content should be 'key_operations', got %v", metadata["content"])
	}
	if metadata["distribution_id"] != "dist-123" {
		t.Errorf("distribution_id should be 'dist-123', got %v", metadata["distribution_id"])
	}
	if metadata["receiver_id"] != "node-456" {
		t.Errorf("receiver_id should be 'node-456', got %v", metadata["receiver_id"])
	}
	if _, ok := metadata["timestamp"]; !ok {
		t.Error("timestamp should be set")
	}
	if metadata["zone_count"] != 5 {
		t.Errorf("zone_count should be 5, got %v", metadata["zone_count"])
	}
	if metadata["key_count"] != 10 {
		t.Errorf("key_count should be 10, got %v", metadata["key_count"])
	}
}

func TestShouldIncludePayloadInline(t *testing.T) {
	tests := []struct {
		payloadSize  int
		totalSize    int
		expectInline bool
	}{
		{100, 300, true},   // Small payload, small total
		{500, 800, true},   // At threshold
		{501, 800, false},  // Just over threshold
		{100, 1200, false}, // Small payload but large total
		{600, 1000, false}, // Large payload
	}

	for _, tt := range tests {
		result := ShouldIncludePayloadInline(tt.payloadSize, tt.totalSize)
		if result != tt.expectInline {
			t.Errorf("ShouldIncludePayloadInline(%d, %d) = %v, expected %v",
				tt.payloadSize, tt.totalSize, result, tt.expectInline)
		}
	}
}

func TestEstimateManifestSize(t *testing.T) {
	metadata := map[string]interface{}{
		"content":         "test",
		"distribution_id": "dist-123",
	}
	payload := []byte("test payload")

	size := EstimateManifestSize(metadata, payload)

	// Size should be reasonable (header overhead + JSON)
	if size < 50 || size > 500 {
		t.Errorf("EstimateManifestSize returned unexpected size: %d", size)
	}
}

func TestSplitIntoCHUNKs(t *testing.T) {
	// Create 150 bytes of test data
	data := make([]byte, 150)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Split into 50-byte chunks
	chunks := SplitIntoCHUNKs(data, 50, core.FormatJSON)

	if len(chunks) != 3 {
		t.Fatalf("Expected 3 chunks, got %d", len(chunks))
	}

	// Verify chunk properties
	for i, chunk := range chunks {
		if chunk.Sequence != uint16(i+1) {
			t.Errorf("Chunk %d: expected sequence %d, got %d", i, i+1, chunk.Sequence)
		}
		if chunk.Total != 3 {
			t.Errorf("Chunk %d: expected total 3, got %d", i, chunk.Total)
		}
		if chunk.Format != core.FormatJSON {
			t.Errorf("Chunk %d: expected format %d, got %d", i, core.FormatJSON, chunk.Format)
		}
	}

	// First two chunks should be 50 bytes, last should be remaining
	if len(chunks[0].Data) != 50 {
		t.Errorf("First chunk should have 50 bytes, got %d", len(chunks[0].Data))
	}
	if len(chunks[1].Data) != 50 {
		t.Errorf("Second chunk should have 50 bytes, got %d", len(chunks[1].Data))
	}
	if len(chunks[2].Data) != 50 {
		t.Errorf("Third chunk should have 50 bytes, got %d", len(chunks[2].Data))
	}
}

func TestSplitIntoCHUNKsDefaultSize(t *testing.T) {
	data := []byte("small data")
	chunks := SplitIntoCHUNKs(data, 0, core.FormatJSON) // 0 = use default

	if len(chunks) != 1 {
		t.Errorf("Expected 1 chunk for small data, got %d", len(chunks))
	}
}

func TestReassembleCHUNKs(t *testing.T) {
	// Create test data
	data := make([]byte, 150)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Split and reassemble
	chunks := SplitIntoCHUNKs(data, 50, core.FormatJSON)
	reassembled, err := ReassembleCHUNKs(chunks)

	if err != nil {
		t.Fatalf("ReassembleCHUNKs failed: %v", err)
	}

	if len(reassembled) != len(data) {
		t.Errorf("Reassembled length %d doesn't match original %d", len(reassembled), len(data))
	}

	for i := range data {
		if reassembled[i] != data[i] {
			t.Errorf("Byte %d mismatch: expected %d, got %d", i, data[i], reassembled[i])
			break
		}
	}
}

func TestReassembleCHUNKsErrors(t *testing.T) {
	// Empty chunks
	_, err := ReassembleCHUNKs(nil)
	if err == nil {
		t.Error("Expected error for nil chunks")
	}

	_, err = ReassembleCHUNKs([]*core.CHUNK{})
	if err == nil {
		t.Error("Expected error for empty chunks")
	}

	// Mismatched total
	chunks := []*core.CHUNK{
		{Sequence: 1, Total: 2, Data: []byte("a")},
	}
	_, err = ReassembleCHUNKs(chunks)
	if err == nil {
		t.Error("Expected error for mismatched chunk count")
	}
}
