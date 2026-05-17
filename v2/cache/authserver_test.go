/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"fmt"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// TestAddrXportKeying_PerTransportIsolation verifies that recording a failure
// against one transport does not affect availability of the same address on
// a different transport.
func TestAddrXportKeying_PerTransportIsolation(t *testing.T) {
	as := NewAuthServer("ns1.example.")
	as.SetAddrs([]string{"127.0.0.1:53"})

	if !as.IsAddrXportAvailable("127.0.0.1:53", core.TransportDo53) {
		t.Fatal("fresh tuple should be available")
	}

	as.RecordAddressFailure("127.0.0.1:53", core.TransportDoT, fmt.Errorf("tls handshake failed"))

	if as.IsAddrXportAvailable("127.0.0.1:53", core.TransportDoT) {
		t.Error("(addr, DoT) should be in backoff after a failure")
	}
	if !as.IsAddrXportAvailable("127.0.0.1:53", core.TransportDo53) {
		t.Error("(addr, Do53) should still be available — DoT failure must not poison Do53")
	}
	if !as.IsAddrXportAvailable("127.0.0.1:53", core.TransportDoH) {
		t.Error("(addr, DoH) should still be available — DoT failure must not poison DoH")
	}
}

// TestAddrXportKeying_SuccessClearsOnlyThatTransport verifies that
// RecordAddressSuccess on one transport leaves backoff on other transports
// intact.
func TestAddrXportKeying_SuccessClearsOnlyThatTransport(t *testing.T) {
	as := NewAuthServer("ns2.example.")
	as.RecordAddressFailure("10.0.0.1:53", core.TransportDoT, fmt.Errorf("x"))
	as.RecordAddressFailure("10.0.0.1:53", core.TransportDoQ, fmt.Errorf("y"))

	if as.IsAddrXportAvailable("10.0.0.1:53", core.TransportDoT) {
		t.Fatal("DoT should be in backoff")
	}
	if as.IsAddrXportAvailable("10.0.0.1:53", core.TransportDoQ) {
		t.Fatal("DoQ should be in backoff")
	}

	as.RecordAddressSuccess("10.0.0.1:53", core.TransportDoT)

	if !as.IsAddrXportAvailable("10.0.0.1:53", core.TransportDoT) {
		t.Error("DoT should be available after RecordAddressSuccess")
	}
	if as.IsAddrXportAvailable("10.0.0.1:53", core.TransportDoQ) {
		t.Error("DoQ should remain in backoff after clearing only DoT")
	}
}

// TestAddrXportKeying_RcodeBackoff verifies the rcode-based backoff path is
// also per-transport.
func TestAddrXportKeying_RcodeBackoff(t *testing.T) {
	as := NewAuthServer("ns3.example.")
	as.RecordAddressFailureForRcode("10.0.0.2:53", core.TransportDo53, 5 /*REFUSED*/)

	if as.IsAddrXportAvailable("10.0.0.2:53", core.TransportDo53) {
		t.Error("Do53 should be in backoff after rcode failure")
	}
	if !as.IsAddrXportAvailable("10.0.0.2:53", core.TransportDoT) {
		t.Error("DoT should not be poisoned by Do53 rcode failure")
	}
}

// TestZoneAddrXportKeying verifies zone-scoped lame-delegation backoff is
// also per-transport.
func TestZoneAddrXportKeying(t *testing.T) {
	z := &Zone{ZoneName: "example."}
	z.RecordZoneAddressFailureForRcode("10.0.0.3:53", core.TransportDoT, 5 /*REFUSED*/, false)

	if z.IsZoneAddrXportAvailable("10.0.0.3:53", core.TransportDoT) {
		t.Error("zone-scoped (addr, DoT) should be in backoff")
	}
	if !z.IsZoneAddrXportAvailable("10.0.0.3:53", core.TransportDo53) {
		t.Error("zone-scoped (addr, Do53) must not be poisoned by DoT lame-delegation")
	}
	z.RecordZoneAddressSuccess("10.0.0.3:53", core.TransportDoT)
	if !z.IsZoneAddrXportAvailable("10.0.0.3:53", core.TransportDoT) {
		t.Error("zone-scoped (addr, DoT) should be cleared after RecordZoneAddressSuccess")
	}
}

// TestSnapshotAddressBackoffs_KeyShape verifies the snapshot returns the
// AddrXport-keyed map and only includes entries still in backoff.
func TestSnapshotAddressBackoffs_KeyShape(t *testing.T) {
	as := NewAuthServer("ns4.example.")
	as.RecordAddressFailure("1.2.3.4:53", core.TransportDo53, fmt.Errorf("nope"))
	as.RecordAddressFailure("1.2.3.4:53", core.TransportDoT, fmt.Errorf("also nope"))

	snap := as.SnapshotAddressBackoffs(time.Now())
	if len(snap) != 2 {
		t.Fatalf("expected 2 entries (Do53 + DoT), got %d", len(snap))
	}
	if _, ok := snap[AddrXport{Addr: "1.2.3.4:53", Transport: core.TransportDo53}]; !ok {
		t.Error("snapshot missing Do53 entry")
	}
	if _, ok := snap[AddrXport{Addr: "1.2.3.4:53", Transport: core.TransportDoT}]; !ok {
		t.Error("snapshot missing DoT entry")
	}

	// Expire one by querying with a far-future "now"
	snap = as.SnapshotAddressBackoffs(time.Now().Add(24 * time.Hour))
	if len(snap) != 0 {
		t.Errorf("expected 0 entries after virtual 24h elapsed, got %d", len(snap))
	}
}

// TestRTT_RecordAndGet verifies a fresh sample is returned exactly.
func TestRTT_RecordAndGet(t *testing.T) {
	as := NewAuthServer("rtt1.example.")
	as.RecordRTT("1.2.3.4:53", core.TransportDo53, 100*time.Millisecond)
	got, ok := as.GetRTT("1.2.3.4:53", core.TransportDo53)
	if !ok {
		t.Fatal("expected sample present")
	}
	if got != 100*time.Millisecond {
		t.Errorf("first sample should equal observation, got %s", got)
	}
}

// TestRTT_GetMiss verifies an unknown tuple returns ok=false.
func TestRTT_GetMiss(t *testing.T) {
	as := NewAuthServer("rtt2.example.")
	if _, ok := as.GetRTT("9.9.9.9:53", core.TransportDoT); ok {
		t.Error("expected ok=false for unprobed tuple")
	}
	as.RecordRTT("1.2.3.4:53", core.TransportDo53, 50*time.Millisecond)
	if _, ok := as.GetRTT("1.2.3.4:53", core.TransportDoT); ok {
		t.Error("Do53 sample should not satisfy DoT lookup")
	}
}

// TestRTT_EMAConvergence verifies multiple samples drift EMA toward the new
// value rather than jumping.
func TestRTT_EMAConvergence(t *testing.T) {
	as := NewAuthServer("rtt3.example.")
	as.RecordRTT("1.2.3.4:53", core.TransportDo53, 100*time.Millisecond)
	for i := 0; i < 10; i++ {
		as.RecordRTT("1.2.3.4:53", core.TransportDo53, 500*time.Millisecond)
	}
	got, _ := as.GetRTT("1.2.3.4:53", core.TransportDo53)
	if got < 300*time.Millisecond {
		t.Errorf("after 10 high samples EMA should have drifted upward toward 500ms, got %s", got)
	}
	if got > 500*time.Millisecond {
		t.Errorf("EMA must not exceed latest sample, got %s", got)
	}
	for i := 0; i < 10; i++ {
		as.RecordRTT("1.2.3.4:53", core.TransportDo53, 10*time.Millisecond)
	}
	got, _ = as.GetRTT("1.2.3.4:53", core.TransportDo53)
	if got > 100*time.Millisecond {
		t.Errorf("after 10 low samples EMA should have drifted toward 10ms, got %s", got)
	}
}

// TestRTT_IgnoresNonPositive verifies RecordRTT silently drops zero/negative.
func TestRTT_IgnoresNonPositive(t *testing.T) {
	as := NewAuthServer("rtt4.example.")
	as.RecordRTT("1.2.3.4:53", core.TransportDo53, 0)
	as.RecordRTT("1.2.3.4:53", core.TransportDo53, -1*time.Millisecond)
	if _, ok := as.GetRTT("1.2.3.4:53", core.TransportDo53); ok {
		t.Error("non-positive samples should not create an entry")
	}
}

// TestRTT_Decay verifies that a sample older than BackoffPolicy.MaxFailure
// is treated as expired (ok=false), so the sort path re-probes.
func TestRTT_Decay(t *testing.T) {
	as := NewAuthServer("rtt5.example.")
	as.RecordRTT("1.2.3.4:53", core.TransportDo53, 50*time.Millisecond)

	max := GetBackoffPolicy().MaxFailure
	as.mu.Lock()
	r := as.RTTEstimates[AddrXport{Addr: "1.2.3.4:53", Transport: core.TransportDo53}]
	r.LastSampleAt = time.Now().Add(-max - time.Minute)
	as.mu.Unlock()

	if _, ok := as.GetRTT("1.2.3.4:53", core.TransportDo53); ok {
		t.Error("expected stale RTT (older than MaxFailure) to read as missing")
	}
}
