package tdns

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// #705: a repeated KSK "auto-rollover asap" keeps the earlier of the pending
// and the newly computed time. The max-ttl-expiry gate is anchored at the
// moment of the call, so a repeat that recomputed used to move the roll later
// by the time between calls.

const kskAsapZone = "ksk-asap.example."

const kskAsapZoneText = `ksk-asap.example.	3600	IN	SOA	ns.ksk-asap.example. hostmaster.ksk-asap.example. 1 7200 1800 604800 7200
ksk-asap.example.	3600	IN	NS	ns.ksk-asap.example.
ns.ksk-asap.example.	3600	IN	A	192.0.2.1
`

// kskAsapFixture is a multi-DS zone with an active and a standby KSK whose
// last signing pass observed a one-hour TTL: asap is Ready, bound by the
// max-ttl-expiry gate.
func kskAsapFixture(t *testing.T) (*Config, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	ktEngineZone(t, kdb, kskAsapZone, kskAsapZoneText, ktMultiDSPolicy(dns.ED25519, dns.ED25519))
	ktGenKSK(t, kdb, kskAsapZone, DnskeyStateActive, dns.ED25519)
	ktGenKSK(t, kdb, kskAsapZone, DnskeyStateStandby, dns.ED25519)
	if err := UpsertZoneSigningMaxTTL(kdb, kskAsapZone, 3600); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	return conf, kdb
}

func postKskAsap(t *testing.T, conf *Config) (RolloverAsapResponse, time.Time) {
	t.Helper()
	body, _ := json.Marshal(RolloverAsapRequest{Zone: kskAsapZone})
	rec := httptest.NewRecorder()
	APIRolloverAsap(conf)(rec, httptest.NewRequest(http.MethodPost, "/rollover/asap", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("asap: status %d: %s", rec.Code, rec.Body.String())
	}
	var resp RolloverAsapResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("asap response: %v", err)
	}
	at, err := time.Parse(time.RFC3339, resp.Earliest)
	if err != nil {
		t.Fatalf("asap earliest %q: %v", resp.Earliest, err)
	}
	return resp, at
}

// setPendingRequest makes the zone's pending request look as if it had been
// made earlier, with the times given.
func setPendingRequest(t *testing.T, kdb *KeyDB, requestedAt, earliest time.Time) {
	t.Helper()
	if _, err := kdb.DB.Exec(`UPDATE RolloverZoneState SET manual_rollover_requested_at=?, manual_rollover_earliest=? WHERE zone=?`,
		requestedAt.UTC().Format(time.RFC3339), earliest.UTC().Format(time.RFC3339), kskAsapZone); err != nil {
		t.Fatal(err)
	}
}

func storedManualEarliest(t *testing.T, kdb *KeyDB) string {
	t.Helper()
	row, err := LoadRolloverZoneRow(kdb, kskAsapZone)
	if err != nil || row == nil || !row.ManualRolloverEarliest.Valid {
		t.Fatalf("no stored request: row=%+v err=%v", row, err)
	}
	return row.ManualRolloverEarliest.String
}

func TestAsapRepeatNeverDelaysTheRoll(t *testing.T) {
	conf, kdb := kskAsapFixture(t)
	_, first := postKskAsap(t, conf)

	// The first request was made ten minutes ago, so the time it computed is
	// ten minutes earlier than a fresh computation now.
	pending := first.Add(-10 * time.Minute)
	requested := time.Now().Add(-10 * time.Minute)
	setPendingRequest(t, kdb, requested, pending)

	resp, got := postKskAsap(t, conf)
	if !got.Equal(pending) {
		t.Errorf("repeat moved the roll from %s to %s", pending.UTC().Format(time.RFC3339), resp.Earliest)
	}
	if s := storedManualEarliest(t, kdb); s != pending.UTC().Format(time.RFC3339) {
		t.Errorf("stored earliest %s, want the pending %s", s, pending.UTC().Format(time.RFC3339))
	}
	if want := requested.UTC().Format(time.RFC3339); resp.RequestedAt != want {
		t.Errorf("repeat: requested at %s, want the pending request's %s", resp.RequestedAt, want)
	}
}

// Keeping the pending time is a floor on how early, not a pin: when the gates
// now allow an earlier roll than the one pending, a repeat takes it.
func TestAsapRepeatTakesAnEarlierComputedTime(t *testing.T) {
	conf, kdb := kskAsapFixture(t)
	_, first := postKskAsap(t, conf)

	pending := first.Add(10 * time.Hour)
	setPendingRequest(t, kdb, time.Now(), pending)

	resp, got := postKskAsap(t, conf)
	if !got.Before(pending) {
		t.Errorf("repeat kept the later pending %s over a computed %s", pending.UTC().Format(time.RFC3339), resp.Earliest)
	}
	if got.Before(first) {
		t.Errorf("repeat computed %s, before the first request's %s", resp.Earliest, first.UTC().Format(time.RFC3339))
	}
}
