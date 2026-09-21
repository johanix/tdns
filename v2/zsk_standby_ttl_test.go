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

// #705: a standby ZSK is one "asap --zsk" promotes on the next tick, so a ZSK
// may reach standby only once resolvers can hold it: published for
// propagation-delay plus the served DNSKEY TTL.

const zskTTLZone = "zsk-ttl.example."

const zskTTLZoneText = `zsk-ttl.example.	3600	IN	SOA	ns.zsk-ttl.example. hostmaster.zsk-ttl.example. 1 7200 1800 604800 7200
zsk-ttl.example.	3600	IN	NS	ns.zsk-ttl.example.
ns.zsk-ttl.example.	3600	IN	A	192.0.2.1
`

// zskTTLPolicy is a KSK-ZSK policy serving the DNSKEY RRset with dnskeyTTL
// seconds (0: no TTL in the policy).
func zskTTLPolicy(dnskeyTTL uint32) *DnssecPolicy {
	pol := &DnssecPolicy{
		Name:         "zsk-ttl",
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		KSK:          KeyLifetime{Lifetime: 30 * 86400},
		ZSK:          KeyLifetime{Lifetime: 86400},
	}
	pol.TTLS.DNSKEY = dnskeyTTL
	return pol
}

// publishedZSK publishes one ZSK in the zone, published at t0.
func publishedZSK(t *testing.T, kdb *KeyDB, t0 time.Time) uint16 {
	t.Helper()
	k := ktGenZSK(t, kdb, zskTTLZone, DnskeyStatePublished, dns.ED25519)
	backdate(t, kdb, zskTTLZone, k, "published_at", t0)
	return k
}

type standbyStep struct {
	after time.Duration
	want  string
}

func runStandbySteps(t *testing.T, kdb *KeyDB, k uint16, t0 time.Time, delay time.Duration, steps []standbyStep) {
	t.Helper()
	for _, s := range steps {
		transitionPublishedToStandby(&Conf, kdb, t0.Add(s.after), delay)
		if got := ktKeyState(t, kdb, zskTTLZone, k); got != s.want {
			t.Fatalf("%s after publication: ZSK is %s, want %s", s.after, got, s.want)
		}
	}
}

func TestZskStandbyWaitsForDnskeyTTL(t *testing.T) {
	kdb := newTestKeyDB(t)
	ktEngineZone(t, kdb, zskTTLZone, zskTTLZoneText, zskTTLPolicy(90))
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	k := publishedZSK(t, kdb, t0)

	runStandbySteps(t, kdb, k, t0, 30*time.Second, []standbyStep{
		// Past the propagation delay, which is where the gate used to open:
		// a resolver can still hold a DNSKEY RRset without this key.
		{31 * time.Second, DnskeyStatePublished},
		{119 * time.Second, DnskeyStatePublished},
		{121 * time.Second, DnskeyStateStandby},
	})
}

// A zone with no TTL in its policy waits for the TTL its first signing pass
// observes, rather than promoting on the propagation delay alone.
func TestZskStandbyDeferredUntilDnskeyTTLKnown(t *testing.T) {
	kdb := newTestKeyDB(t)
	ktEngineZone(t, kdb, zskTTLZone, zskTTLZoneText, zskTTLPolicy(0))
	t0 := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	k := publishedZSK(t, kdb, t0)

	runStandbySteps(t, kdb, k, t0, 30*time.Second, []standbyStep{
		{time.Hour, DnskeyStatePublished},
	})
	if err := UpsertZoneSigningMaxTTL(kdb, zskTTLZone, 300); err != nil {
		t.Fatal(err)
	}
	runStandbySteps(t, kdb, k, t0, 30*time.Second, []standbyStep{
		{329 * time.Second, DnskeyStatePublished},
		{331 * time.Second, DnskeyStateStandby},
	})
}

// `auto-rollover status` projects the same wait the timer applies.
func TestZskStatusProjectsStandbyAfterDnskeyTTL(t *testing.T) {
	kdb := newTestKeyDB(t)
	t0 := time.Now().Add(-time.Minute).Truncate(time.Second)
	publishedZSK(t, kdb, t0)

	for _, c := range []struct {
		pol  *DnssecPolicy
		want string // NextTransitionAt; "" means a note instead
	}{
		{zskTTLPolicy(90), t0.Add(120 * time.Second).UTC().Format(time.RFC3339)},
		{zskTTLPolicy(0), ""},
	} {
		out := &RolloverStatus{}
		out.ZSKs, _ = loadRolloverKeyEntries(kdb, zskTTLZone, false)
		populateZskNextTransitions(out, kdb, zskTTLZone, c.pol, 30*time.Second)
		var e *RolloverKeyEntry
		for i := range out.ZSKs {
			if out.ZSKs[i].State == DnskeyStatePublished {
				e = &out.ZSKs[i]
			}
		}
		if e == nil {
			t.Fatalf("no published ZSK entry in %+v", out.ZSKs)
		}
		if e.NextTransitionAt != c.want {
			t.Errorf("DNSKEY TTL %ds: published → standby at %q, want %q", c.pol.TTLS.DNSKEY, e.NextTransitionAt, c.want)
		}
		if c.want == "" && e.NextTransitionNote == "" {
			t.Errorf("DNSKEY TTL unknown: no note explaining the missing time")
		}
	}
}

func postZskAsap(t *testing.T, conf *Config) RolloverAsapResponse {
	t.Helper()
	body, _ := json.Marshal(RolloverAsapRequest{Zone: zskTTLZone, KeyType: "ZSK"})
	rec := httptest.NewRecorder()
	APIRolloverAsap(conf)(rec, httptest.NewRequest(http.MethodPost, "/rollover/asap", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("asap --zsk: status %d: %s", rec.Code, rec.Body.String())
	}
	var resp RolloverAsapResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("asap --zsk response: %v", err)
	}
	return resp
}

// "asap --zsk" promises "now" only when a standby exists, and a repeat is the
// same request.
func TestAsapZskAnswersWhatTheWorkerCanDo(t *testing.T) {
	kdb := newTestKeyDB(t)
	ktEngineZone(t, kdb, zskTTLZone, zskTTLZoneText, zskTTLPolicy(90))
	ktGenZSK(t, kdb, zskTTLZone, DnskeyStateActive, dns.ED25519)
	conf := &Config{}
	conf.Internal.KeyDB = kdb

	if resp := postZskAsap(t, conf); resp.Earliest != "" {
		t.Errorf("no standby ZSK: earliest %q, want none", resp.Earliest)
	}
	if m, err := LoadZskManualRollover(kdb, zskTTLZone); err != nil || m.Earliest == "" {
		t.Fatalf("the request must be stored even without a standby: %+v, %v", m, err)
	}

	first := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := kdb.DB.Exec(`UPDATE ZskRolloverState SET manual_rollover_requested_at=? WHERE zone=?`, first, zskTTLZone); err != nil {
		t.Fatal(err)
	}
	ktGenZSK(t, kdb, zskTTLZone, DnskeyStateStandby, dns.ED25519)
	resp := postZskAsap(t, conf)
	if resp.Earliest == "" {
		t.Errorf("with a standby ZSK: no earliest time")
	}
	if resp.RequestedAt != first {
		t.Errorf("repeat: requested at %q, want the pending request's %q", resp.RequestedAt, first)
	}
	if m, _ := LoadZskManualRollover(kdb, zskTTLZone); m.RequestedAt != first {
		t.Errorf("repeat overwrote the stored requested_at: %q, want %q", m.RequestedAt, first)
	}
}
