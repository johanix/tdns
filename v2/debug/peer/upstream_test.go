/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startUpstream(t *testing.T, historyCap int) *Upstream {
	t.Helper()
	u, err := NewUpstream("relay.test.", "127.0.0.1:0", seedZone(t), historyCap)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	u.Start()
	t.Cleanup(u.Stop)
	return u
}

// transferIn runs a transfer against the peer and returns every RR in order.
// Order matters here: AXFR and IXFR are defined by their SOA framing, so a
// test that sorted the result could not tell a valid stream from an invalid one.
func transferIn(t *testing.T, addr string, m *dns.Msg) []dns.RR {
	t.Helper()
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second}
	ch, err := tr.In(m, addr)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	var out []dns.RR
	for env := range ch {
		if env.Error != nil {
			t.Fatalf("transfer envelope: %v", env.Error)
		}
		out = append(out, env.RR...)
	}
	return out
}

func ixfrMsg(zone string, serial uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetIxfr(dns.Fqdn(zone), serial, "ns.relay.test.", "hostmaster.relay.test.")
	return m
}

func TestUpstreamAnswersSOA(t *testing.T) {
	u := startUpstream(t, 8)
	m := new(dns.Msg)
	m.SetQuestion("relay.test.", dns.TypeSOA)
	r, err := dns.Exchange(m, u.Addr())
	if err != nil {
		t.Fatalf("SOA query: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("answer has %d RRs, want 1", len(r.Answer))
	}
	soa, ok := r.Answer[0].(*dns.SOA)
	if !ok || soa.Serial != 1 {
		t.Fatalf("answer = %v, want SOA serial 1", r.Answer[0])
	}
}

func TestUpstreamRefusesAnotherZone(t *testing.T) {
	u := startUpstream(t, 8)
	m := new(dns.Msg)
	m.SetQuestion("elsewhere.test.", dns.TypeSOA)
	r, err := dns.Exchange(m, u.Addr())
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[r.Rcode])
	}
}

func TestUpstreamAXFRIsSOAFramed(t *testing.T) {
	u := startUpstream(t, 8)
	m := new(dns.Msg)
	m.SetAxfr("relay.test.")
	rrs := transferIn(t, u.Addr(), m)

	if len(rrs) != 5 { // 4 seed records, SOA repeated at the end
		t.Fatalf("AXFR returned %d RRs, want 5", len(rrs))
	}
	first, firstOK := rrs[0].(*dns.SOA)
	last, lastOK := rrs[len(rrs)-1].(*dns.SOA)
	if !firstOK || !lastOK {
		t.Fatal("AXFR is not SOA-framed at both ends")
	}
	if first.Serial != last.Serial || first.Serial != 1 {
		t.Fatalf("AXFR framing serials %d/%d, want 1/1", first.Serial, last.Serial)
	}

	got := ZoneFromRRs("relay.test.", rrs)
	if d := CompareContent(u.Current().Zone, got); !d.Equal() {
		t.Fatalf("AXFR did not reproduce the zone:\n%s", d)
	}
	if obs := u.Transfers(); len(obs) != 1 || obs[0].Outcome != "axfr" {
		t.Fatalf("transfer observations = %+v, want one axfr", obs)
	}
}

func TestUpstreamIXFRCarriesOneSequencePerVersion(t *testing.T) {
	u := startUpstream(t, 8)
	for i := 0; i < 3; i++ {
		if _, err := u.Apply(Change{
			Label: "add",
			Add:   []dns.RR{mustRR(t, "h"+strconv.Itoa(i)+".relay.test. 3600 IN A 10.0.4."+strconv.Itoa(i))},
		}); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}

	rrs := transferIn(t, u.Addr(), ixfrMsg("relay.test.", 1))
	obs := u.Transfers()
	if len(obs) != 1 || obs[0].Outcome != "ixfr" {
		t.Fatalf("transfer observations = %+v, want one ixfr", obs)
	}
	if obs[0].Sequences != 3 {
		t.Fatalf("Sequences = %d, want 3 (one per version the client missed)", obs[0].Sequences)
	}

	// RFC 1995 §4 framing: current SOA, then per sequence an old SOA and a new
	// SOA, then the current SOA again. Three sequences with one addition each.
	soaCount := 0
	for _, rr := range rrs {
		if _, ok := rr.(*dns.SOA); ok {
			soaCount++
		}
	}
	if soaCount != 2+2*3 {
		t.Fatalf("stream has %d SOAs, want %d", soaCount, 2+2*3)
	}
	if first, ok := rrs[0].(*dns.SOA); !ok || first.Serial != 4 {
		t.Fatalf("stream does not open with the current SOA: %v", rrs[0])
	}
	if last, ok := rrs[len(rrs)-1].(*dns.SOA); !ok || last.Serial != 4 {
		t.Fatalf("stream does not close with the current SOA: %v", rrs[len(rrs)-1])
	}
}

// A client already at the current serial gets one SOA and nothing else. If
// this were answered as an AXFR the rig would score a needless whole-zone
// transfer as normal behaviour.
func TestUpstreamIXFRUpToDateIsASingleSOA(t *testing.T) {
	u := startUpstream(t, 8)
	rrs := transferIn(t, u.Addr(), ixfrMsg("relay.test.", 1))
	if len(rrs) != 1 {
		t.Fatalf("up-to-date IXFR returned %d RRs, want 1", len(rrs))
	}
	if obs := u.Transfers(); len(obs) != 1 || obs[0].Outcome != "uptodate" {
		t.Fatalf("transfer observations = %+v, want one uptodate", obs)
	}
}

// An unknown or aged-out serial must fall back to AXFR — and must be RECORDED
// as a fallback, because a fallback that reads as a normal AXFR would hide
// exactly the case the history cap exists to produce.
func TestUpstreamIXFRFallsBackForAgedOutSerial(t *testing.T) {
	u := startUpstream(t, 2)
	for i := 0; i < 4; i++ {
		if _, err := u.Apply(Change{
			Label: "add",
			Add:   []dns.RR{mustRR(t, "a"+strconv.Itoa(i)+".relay.test. 3600 IN A 10.0.5."+strconv.Itoa(i))},
		}); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}

	rrs := transferIn(t, u.Addr(), ixfrMsg("relay.test.", 1))
	obs := u.Transfers()
	if len(obs) != 1 || obs[0].Outcome != "fallback" {
		t.Fatalf("transfer observations = %+v, want one fallback", obs)
	}
	got := ZoneFromRRs("relay.test.", rrs)
	if d := CompareContent(u.Current().Zone, got); !d.Equal() {
		t.Fatalf("fallback AXFR did not reproduce the zone:\n%s", d)
	}
}

// The deltas an IXFR carries must equal the changes the rig authored — the
// upstream half of invariant N5. If the peer's own stream did not satisfy it,
// an N5 failure against the SUT would be unattributable.
func TestUpstreamIXFRDeltasMatchTheAuthoredChanges(t *testing.T) {
	u := startUpstream(t, 8)
	add := mustRR(t, "host2.relay.test. 3600 IN A 10.0.0.2")
	rm := mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")
	c := Change{Label: "swap", Add: []dns.RR{add}, Remove: []dns.RR{rm}}
	if _, err := u.Apply(c); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	rrs := transferIn(t, u.Addr(), ixfrMsg("relay.test.", 1))
	res, err := ParseTransfer("relay.test.", rrs, true)
	if err != nil {
		t.Fatalf("ParseTransfer: %v", err)
	}
	if res.Kind != KindIXFR {
		t.Fatalf("Kind = %s, want ixfr", res.Kind)
	}
	if d := CompareDelta(c, res.Deltas); !d.Equal() {
		t.Fatalf("the peer's own IXFR does not express the authored change:\n%s", d)
	}
}

func TestUpstreamNotifySendsAndRecords(t *testing.T) {
	var (
		mu       sync.Mutex
		received []*dns.Msg
	)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		received = append(received, r.Copy())
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	u := startUpstream(t, 8)
	rcode, err := u.Notify(context.Background(), pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("receiver got %d messages, want 1", len(received))
	}
	got := received[0]
	if got.Opcode != dns.OpcodeNotify {
		t.Fatalf("opcode = %s, want NOTIFY", dns.OpcodeToString[got.Opcode])
	}
	// The rig sends what tdns sends: no SOA in the answer section. A rig that
	// helpfully added one would be testing a downstream path that does not exist.
	if len(got.Answer) != 0 {
		t.Fatalf("NOTIFY carried %d answer RRs; tdns sends none (see design §2.4)", len(got.Answer))
	}
	if obs := u.NotifiesSent(); len(obs) != 1 || obs[0].Serial != 1 || obs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("notify observations = %+v", obs)
	}
}

func TestUpstreamNotifyRecordsAFailure(t *testing.T) {
	u := startUpstream(t, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// 127.0.0.1:1 has nothing on it; the point is that the failure is recorded
	// rather than dropped, so a run cannot silently notify nobody.
	if _, err := u.Notify(ctx, "127.0.0.1:1"); err == nil {
		t.Fatal("Notify to a dead address reported success")
	}
	obs := u.NotifiesSent()
	if len(obs) != 1 || obs[0].Err == "" {
		t.Fatalf("notify observations = %+v, want one carrying an error", obs)
	}
}
