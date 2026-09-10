/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testAgentTsigKey = "agent-to-primary."

// withAgentTsigKey installs a TSIG key store holding the agent's key for the
// test. Both the writer (through TsigMaterialForPeer) and the sink server
// (through Conf.tsigProvider) read the same store.
func withAgentTsigKey(t *testing.T) {
	t.Helper()
	prev := Conf.Internal.TsigKeyStore
	t.Cleanup(func() { Conf.Internal.TsigKeyStore = prev })
	store := NewTsigKeyStore()
	store.Add(TsigDetails{Name: testAgentTsigKey, Algorithm: "hmac-sha256", Secret: "MTIzNDU2Nzg5MDEyMzQ1Ng=="})
	Conf.Internal.TsigKeyStore = store
}

// updateSink is a fake parent primary: it records the UPDATEs it receives
// and answers each with a fixed rcode.
type updateSink struct {
	addr     string
	rcode    int
	mu       sync.Mutex
	msgs     []*dns.Msg
	signed   bool
	verified bool
	received chan *dns.Msg
}

func startUpdateSink(t *testing.T, rcode int) *updateSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sink := &updateSink{addr: ln.Addr().String(), rcode: rcode, received: make(chan *dns.Msg, 32)}
	started := make(chan struct{})
	srv := &dns.Server{
		Listener:     ln,
		TsigProvider: Conf.tsigProvider(),
		// miekg's default accept function answers NOTIMP to any UPDATE;
		// tdns's own accepts them, as a real primary would.
		MsgAcceptFunc: MsgAcceptFunc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			sink.mu.Lock()
			sink.msgs = append(sink.msgs, r)
			sink.signed = r.IsTsig() != nil
			sink.verified = sink.signed && w.TsigStatus() == nil
			sink.mu.Unlock()
			m := new(dns.Msg)
			m.SetRcode(r, sink.rcode)
			if r.IsTsig() != nil {
				m.SetTsig(r.IsTsig().Hdr.Name, r.IsTsig().Algorithm, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
			select {
			case sink.received <- r:
			default:
			}
		}),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("update sink did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return sink
}

// last is the most recent UPDATE received, or nil.
func (s *updateSink) last() *dns.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.msgs) == 0 {
		return nil
	}
	return s.msgs[len(s.msgs)-1]
}

func (s *updateSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

func (s *updateSink) tsig() (signed, verified bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signed, s.verified
}

// wait blocks until the sink has received an UPDATE, or fails the test.
func (s *updateSink) wait(t *testing.T, d time.Duration) *dns.Msg {
	t.Helper()
	select {
	case m := <-s.received:
		return m
	case <-time.After(d):
		t.Fatalf("no UPDATE reached the sink within %s", d)
		return nil
	}
}

// proxyWriterFixture is a childsync-proxy's view of the parent: the served
// zone (adoptParentZone: alpha and bravo delegated), a sqlite store that
// already holds a child the zone does not serve yet, and a writer over both.
func proxyWriterFixture(t *testing.T, targets ...string) (*ddnsParentZoneWriter, *ZoneData) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)
	zd.ZoneType = Secondary
	store := &DBDelegationBackend{kdb: kdb}
	accepted := childUpdate(t, "charlie.parent.example. 3600 IN NS ns.charlie.parent.example.")
	accepted.ZoneName = "parent.example."
	if err := store.ApplyChildUpdate("parent.example.", accepted); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}
	w := &ddnsParentZoneWriter{zd: zd, store: store, targets: targets, keyName: testAgentTsigKey}
	return w, zd
}

func writerRRs(t *testing.T, strs ...string) []dns.RR {
	t.Helper()
	out := make([]dns.RR, 0, len(strs))
	for _, s := range strs {
		out = append(out, mustDsyncRR(t, s))
	}
	return out
}

func TestDdnsWriterSignsAndTheParentVerifies(t *testing.T) {
	withAgentTsigKey(t)
	sink := startUpdateSink(t, dns.RcodeSuccess)
	w, _ := proxyWriterFixture(t, sink.addr)

	actions := writerRRs(t, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")
	if err := w.Write(context.Background(), "parent.example.", actions, "test"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := sink.last()
	if got == nil || got.Opcode != dns.OpcodeUpdate {
		t.Fatalf("the sink did not receive an UPDATE: %v", got)
	}
	if signed, verified := sink.tsig(); !signed || !verified {
		t.Fatalf("the UPDATE must be TSIG-signed and verify at the primary: signed=%v verified=%v", signed, verified)
	}
	if name := got.IsTsig().Hdr.Name; name != testAgentTsigKey {
		t.Errorf("signed with key %q, want %q", name, testAgentTsigKey)
	}
	if len(got.Ns) != 1 || got.Ns[0].String() != actions[0].String() {
		t.Errorf("the UPDATE carries %v, want the actions verbatim", got.Ns)
	}
}

func TestDdnsWriterRefusesToSendUnsignedUnlessAllowed(t *testing.T) {
	withAgentTsigKey(t)
	sink := startUpdateSink(t, dns.RcodeSuccess)
	w, _ := proxyWriterFixture(t, sink.addr)
	w.keyName = ""
	actions := writerRRs(t, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")

	err := w.Write(context.Background(), "parent.example.", actions, "test")
	if err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("an unsigned push must be refused by default, got %v", err)
	}
	if sink.count() != 0 {
		t.Fatal("the refused push still reached the primary")
	}

	w.allowInsecure = true
	if err := w.Write(context.Background(), "parent.example.", actions, "test"); err != nil {
		t.Fatalf("allow-insecure: %v", err)
	}
	if signed, _ := sink.tsig(); sink.count() == 0 || signed {
		t.Fatalf("allow-insecure must send, unsigned: received=%d signed=%v", sink.count(), signed)
	}
}

// The parent's answer is classified for the push engine: NOERROR is done, a
// SERVFAIL is worth retrying, a REFUSED or NOTAUTH is the primary's policy
// saying no and is not. A transport failure is an ordinary error.
func TestDdnsWriterClassifiesTheParentsAnswer(t *testing.T) {
	withAgentTsigKey(t)
	actions := writerRRs(t, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")

	for _, tc := range []struct {
		rcode     int
		transient bool
	}{
		{dns.RcodeRefused, false},
		{dns.RcodeNotAuth, false},
		{dns.RcodeServerFailure, true},
	} {
		t.Run(dns.RcodeToString[tc.rcode], func(t *testing.T) {
			sink := startUpdateSink(t, tc.rcode)
			w, _ := proxyWriterFixture(t, sink.addr)
			err := w.Write(context.Background(), "parent.example.", actions, "test")
			var rej *WriteRejected
			if !errors.As(err, &rej) {
				t.Fatalf("want a WriteRejected, got %v", err)
			}
			if rej.Rcode != tc.rcode || rej.Transient() != tc.transient {
				t.Fatalf("rejection = %+v transient=%v, want rcode %s transient=%v", rej, rej.Transient(), dns.RcodeToString[tc.rcode], tc.transient)
			}
		})
	}

	t.Run("transport", func(t *testing.T) {
		w, _ := proxyWriterFixture(t, "127.0.0.1:1")
		err := w.Write(context.Background(), "parent.example.", actions, "test")
		var rej *WriteRejected
		if err == nil || errors.As(err, &rej) {
			t.Fatalf("an unreachable primary is a transport error, got %v", err)
		}
	})
}

// With no ddns.targets the writer pushes to the zone's own primaries: the
// machine it transfers from is the machine to update.
func TestDdnsWriterDefaultsToTheZonesPrimaries(t *testing.T) {
	withAgentTsigKey(t)
	sink := startUpdateSink(t, dns.RcodeSuccess)
	w, zd := proxyWriterFixture(t)
	zd.Upstreams = []PeerConf{{Addr: sink.addr}}

	if err := w.Write(context.Background(), "parent.example.",
		writerRRs(t, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example."), "test"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if sink.count() == 0 {
		t.Fatal("nothing reached the zone's primary")
	}
}

// D-5: the writer refuses, before it builds a message, any owner that is not
// a delegation name of the parent or one of the agent's own advertisement
// names -- whatever the primary's update-policy would have allowed.
func TestDdnsWriterIsBoundToDelegationNames(t *testing.T) {
	withAgentTsigKey(t)
	allSchemesChildSync(t)
	w, _ := proxyWriterFixture(t, "127.0.0.1:1") // never reached when refused

	for _, tc := range []struct {
		name    string
		actions []string
		refused string
	}{
		{"apex SOA", []string{"parent.example. 3600 IN SOA ns.parent.example. h.parent.example. 9 1 1 1 1"}, "not below the parent apex"},
		{"apex NS", []string{"parent.example. 3600 IN NS ns.evil.example."}, "not below the parent apex"},
		{"out of zone", []string{"other.example. 3600 IN NS ns.other.example."}, "not below the parent apex"},
		{"an ordinary name in the parent", []string{"www.parent.example. 3600 IN A 192.0.2.99"}, "not at or below a delegation point"},
		{"glue for a child that exists nowhere", []string{"ns.delta.parent.example. 3600 IN A 192.0.2.4"}, "not at or below a delegation point"},
		{"a served delegation point", []string{"alpha.parent.example. 3600 IN NS ns2.alpha.parent.example."}, ""},
		{"glue below a served cut", []string{"ns.alpha.parent.example. 3600 IN AAAA 2001:db8::99"}, ""},
		{"a cut the store holds but the zone does not serve yet", []string{"charlie.parent.example. 3600 IN DS 1 13 2 00"}, ""},
		{"glue below a store-only cut", []string{"ns.charlie.parent.example. 3600 IN A 192.0.2.3"}, ""},
		{"a new child, cut and glue in one update", []string{
			"delta.parent.example. 3600 IN NS ns.delta.parent.example.",
			"ns.delta.parent.example. 3600 IN A 192.0.2.4"}, ""},
		{"the _dsync owner", []string{"_dsync.parent.example. 7200 IN DSYNC CDS NOTIFY 5302 notifications.parent.example."}, ""},
		{"the UPDATE target (KEY and SVCB live here)", []string{"updates.parent.example. 7200 IN A 192.0.2.53"}, ""},
		{"the NOTIFY target", []string{"notifications.parent.example. 7200 IN AAAA 2001:db8::53"}, ""},
		{"the API target", []string{"api.parent.example. 7200 IN TXT \"tdns-child-api-v1.0\""}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := w.boundToDelegationNames("parent.example.", writerRRs(t, tc.actions...))
			if tc.refused == "" {
				if err != nil {
					t.Fatalf("must be allowed, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.refused) {
				t.Fatalf("must be refused (%s), got %v", tc.refused, err)
			}
		})
	}
}

func TestRenderNsupdateBlock(t *testing.T) {
	del := mustDsyncRR(t, "alpha.parent.example. 3600 IN NS old.alpha.parent.example.")
	del.Header().Class = dns.ClassNONE
	del.Header().Ttl = 0
	wipe := mustDsyncRR(t, "bravo.parent.example. 3600 IN DS 1 13 2 00")
	wipe.Header().Class = dns.ClassANY
	add := mustDsyncRR(t, "alpha.parent.example. 3600 IN NS new.alpha.parent.example.")

	got := RenderNsupdateBlock("parent.example.", []string{"192.0.2.1:53"}, "agent-to-primary.", []dns.RR{del, wipe, add})
	want := "server 192.0.2.1:53\n" +
		"; sign with TSIG key agent-to-primary. (nsupdate -k <keyfile>)\n" +
		"zone parent.example.\n" +
		"update delete alpha.parent.example.\t0\tIN\tNS\told.alpha.parent.example.\n" +
		"update delete bravo.parent.example. DS\n" +
		"update add alpha.parent.example.\t3600\tIN\tNS\tnew.alpha.parent.example.\n" +
		"send\n"
	if got != want {
		t.Fatalf("rendered block differs.\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}
