/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// seenNotify is one NOTIFY as a test receiver saw it.
type seenNotify struct {
	msg     *dns.Msg
	signed  bool
	tsigErr error
}

// startNotifySink runs a UDP receiver on loopback that records every NOTIFY and
// answers NOERROR, signing its answer when the request was signed.
func startNotifySink(t *testing.T, secrets map[string]string) (string, <-chan seenNotify) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	seen := make(chan seenNotify, 16)
	ready := make(chan struct{})
	srv := &dns.Server{
		PacketConn: pc,
		TsigSecret: secrets,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			sn := seenNotify{msg: r.Copy(), signed: r.IsTsig() != nil}
			if sn.signed {
				sn.tsigErr = w.TsigStatus()
			}
			seen <- sn
			m := new(dns.Msg)
			m.SetReply(r)
			if tsig := r.IsTsig(); tsig != nil {
				m.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
		}),
		NotifyStartedFunc: func() { close(ready) },
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), seen
}

func nextNotify(t *testing.T, seen <-chan seenNotify) seenNotify {
	t.Helper()
	select {
	case sn := <-seen:
		return sn
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver saw no NOTIFY")
	}
	return seenNotify{}
}

func notifiedSOA(t *testing.T, m *dns.Msg) *dns.SOA {
	t.Helper()
	if len(m.Answer) != 1 {
		t.Fatalf("NOTIFY(SOA) answer section has %d RRs, want 1:\n%s", len(m.Answer), m)
	}
	soa, ok := m.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("NOTIFY(SOA) answer is %T, want *dns.SOA", m.Answer[0])
	}
	return soa
}

// A NOTIFY(SOA) carries the SOA being served, and a later NOTIFY the later one.
func TestNotifySOACarriesTheServedSOA(t *testing.T) {
	addr, seen := startNotifySink(t, nil)
	zd := loadIxfrTestZone(t, basicZone)
	zd.Notify = []PeerConf{{Addr: addr}}
	conf := &Config{}

	if rcode, _, err := zd.SendNotify(context.Background(), conf, dns.TypeSOA, []string{addr}); err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("SendNotify: rcode %s, err %v", dns.RcodeToString[rcode], err)
	}
	served := zd.publishedSnapshot().SOA
	if got := notifiedSOA(t, nextNotify(t, seen).msg); got.String() != served.String() {
		t.Errorf("NOTIFY carries\n  %s\nwant the served\n  %s", got, served)
	}

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if _, _, err := zd.SendNotify(context.Background(), conf, dns.TypeSOA, []string{addr}); err != nil {
		t.Fatalf("SendNotify after a publish: %v", err)
	}
	newer := zd.publishedSnapshot().SOA.Serial
	if newer == served.Serial {
		t.Fatal("setup: the publish did not move the serial")
	}
	if got := notifiedSOA(t, nextNotify(t, seen).msg).Serial; got != newer {
		t.Errorf("NOTIFY after a publish carries serial %d, want %d", got, newer)
	}
}

// The SOA is added before the TSIG stamp, so a signed NOTIFY still verifies.
func TestNotifySOAIsCoveredByTSIG(t *testing.T) {
	const keyName = "notify-key."
	addr, seen := startNotifySink(t, map[string]string{keyName: b64Secret16})
	zd := loadIxfrTestZone(t, basicZone)
	zd.Notify = []PeerConf{{Addr: addr, Key: keyName}}
	conf := &Config{}
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: keyName, Algorithm: "hmac-sha256", Secret: b64Secret16})

	if rcode, _, err := zd.SendNotify(context.Background(), conf, dns.TypeSOA, []string{addr}); err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("SendNotify: rcode %s, err %v", dns.RcodeToString[rcode], err)
	}
	sn := nextNotify(t, seen)
	if !sn.signed {
		t.Fatal("the NOTIFY was not signed")
	}
	if sn.tsigErr != nil {
		t.Errorf("the receiver could not verify the NOTIFY's TSIG: %v", sn.tsigErr)
	}
	notifiedSOA(t, sn.msg)
}

// Only NOTIFY(SOA) carries a record; the others ask the receiver to look.
func TestNotifyOtherTypesCarryNothing(t *testing.T) {
	addr, seen := startNotifySink(t, nil)
	zd := loadIxfrTestZone(t, basicZone)
	if _, _, err := zd.SendNotify(context.Background(), &Config{}, dns.TypeDNSKEY, []string{addr}); err != nil {
		t.Fatalf("SendNotify: %v", err)
	}
	if m := nextNotify(t, seen).msg; len(m.Answer) != 0 {
		t.Errorf("NOTIFY(DNSKEY) carries %d answer RRs, want none:\n%s", len(m.Answer), m)
	}
}
