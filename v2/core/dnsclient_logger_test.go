/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A client given a logger says that it retried a truncated answer over TCP
// there, and nothing through the log package.
func TestTruncationRetryLogsThroughTheClientsLogger(t *testing.T) {
	const qname = "tclog.example."
	udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRR(qname, "192.0.2.1")}
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, udp, tcp)
	defer cleanup()

	var global bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&global)
	t.Cleanup(func() { log.SetOutput(prev) })

	var own bytes.Buffer
	c := NewDNSClient(TransportDo53, port, nil, WithLogger(log.New(&own, "", 0)))
	c.Timeout = 2 * time.Second
	if _, _, res, err := c.ExchangeWithResult(mustQuery(qname), "127.0.0.1", false); err != nil || !res.Truncated {
		t.Fatalf("ExchangeWithResult: %+v, %v; want the truncated answer retried over TCP", res, err)
	}
	if !strings.Contains(own.String(), "truncated (TC=1); retrying over TCP") {
		t.Errorf("the client's logger got %q; want the truncation retry", own.String())
	}
	if global.Len() != 0 {
		t.Errorf("the log package got %q", global.String())
	}
}
