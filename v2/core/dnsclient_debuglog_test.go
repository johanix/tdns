/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Under debug, a client given a logger says what it sends there, and
// nothing on stdout or through the log package.
func TestDebugLinesGoToTheClientsLogger(t *testing.T) {
	const qname = "dbglog.example."
	answer := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRR(qname, "192.0.2.1")}
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, answer, answer)
	defer cleanup()

	global := captureLog(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = pw
	restore := func() { os.Stdout = stdout }
	t.Cleanup(restore)

	var own bytes.Buffer
	c := NewDNSClient(TransportDo53, port, nil, WithLogger(log.New(&own, "", 0)))
	c.Timeout = 2 * time.Second
	_, _, _, xerr := c.ExchangeWithResult(mustQuery(qname), "127.0.0.1", true)

	restore()
	pw.Close()
	printed, _ := io.ReadAll(pr)
	if xerr != nil {
		t.Fatalf("ExchangeWithResult: %v", xerr)
	}
	for _, want := range []string{"*** Exchange: sending", "*** Do53 sending"} {
		if !strings.Contains(own.String(), want) {
			t.Errorf("the client's logger got %q; want %q", own.String(), want)
		}
	}
	if len(printed) != 0 {
		t.Errorf("stdout got %q", printed)
	}
	if global.Len() != 0 {
		t.Errorf("the log package got %q", global.String())
	}
}
