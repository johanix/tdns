/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// imr-resolve answers through the engine, with the validator's verdict: the
// question "tdns-cli imr query" puts to a running daemon.
func TestAPIimrResolveAnswersThroughTheEngine(t *testing.T) {
	imr := newTestImr(t)
	rrset := &core.RRset{Name: "www.example.", Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1"),
	}}}
	imr.Cache.Set("www.example.", dns.TypeA, &cache.CachedRRset{Name: "www.example.", RRtype: dns.TypeA,
		RRset: rrset, Context: cache.ContextAnswer, State: cache.ValidationStateSecure,
		Expiration: time.Now().Add(time.Minute)})

	saved := Globals.ImrEngine
	Globals.ImrEngine = imr
	t.Cleanup(func() { Globals.ImrEngine = saved })

	body, _ := json.Marshal(ImrMgmtPost{Command: "imr-resolve",
		Data: map[string]interface{}{"qname": "www.example.", "qtype": "A"}})
	rec := httptest.NewRecorder()
	(&Config{}).APIimr()(rec, httptest.NewRequest(http.MethodPost, "/imr", bytes.NewReader(body)))

	var resp ImrMgmtResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v (%s)", err, rec.Body.String())
	}
	if resp.Error {
		t.Fatalf("imr-resolve failed: %s", resp.ErrorMsg)
	}
	data, _ := resp.Data.(map[string]interface{})
	if got, want := data["state"], cache.ValidationStateToString[cache.ValidationStateSecure]; got != want {
		t.Errorf("state %v, want %q", got, want)
	}
	records, _ := data["records"].([]interface{})
	if len(records) != 1 || !strings.Contains(records[0].(string), "192.0.2.1") {
		t.Errorf("records %v, want the cached A record", records)
	}
}
