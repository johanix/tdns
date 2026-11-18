/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The API's "imr query" (imr-resolve) asks as a DNS client does: a DS or
// DNSKEY question at a CNAME owner follows the CNAME, as it does for dig, and
// the records that come back are those at the chain's end.
func TestAPIimrResolveFollowsACNAMEForDSAndDNSKEY(t *testing.T) {
	for _, c := range []struct {
		qname, owner string
		qtype        uint16
	}{
		{"s1." + sigChainZone, "s3." + sigChainZone, dns.TypeDS},
		{"top." + sigChainZone, sigChainZone, dns.TypeDNSKEY},
	} {
		t.Run(dns.TypeToString[c.qtype], func(t *testing.T) {
			imr, _ := sigChainImr(t)
			saved := Globals.ImrEngine
			Globals.ImrEngine = imr
			t.Cleanup(func() { Globals.ImrEngine = saved })

			body, _ := json.Marshal(ImrMgmtPost{Command: "imr-resolve",
				Data: map[string]interface{}{"qname": c.qname, "qtype": dns.TypeToString[c.qtype]}})
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
			records, _ := data["records"].([]interface{})
			if len(records) == 0 {
				t.Fatalf("%s %s: no records (%v); want the %s at %s", c.qname, dns.TypeToString[c.qtype], data,
					dns.TypeToString[c.qtype], c.owner)
			}
			for _, r := range records {
				rr := mustRR(t, r.(string))
				if rr.Header().Rrtype != c.qtype || !core.EqualNames(rr.Header().Name, c.owner) {
					t.Errorf("%s %s: record %v; want the %s at %s", c.qname, dns.TypeToString[c.qtype], rr,
						dns.TypeToString[c.qtype], c.owner)
				}
			}
			if got, want := data["state"], cache.ValidationStateToString[cache.ValidationStateSecure]; got != want {
				t.Errorf("state %v, want %q", got, want)
			}
		})
	}
}
