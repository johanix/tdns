package core

import (
	"testing"

	"github.com/miekg/dns"
)

// HSYNC3's label and upstream follow the Label rule: 1 to 16 characters, each
// a lowercase ASCII letter, a digit or a hyphen; upstream may also be ".".
// That is what lets a Label in HSYNCPARAM match its HSYNC3 record octet by
// octet. The label is stored as written: earlier code added a trailing dot
// ("netnod."), which is not a Label.
func TestHsync3LabelsFollowTheLabelRule(t *testing.T) {
	if err := RegisterHsync3RR(); err != nil {
		t.Fatalf("RegisterHsync3RR: %v", err)
	}

	for _, tc := range []struct {
		rdata, label, upstream string
	}{
		{"ON netnod agent.netnod.example. .", "netnod", "."},
		{"ON cloudflare agent.cloudflare.example. netnod", "cloudflare", "netnod"},
		{"OFF p1 agent.p1.example. p2", "p1", "p2"},
		{"ON abcdefghijklmnop agent.x.example. a-b", "abcdefghijklmnop", "a-b"}, // 16 characters
	} {
		rr, err := dns.NewRR("zone.example. 3600 IN HSYNC3 " + tc.rdata)
		if err != nil {
			t.Errorf("%q refused: %v", tc.rdata, err)
			continue
		}
		h := rr.(*dns.PrivateRR).Data.(*HSYNC3)
		if h.Label != tc.label || h.Upstream != tc.upstream {
			t.Errorf("%q read as label %q upstream %q, want %q %q", tc.rdata, h.Label, h.Upstream, tc.label, tc.upstream)
		}

		// Wire and text round trips give the same record.
		buf := make([]byte, 256)
		n, err := h.Pack(buf)
		if err != nil {
			t.Errorf("%q: Pack: %v", tc.rdata, err)
			continue
		}
		var back HSYNC3
		if _, err := back.Unpack(buf[:n]); err != nil {
			t.Errorf("%q: Unpack: %v", tc.rdata, err)
			continue
		}
		if back != *h {
			t.Errorf("%q: wire round trip gave %+v, want %+v", tc.rdata, back, *h)
		}
		again, err := dns.NewRR("zone.example. 3600 IN HSYNC3 " + back.String())
		if err != nil {
			t.Errorf("%s does not load: %v", back.String(), err)
			continue
		}
		if got := *again.(*dns.PrivateRR).Data.(*HSYNC3); got != *h {
			t.Errorf("%q: text round trip gave %+v, want %+v", tc.rdata, got, *h)
		}
	}

	badLabels := []string{
		"netnod.",          // the dotted form earlier code produced
		"Netnod", "NETNOD", // uppercase
		"abcdefghijklmnopq", // 17 characters
		"net_nod", "net.nod", "net nod", `net"nod`, "net\x00nod",
	}

	// In presentation format.
	for _, l := range badLabels {
		var h HSYNC3
		if err := h.Parse([]string{"ON", l, "agent.example.", "."}); err == nil {
			t.Errorf("label %q accepted", l)
		}
		if err := h.Parse([]string{"ON", "fox", "agent.example.", l}); err == nil {
			t.Errorf("upstream %q accepted", l)
		}
	}

	// On the wire, and on the way out.
	for _, l := range badLabels {
		good := &HSYNC3{State: 1, Label: "fox", Identity: "agent.example.", Upstream: "."}

		badLabel := *good
		badLabel.Label = l
		badUpstream := *good
		badUpstream.Upstream = l

		for _, h := range []*HSYNC3{&badLabel, &badUpstream} {
			if _, err := h.Pack(make([]byte, 256)); err == nil {
				t.Errorf("%+v packed", *h)
			}
			wire := hsync3WireForTest(h)
			var back HSYNC3
			if _, err := back.Unpack(wire); err == nil {
				t.Errorf("%+v accepted on the wire", *h)
			}
		}
	}

	// An empty label is not a Label either.
	var h HSYNC3
	if _, err := h.Unpack(hsync3WireForTest(&HSYNC3{State: 1, Label: "", Identity: "agent.example.", Upstream: "."})); err == nil {
		t.Error("an empty label was accepted on the wire")
	}
}

// hsync3WireForTest builds HSYNC3 RDATA without Pack's checks, the way a
// sender that does not apply them would.
func hsync3WireForTest(h *HSYNC3) []byte {
	buf := make([]byte, 256)
	off := 0
	buf[off] = h.State
	off++
	off, _ = packCharacterString(h.Label, buf, off)
	off, _ = dns.PackDomainName(h.Identity, buf, off, nil, false)
	off, _ = packCharacterString(h.Upstream, buf, off)
	return buf[:off]
}
