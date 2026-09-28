/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// dohWriterFrom is the writer the DoH engine builds for a request from remote.
func dohWriterFrom(t *testing.T, remote string, msg *dns.Msg) *dohResponseWriter {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, DefaultDoHPath, nil)
	req.RemoteAddr = remote
	return newDoHResponseWriter(new(bytes.Buffer), req, msg)
}

func queryMsg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeSOA)
	return m
}

// The DoH writer used to report every client as 127.0.0.1:443. It now reports
// the address the HTTP request came from, and the listener's address, and a
// fixed stand-in only when the HTTP layer gave nothing readable.
func TestDoHWriterReportsTheClientsAddress(t *testing.T) {
	for _, tc := range []struct {
		remote string
		want   string // "" = the unreadable stand-in
	}{
		{"192.0.2.7:51234", "192.0.2.7:51234"},
		{"[2001:db8::7]:4430", "[2001:db8::7]:4430"},
		{"not-an-address", ""},
	} {
		w := dohWriterFrom(t, tc.remote, queryMsg())
		ra := w.RemoteAddr()
		if tc.want == "" {
			if _, ok := ra.(dummyAddr); !ok {
				t.Errorf("remote %q: got %T %v, want the stand-in", tc.remote, ra, ra)
			}
			if _, ok := peerIP(ra.String()); ok {
				t.Errorf("remote %q: the stand-in %q parses as an address; authorization by address must fail on it", tc.remote, ra)
			}
			continue
		}
		if _, ok := ra.(dohPeerAddr); !ok || ra.String() != tc.want {
			t.Errorf("remote %q: got %T %v, want the DoH peer %s", tc.remote, ra, ra, tc.want)
		}
		if src, ok := peerIP(ra.String()); !ok || src.String() != strings.Trim(tc.want[:strings.LastIndex(tc.want, ":")], "[]") {
			t.Errorf("remote %q: peerIP(%q) = %v, %v; want the client's address", tc.remote, ra, src, ok)
		}
	}

	req := httptest.NewRequest(http.MethodPost, DefaultDoHPath, nil)
	local := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, local))
	if got := newDoHResponseWriter(new(bytes.Buffer), req, queryMsg()).LocalAddr(); got != local {
		t.Errorf("LocalAddr: got %v, want the listener's %v", got, local)
	}
}

// A NOTIFY over DoH from elsewhere used to be judged as coming from
// 127.0.0.1, so it passed an allow-notify entry meant for a primary on the
// same host.
func TestDoHNotifyFromElsewhereIsNotTakenForLoopback(t *testing.T) {
	zd := &ZoneData{AllowNotify: []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY}}}
	notify := new(dns.Msg)
	notify.SetNotify("example.test.")

	if ok, _, _, reason := zd.authorizeInboundNotify(dohWriterFrom(t, "192.0.2.7:51234", notify), notify); ok {
		t.Errorf("NOTIFY over DoH from 192.0.2.7 accepted by allow-notify 127.0.0.1 (reason %q)", reason)
	}
	if ok, _, _, reason := zd.authorizeInboundNotify(dohWriterFrom(t, "127.0.0.1:51234", notify), notify); !ok {
		t.Errorf("NOTIFY over DoH from 127.0.0.1 refused: %s", reason)
	}
	// A peer the HTTP layer gave in no readable form must not match the
	// loopback entry either: authorization by address fails on it.
	if ok, _, _, _ := zd.authorizeInboundNotify(dohWriterFrom(t, "not-an-address", notify), notify); ok {
		t.Error("NOTIFY over DoH from an unparseable peer accepted by allow-notify 127.0.0.1")
	}
}

// The client is the HTTP connection's peer. A header naming another address
// (X-Forwarded-For, as a proxy would add, or anyone else could) is not taken
// for it: trusting a proxy is a decision the DoH listener does not make.
func TestDoHIgnoresXForwardedFor(t *testing.T) {
	zd := &ZoneData{AllowNotify: []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY}}}
	notify := new(dns.Msg)
	notify.SetNotify("example.test.")

	req := httptest.NewRequest(http.MethodPost, DefaultDoHPath, nil)
	req.RemoteAddr = "192.0.2.7:51234"
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		req.Header.Set(h, "127.0.0.1")
	}
	req.Header.Set("Forwarded", "for=127.0.0.1")
	w := newDoHResponseWriter(new(bytes.Buffer), req, notify)

	if got := w.RemoteAddr().String(); got != "192.0.2.7:51234" {
		t.Errorf("RemoteAddr %q, want the HTTP peer 192.0.2.7:51234", got)
	}
	if ok, _, _, reason := zd.authorizeInboundNotify(w, notify); ok {
		t.Errorf("NOTIFY over DoH from 192.0.2.7 claiming X-Forwarded-For 127.0.0.1 accepted by allow-notify 127.0.0.1 (reason %q)", reason)
	}
}

// DoH and DoQ verify no TSIG, so a signed request must not look verified. A nil
// TsigStatus used to say it was, and a request naming an approved key with any
// MAC at all passed checkInboundTSIG and the transfer ACL.
func TestSignedRequestOverDoHOrDoQIsNotVerified(t *testing.T) {
	signed := signedMsg("k")
	for name, w := range map[string]dns.ResponseWriter{
		"DoH": dohWriterFrom(t, "192.0.2.7:51234", signed),
		"DoQ": &doqResponseWriter{tsig: signed.IsTsig() != nil},
	} {
		if err := w.TsigStatus(); !errors.Is(err, errTsigUnverified) {
			t.Errorf("%s: TsigStatus of a signed request = %v, want errTsigUnverified", name, err)
		}
		if err := checkInboundTSIG(w, signed, []string{"k"}); err == nil {
			t.Errorf("%s: an unverified TSIG under the approved key passed checkInboundTSIG", name)
		}
	}

	// Unsigned requests are unaffected: miekg also reports nil for them.
	for name, w := range map[string]dns.ResponseWriter{
		"DoH": dohWriterFrom(t, "192.0.2.7:51234", queryMsg()),
		"DoQ": &doqResponseWriter{},
	} {
		if err := w.TsigStatus(); err != nil {
			t.Errorf("%s: TsigStatus of an unsigned request = %v, want nil", name, err)
		}
	}
}

// The transfer ACL: an entry that requires key k must not match a DoH request
// that merely names k.
func TestTransferOverDoHNeedsAVerifiedTSIG(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.test.", Downstreams: []AclEntry{{Prefix: "0.0.0.0/0", Key: "k"}}}
	axfr := new(dns.Msg)
	axfr.SetAxfr("example.test.")
	axfr.SetTsig("k.", dns.HmacSHA256, 300, 0)

	if err := zd.authorizeTransfer(context.Background(), dohWriterFrom(t, "192.0.2.7:51234", axfr), axfr, nil); err == nil {
		t.Error("an AXFR over DoH naming key k with an unchecked MAC was authorized")
	}
}

// The transfer ACL's twin of the NOTIFY test: a downstream entry for 127.0.0.1
// must not match a DoH request from elsewhere.
func TestDoHTransferFromElsewhereIsNotTakenForLoopback(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.test.", Downstreams: []AclEntry{{Prefix: "127.0.0.1/32", Key: NOKEY}}}
	axfr := new(dns.Msg)
	axfr.SetAxfr("example.test.")

	if err := zd.authorizeTransfer(context.Background(), dohWriterFrom(t, "192.0.2.7:51234", axfr), axfr, nil); err == nil {
		t.Error("an AXFR over DoH from 192.0.2.7 was authorized by downstream 127.0.0.1")
	}
	if err := zd.authorizeTransfer(context.Background(), dohWriterFrom(t, "127.0.0.1:51234", axfr), axfr, nil); err != nil {
		t.Errorf("an AXFR over DoH from 127.0.0.1 was refused by downstream 127.0.0.1: %v", err)
	}
}
