/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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
		tcp, ok := ra.(*net.TCPAddr)
		if !ok || tcp.String() != tc.want {
			t.Errorf("remote %q: got %T %v, want *net.TCPAddr %s", tc.remote, ra, ra, tc.want)
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
}
