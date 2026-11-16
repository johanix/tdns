/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// do53Writer captures what the Do53 handler chain writes, from a UDP client.
type do53Writer struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *do53Writer) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *do53Writer) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5353}
}

// do53Exchange sends r through the Do53 handler chain (do53Handler), with
// the auth handler replaced by one that answers NOERROR, and returns the
// answer and whether the auth handler saw r.
func do53Exchange(t *testing.T, refuse bool, r *dns.Msg) (*dns.Msg, bool) {
	t.Helper()
	handled := false
	auth := func(w dns.ResponseWriter, r *dns.Msg) {
		handled = true
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	}
	w := &do53Writer{}
	do53Handler(refuse, auth)(w, r)
	if w.msg == nil {
		t.Fatalf("%v: nothing written", r.Question)
	}
	return w.msg, handled
}

func do53Msg(opcode int, name string, qtype, qclass uint16, edns bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Question[0].Qclass = qclass
	m.Opcode = opcode
	if edns {
		m.SetEdns0(1232, true)
	}
	return m
}

// With the option, a query over Do53 is refused with EDE 18, all but the
// transport signal and DNSKEY; every other opcode goes to the auth handler.
func TestDo53QueriesRefused(t *testing.T) {
	in := uint16(dns.ClassINET)
	for _, tc := range []struct {
		name   string
		msg    *dns.Msg
		served bool
	}{
		{"A", do53Msg(dns.OpcodeQuery, "www.example.", dns.TypeA, in, true), false},
		{"SOA", do53Msg(dns.OpcodeQuery, "example.", dns.TypeSOA, in, true), false},
		{"AXFR", do53Msg(dns.OpcodeQuery, "example.", dns.TypeAXFR, in, true), false},
		{"IXFR", do53Msg(dns.OpcodeQuery, "example.", dns.TypeIXFR, in, true), false},
		{"NS", do53Msg(dns.OpcodeQuery, "example.", dns.TypeNS, in, true), false},
		{"SVCB not at _dns", do53Msg(dns.OpcodeQuery, "svc.example.", dns.TypeSVCB, in, true), false},
		{"SVCB with _dns below the first label", do53Msg(dns.OpcodeQuery, "x._dns.example.", dns.TypeSVCB, in, true), false},
		{"TXT at _dns", do53Msg(dns.OpcodeQuery, "_dns.ns1.example.", dns.TypeTXT, in, true), false},
		{"SVCB at _dns in class CH", do53Msg(dns.OpcodeQuery, "_dns.ns1.example.", dns.TypeSVCB, dns.ClassCHAOS, true), false},
		{"CH TXT version.bind", do53Msg(dns.OpcodeQuery, "version.bind.", dns.TypeTXT, dns.ClassCHAOS, true), false},
		{"transport signal", do53Msg(dns.OpcodeQuery, "_dns.ns1.example.", dns.TypeSVCB, in, true), true},
		{"transport signal, upper case", do53Msg(dns.OpcodeQuery, "_DNS.ns1.example.", dns.TypeSVCB, in, true), true},
		{"DNSKEY", do53Msg(dns.OpcodeQuery, "example.", dns.TypeDNSKEY, in, true), true},
		{"NOTIFY", do53Msg(dns.OpcodeNotify, "example.", dns.TypeSOA, in, false), true},
		{"UPDATE", do53Msg(dns.OpcodeUpdate, "example.", dns.TypeSOA, in, false), true},
	} {
		resp, handled := do53Exchange(t, true, tc.msg)
		if handled != tc.served {
			t.Errorf("%s: reached the auth handler = %v, want %v", tc.name, handled, tc.served)
		}
		if tc.served {
			continue
		}
		if resp.Rcode != dns.RcodeRefused || resp.Authoritative {
			t.Errorf("%s: rcode %s, AA %v; want REFUSED, AA clear", tc.name, dns.RcodeToString[resp.Rcode], resp.Authoritative)
		}
		if resp.Id != tc.msg.Id || len(resp.Question) != 1 || resp.Question[0] != tc.msg.Question[0] {
			t.Errorf("%s: the refusal does not answer the query: %v", tc.name, resp.Question)
		}
		ede := refusalEDE(resp)
		if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeProhibited || !strings.Contains(ede.ExtraText, "encrypted transport") {
			t.Errorf("%s: EDE %v, want 18 (Prohibited) saying to use an encrypted transport", tc.name, ede)
		}
	}
}

// refusalEDE is the EDE in m, or nil.
func refusalEDE(m *dns.Msg) *dns.EDNS0_EDE {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			return ede
		}
	}
	return nil
}

// A query without EDNS is refused without an OPT: there is nowhere to put
// the EDE (RFC 6891 section 7).
func TestDo53QueryRefusedWithoutEDNS(t *testing.T) {
	resp, handled := do53Exchange(t, true, do53Msg(dns.OpcodeQuery, "www.example.", dns.TypeA, dns.ClassINET, false))
	if handled || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("handled %v, rcode %s; want REFUSED", handled, dns.RcodeToString[resp.Rcode])
	}
	if resp.IsEdns0() != nil {
		t.Error("the refusal of a query without EDNS carries an OPT")
	}
}

// A query with two questions is refused, even when the first is let
// through: the auth handler would answer the first.
func TestDo53QueryWithTwoQuestionsRefused(t *testing.T) {
	m := do53Msg(dns.OpcodeQuery, "_dns.ns1.example.", dns.TypeSVCB, dns.ClassINET, true)
	m.Question = append(m.Question, dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if resp, handled := do53Exchange(t, true, m); handled || resp.Rcode != dns.RcodeRefused {
		t.Errorf("handled %v, rcode %s; want REFUSED", handled, dns.RcodeToString[resp.Rcode])
	}
}

// Without the option every message reaches the auth handler, as before.
func TestDo53QueriesAnsweredWithoutTheOption(t *testing.T) {
	if _, handled := do53Exchange(t, false, do53Msg(dns.OpcodeQuery, "www.example.", dns.TypeA, dns.ClassINET, true)); !handled {
		t.Error("a query over Do53 was refused without the option")
	}
}

// The option reads as a bool; an invalid value reads as off.
func TestParseAuthOptionsDo53QueriesRefused(t *testing.T) {
	for _, tc := range []struct {
		opts []string
		on   bool
	}{
		{nil, false},
		{[]string{"debug-do53-queries-refused"}, true},
		{[]string{"debug-do53-queries-refused:true"}, true},
		{[]string{"debug-do53-queries-refused:false"}, false},
		{[]string{"debug-do53-queries-refused:yes"}, false},
	} {
		conf := &Config{}
		conf.AuthEngine.OptionsStrs = tc.opts
		conf.ParseAuthOptions()
		if got := do53QueriesRefusedConfigured(conf.AuthEngine.Options); got != tc.on {
			t.Errorf("%q: on = %v, want %v", tc.opts, got, tc.on)
		}
	}
}

// tdns-agent refuses the option, whatever its value; tdns-auth takes it.
func TestAgentRefusesDo53QueriesRefused(t *testing.T) {
	for _, val := range []string{"true", "false"} {
		opts := map[AuthOption]string{AuthOptDebugDo53QueriesRefused: val}
		err := refuseAuthOptionsForApp(AppTypeAgent, opts)
		if err == nil || !strings.Contains(err.Error(), "debug-do53-queries-refused") {
			t.Errorf("tdns-agent with the option %s: err = %v, want it refused", val, err)
		}
		if err := refuseAuthOptionsForApp(AppTypeAuth, opts); err != nil {
			t.Errorf("tdns-auth refused the option: %v", err)
		}
	}
}

// writeTestCert writes a self-signed certificate and its key into dir.
func writeTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ns1.example"},
		DNSNames:     []string{"ns1.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// The server does not start with the option unless queries have an
// encrypted transport to go to: one in listeners.transports, with a
// certificate that loads.
func TestCheckDo53QueriesRefused(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestCert(t, dir)
	broken := filepath.Join(dir, "broken.pem")
	if err := os.WriteFile(broken, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		opt        string
		transports []string
		cert, key  string
		wantErr    string
	}{
		{"option off", "", []string{"do53"}, "", "", ""},
		{"Do53 only", "debug-do53-queries-refused", []string{"do53"}, cert, key, "needs an encrypted transport"},
		{"no certificate", "debug-do53-queries-refused", []string{"do53", "dot"}, "", "", "needs listeners.certfile"},
		{"certificate does not load", "debug-do53-queries-refused", []string{"do53", "doq"}, broken, key, "certificate that loads"},
		{"missing key file", "debug-do53-queries-refused", []string{"do53", "doq"}, cert, filepath.Join(dir, "nokey.pem"), "certificate that loads"},
		{"dot with a certificate", "debug-do53-queries-refused", []string{"do53", "dot"}, cert, key, ""},
		{"doh alone with a certificate", "debug-do53-queries-refused", []string{"doh"}, cert, key, ""},
	} {
		conf := &Config{}
		if tc.opt != "" {
			conf.AuthEngine.OptionsStrs = []string{tc.opt}
		}
		conf.Listeners.Transports = tc.transports
		conf.Listeners.CertFile, conf.Listeners.KeyFile = tc.cert, tc.key
		on, err := conf.Do53QueriesRefusedCheck()
		if on != (tc.opt != "") {
			t.Errorf("%s: on = %v", tc.name, on)
		}
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v, want no error", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

// ParseConfig refuses the option without an encrypted transport, so
// tdns-auth does not start with it.
func TestParseConfigRefusesDo53QueriesRefusedWithoutEncryption(t *testing.T) {
	prev := Globals.App.Type
	Globals.App.Type = AppTypeAuth
	t.Cleanup(func() { Globals.App.Type = prev })

	loader := &Config{}
	loader.Internal.CfgFile = writeCfg(t, "listeners:\n   addresses: [ 127.0.0.1:5399 ]\n   transports: [ do53 ]\nauthengine:\n   options: [ debug-do53-queries-refused ]\n")
	err := loader.ParseConfig(false)
	if err == nil || !strings.Contains(err.Error(), "needs an encrypted transport") {
		t.Errorf("err = %v, want the option refused for want of an encrypted transport", err)
	}
}

// DnsEngine's verdict once the encrypted transports have been started: it
// stops the server when none came up.
func TestDo53QueriesRefusedStartError(t *testing.T) {
	if err := do53QueriesRefusedStartError(false, "certfile /x does not exist", nil); err == nil || !strings.Contains(err.Error(), "certfile /x") {
		t.Errorf("certificate not loaded: err = %v", err)
	}
	if err := do53QueriesRefusedStartError(true, "", nil); err == nil {
		t.Error("no encrypted transport started, and no error")
	}
	if err := do53QueriesRefusedStartError(true, "", []string{"doq"}); err != nil {
		t.Errorf("DoQ started: %v", err)
	}
}

// occupiedPort holds a TCP port on 127.0.0.1 for the test and returns it.
func occupiedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

// The encrypted engines bind before they return, and fail when no listener
// bound: DnsEngine's start check for debug-do53-queries-refused relies on
// it. A DoT or DoH listener used to bind in its goroutine, after the engine
// had returned nil.
func TestEncryptedEnginesFailWhenNoListenerBinds(t *testing.T) {
	certFile, keyFile := writeTestCert(t, t.TempDir())
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := func(w dns.ResponseWriter, r *dns.Msg) {}
	addrs := []string{"127.0.0.1"}

	if err := DnsDoTEngine(ctx, conf, addrs, []string{occupiedPort(t)}, &cert, handler, false); err == nil {
		t.Error("DoT: no error, but its only port was taken")
	}
	if err := DnsDoHEngine(ctx, conf, addrs, []string{occupiedPort(t)}, "", certFile, keyFile, handler); err == nil {
		t.Error("DoH: no error, but its only port was taken")
	}
	if err := DnsDoTEngine(ctx, conf, addrs, []string{"0"}, &cert, handler, false); err != nil {
		t.Errorf("DoT on a free port: %v", err)
	}
	if err := DnsDoHEngine(ctx, conf, addrs, []string{"0"}, "", certFile, keyFile, handler); err != nil {
		t.Errorf("DoH on a free port: %v", err)
	}
}

// A query with two questions sent to a real Do53 server gets FORMERR from
// the accept layer, as on every transport, and never reaches the handler.
func TestDo53QueryWithTwoQuestionsGetsFormerr(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	handled := false
	auth := func(w dns.ResponseWriter, r *dns.Msg) { handled = true }
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(do53Handler(true, auth)),
		MsgAcceptFunc: MsgAcceptFunc, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })

	m := do53Msg(dns.OpcodeQuery, "_dns.ns1.example.", dns.TypeSVCB, dns.ClassINET, true)
	m.Question = append(m.Question, dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	c := &dns.Client{Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeFormatError || handled {
		t.Errorf("rcode %s, handler reached %v; want FORMERR from the accept layer", dns.RcodeToString[resp.Rcode], handled)
	}
}
