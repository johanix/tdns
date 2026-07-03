package tdns

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const testXfrSecret = "MTIzNDU2Nzg5MDEyMzQ1Ng=="

type axfrTestServer struct {
	addr     string
	sizes    []int
	shutdown func()
}

func (s *axfrTestServer) recordSize(m *dns.Msg) {
	if packed, err := m.Pack(); err == nil {
		s.sizes = append(s.sizes, len(packed))
	}
}

func startTestAXFRServerTSIG(t *testing.T, zd *ZoneData, conf *Config) *axfrTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &axfrTestServer{addr: ln.Addr().String()}
	zone := dns.Fqdn(zd.ZoneName)
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		rec := &recordingResponseWriter{
			ResponseWriter: w,
			record:         srv.recordSize,
		}
		handler := TsigSigningHandler(func(w2 dns.ResponseWriter, req *dns.Msg) {
			_, _ = zd.ZoneTransferOut(w2, req)
		})
		handler(rec, r)
	})

	started := make(chan struct{})
	dnsSrv := &dns.Server{
		Listener:          ln,
		Handler:           mux,
		TsigProvider:      conf.tsigProvider(),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test AXFR server did not start")
	}
	srv.shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = dnsSrv.ShutdownContext(ctx)
	}
	return srv
}

func startTestAXFRServer(t *testing.T, zd *ZoneData) *axfrTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &axfrTestServer{addr: ln.Addr().String()}
	zone := dns.Fqdn(zd.ZoneName)
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		rec := &recordingResponseWriter{
			ResponseWriter: w,
			record:         srv.recordSize,
		}
		_, _ = zd.ZoneTransferOut(rec, r)
	})

	started := make(chan struct{})
	dnsSrv := &dns.Server{
		Listener:          ln,
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test AXFR server did not start")
	}
	srv.shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = dnsSrv.ShutdownContext(ctx)
	}
	return srv
}

type recordingResponseWriter struct {
	dns.ResponseWriter
	record func(*dns.Msg)
}

func (w *recordingResponseWriter) WriteMsg(m *dns.Msg) error {
	if w.record != nil {
		w.record(m)
	}
	return w.ResponseWriter.WriteMsg(m)
}

func loadTestTransferZone(t *testing.T, zoneData string) *ZoneData {
	t.Helper()
	const zone = "example.test."
	zd := &ZoneData{
		ZoneName:  zone,
		ZoneStore: MapZone,
		ZoneType:  Primary,
		Logger:    log.Default(),
		Ready:     true,
		Status:    ZoneStatusReady,
		Downstreams: []AclEntry{{
			Prefix: "127.0.0.0/8",
			Key:    NOKEY,
		}},
	}
	if _, _, err := zd.ReadZoneData(zoneData, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true
	zd.Status = ZoneStatusReady
	return zd
}

func testXfrConf(t *testing.T) *Config {
	t.Helper()
	conf := &Config{}
	conf.Keys.Tsig = []TsigDetails{{Name: "tkey", Algorithm: "hmac-sha256", Secret: testXfrSecret}}
	if err := conf.LoadTsigKeys(); err != nil {
		t.Fatalf("LoadTsigKeys: %v", err)
	}
	return conf
}

func axfrClientTSIG(t *testing.T, conf *Config, addr, zone, keyName string) ([]dns.RR, error) {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetAxfr(zone)
	provider, err := SignForPeer(msg, keyName, conf)
	if err != nil {
		t.Fatalf("SignForPeer: %v", err)
	}
	tr := &dns.Transfer{TsigProvider: provider}
	ch, err := tr.In(msg, addr)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return rrs, env.Error
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs, nil
}

func assertTransferEnvelopeSizes(t *testing.T, sizes []int) {
	t.Helper()
	if len(sizes) < 2 {
		t.Fatalf("expected multiple envelopes, got %d", len(sizes))
	}
	for i, sz := range sizes {
		if sz > dnsMaxMessageSize {
			t.Fatalf("envelope %d size %d exceeds DNS max %d", i, sz, dnsMaxMessageSize)
		}
		if sz > safeMessageSize {
			t.Fatalf("envelope %d size %d exceeds safe limit %d", i, sz, safeMessageSize)
		}
	}
}

func largeApexZone(typeCount, byteLen int) string {
	var b strings.Builder
	b.WriteString(`
$ORIGIN example.test.
@ IN SOA ns.example.test. hostmaster.example.test. (
	1 ; serial
	3600 ; refresh
	600 ; retry
	86400 ; expire
	60 ; minimum
)
@ IN NS ns.example.test.
ns IN A 192.0.2.1
`)
	payload := hex.EncodeToString(make([]byte, byteLen))
	const apexSynthBase = 65350 // unassigned private-use types (avoid tdns core RR types)
	for i := 0; i < typeCount; i++ {
		fmt.Fprintf(&b, "@ 60 TYPE%d \\# %d %s\n", apexSynthBase+i, byteLen, payload)
	}
	b.WriteString("www IN A 192.0.2.2\n")
	return b.String()
}

func axfrClient(t *testing.T, addr, zone string) ([]dns.RR, error) {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetAxfr(zone)
	tr := new(dns.Transfer)
	ch, err := tr.In(msg, addr)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return rrs, env.Error
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs, nil
}

const basicZone = `
$ORIGIN example.test.
@ IN SOA ns.example.test. hostmaster.example.test. (
	1 ; serial
	3600 ; refresh
	600 ; retry
	86400 ; expire
	60 ; minimum
)
@ IN NS ns.example.test.
ns IN A 192.0.2.1
www IN A 192.0.2.2
`

func TestZoneTransferOut_RoundTrip(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if len(rrs) < 4 {
		t.Fatalf("expected at least 4 RRs (SOA bookends + data), got %d", len(rrs))
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Fatalf("first RR should be SOA, got %T", rrs[0])
	}
	if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
		t.Fatalf("last RR should be SOA, got %T", rrs[len(rrs)-1])
	}
	for i, sz := range srv.sizes {
		if sz > dnsMaxMessageSize {
			t.Fatalf("envelope %d size %d exceeds DNS max %d", i, sz, dnsMaxMessageSize)
		}
		if sz > safeMessageSize {
			t.Fatalf("envelope %d size %d exceeds safe limit %d", i, sz, safeMessageSize)
		}
	}
}

func TestZoneTransferOut_LargeZoneSpansEnvelopes(t *testing.T) {
	var b strings.Builder
	b.WriteString(`
$ORIGIN example.test.
@ IN SOA ns.example.test. hostmaster.example.test. (
	1 ; serial
	3600 ; refresh
	600 ; retry
	86400 ; expire
	60 ; minimum
)
@ IN NS ns.example.test.
`)
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&b, "pad%d IN TXT \"%s\"\n", i, strings.Repeat("x", 900))
	}
	b.WriteString("www IN A 192.0.2.2\n")

	zd := loadTestTransferZone(t, b.String())
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if len(rrs) < 82 {
		t.Fatalf("expected many RRs, got %d", len(rrs))
	}
	if len(srv.sizes) < 2 {
		t.Fatalf("expected multiple envelopes, got %d", len(srv.sizes))
	}
	assertTransferEnvelopeSizes(t, srv.sizes)
}

// TestZoneTransferOut_LargeApexSpansEnvelopes is the regression for fix (b): many
// large RRsets at the zone apex must batch through maybeFlushBatch instead of
// accumulating in the first envelope (the old PQ-apex overflow).
func TestZoneTransferOut_LargeApexSpansEnvelopes(t *testing.T) {
	zd := loadTestTransferZone(t, largeApexZone(10, 9000))

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if len(rrs) < 12 {
		t.Fatalf("expected apex SOA bookends plus apex RRsets, got %d RRs", len(rrs))
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Fatalf("first RR should be SOA, got %T", rrs[0])
	}
	assertTransferEnvelopeSizes(t, srv.sizes)
}

// TestZoneTransferOut_TSIGLargeApexEnvelopeSizes checks every TSIG-signed envelope
// on a multi-envelope apex transfer stays under cap (question + TSIG headroom).
func TestZoneTransferOut_TSIGLargeApexEnvelopeSizes(t *testing.T) {
	conf := testXfrConf(t)
	zd := loadTestTransferZone(t, largeApexZone(10, 9000))
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}

	srv := startTestAXFRServerTSIG(t, zd, conf)
	defer srv.shutdown()

	rrs, err := axfrClientTSIG(t, conf, srv.addr, zd.ZoneName, "tkey")
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if len(rrs) < 12 {
		t.Fatalf("expected many RRs, got %d", len(rrs))
	}
	assertTransferEnvelopeSizes(t, srv.sizes)
}

func hugeTXT(name string, total int) *dns.TXT {
	var chunks []string
	for remaining := total; remaining > 0; {
		n := 255
		if remaining < n {
			n = remaining
		}
		chunks = append(chunks, strings.Repeat("x", n))
		remaining -= n
	}
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Txt: chunks,
	}
}

func TestZoneTransferOut_OversizeRRsetAborts(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	txt := hugeTXT("big.example.test.", 65000)
	od := OwnerData{
		Name:    "big.example.test.",
		RRtypes: NewRRTypeStore(),
	}
	od.RRtypes.Set(dns.TypeTXT, core.RRset{
		Name:   "big.example.test.",
		Class:  dns.ClassINET,
		RRtype: dns.TypeTXT,
		RRs:    []dns.RR{txt},
	})
	zd.Data.Set("big.example.test.", od)

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	_, err := axfrClient(t, srv.addr, zd.ZoneName)
	if err == nil {
		t.Fatal("expected transfer to fail on oversize RRset")
	}
}

func TestZoneTransferOut_ClientDisconnect(t *testing.T) {
	var b strings.Builder
	b.WriteString(`
$ORIGIN example.test.
@ IN SOA ns.example.test. hostmaster.example.test. (
	1 ; serial
	3600 ; refresh
	600 ; retry
	86400 ; expire
	60 ; minimum
)
@ IN NS ns.example.test.
`)
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "host%d IN A 192.0.2.1\n", i)
	}
	zd := loadTestTransferZone(t, b.String())

	handlerDone := make(chan struct{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	zone := dns.Fqdn(zd.ZoneName)
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		defer close(handlerDone)
		_, _ = zd.ZoneTransferOut(w, r)
	})
	started := make(chan struct{})
	dnsSrv := &dns.Server{
		Listener:          ln,
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test AXFR server did not start")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = dnsSrv.ShutdownContext(ctx)
	}()

	msg := new(dns.Msg)
	msg.SetAxfr(zd.ZoneName)
	tr := new(dns.Transfer)
	ch, err := tr.In(msg, ln.Addr().String())
	if err != nil {
		t.Fatalf("Transfer.In: %v", err)
	}
	if _, ok := <-ch; !ok {
		t.Fatal("expected at least one envelope before disconnect")
	}

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish after client stopped reading")
	}
}

func TestZoneTransferOut_RefusesWhenNotReady(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	zd.Status = ZoneStatusLoading
	w := &fakeRW{remote: udpAddr("127.0.0.1")}
	r := new(dns.Msg)
	r.SetAxfr(zd.ZoneName)
	sent, err := zd.ZoneTransferOut(w, r)
	if err != nil {
		t.Fatalf("ZoneTransferOut: %v", err)
	}
	if sent != 0 {
		t.Fatalf("expected 0 RRs sent, got %d", sent)
	}
	if w.written == nil || w.written.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got %v", w.written)
	}
}

// TestZoneTransferOut_TSIGRoundTrip exercises AXFR over TCP with TSIG on both
// request and response envelopes (production uses TsigSigningHandler + TsigProvider).
func TestZoneTransferOut_TSIGRoundTrip(t *testing.T) {
	conf := testXfrConf(t)
	zd := loadTestTransferZone(t, basicZone)
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}

	srv := startTestAXFRServerTSIG(t, zd, conf)
	defer srv.shutdown()

	rrs, err := axfrClientTSIG(t, conf, srv.addr, zd.ZoneName, "tkey")
	if err != nil {
		t.Fatalf("Transfer.In: %v", err)
	}
	if len(rrs) < 4 {
		t.Fatalf("expected at least 4 RRs, got %d", len(rrs))
	}
}
