package tdns

import (
	"context"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// End to end: real miekg clients signing with TSIG, over TCP and UDP, against
// a server built as do53.go builds it (keystore provider, tdns's
// MsgAcceptFunc, TsigSigningHandler around the real dispatch), the real
// UpdateHandler, and the real ZoneUpdater on a primary zone with a KeyDB
// behind it. Assertions read the published zone, which is what queries and
// transfers see. The message shapes are those of three kinds of real client:
//
//   - a dynamic-DNS updater: delete the RRset and add, in one message, and
//     deletes of things that are not there;
//   - an ACME client in lego's style: over UDP, RemoveRRset + Insert of the
//     challenge TXT, then a Remove of that one value;
//   - an ACME client in certbot's style: over TCP, a plain add (which keeps
//     other values) and a delete of one value.

type tsigE2E struct {
	zd      *ZoneData
	tcpAddr string
	udpAddr string
	secrets map[string]string // key name -> base64 secret
}

const e2eSecret = "MTIzNDU2Nzg5MDEyMzQ1Ng=="

func startTsigE2E(t *testing.T) *tsigE2E {
	t.Helper()
	withAppType(t, AppTypeAuth)
	zd, kdb := updaterZoneWithRealKeyDB(t, Primary, map[ZoneOption]bool{OptAllowTsigUpdates: true})
	zd.UpdatePolicy = UpdatePolicy{
		Zone: UpdatePolicyDetail{Type: "none", RRtypes: map[uint16]bool{}, TTL: 120},
		TsigGrants: mustGrants(t, zd.ZoneName,
			TsigGrantConf{Key: "ddns.", NameType: "zonesub", RRtypes: []string{"ANY"}},
			TsigGrantConf{Key: "h1.example.test.", NameType: "self", RRtypes: []string{"A"}},
		),
	}

	conf := &Config{}
	conf.Keys.Tsig = []TsigDetails{
		{Name: "ddns.", Algorithm: "hmac-sha256", Secret: e2eSecret},
		{Name: "h1.example.test.", Algorithm: "hmac-sha256", Secret: e2eSecret},
		{Name: "nogrant.", Algorithm: "hmac-sha256", Secret: e2eSecret},
	}
	if err := conf.LoadTsigKeys(); err != nil {
		t.Fatalf("LoadTsigKeys: %v", err)
	}
	conf.Internal.DnsUpdateQ = make(chan DnsUpdateRequest, 8)
	conf.Internal.UpdateQ = kdb.UpdateQ

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = kdb.ZoneUpdaterEngine(ctx) }()
	go func() { _ = UpdateHandler(ctx, conf) }()

	handler := dns.HandlerFunc(TsigSigningHandler(udpTruncate(createAuthDnsHandler(ctx, conf))))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	for _, srv := range []*dns.Server{
		{Listener: l, Net: "tcp", TsigProvider: conf.tsigProvider(), MsgAcceptFunc: MsgAcceptFunc, Handler: handler},
		{PacketConn: pc, TsigProvider: conf.tsigProvider(), MsgAcceptFunc: MsgAcceptFunc, Handler: handler},
	} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func(s *dns.Server) { _ = s.ActivateAndServe() }(srv)
		t.Cleanup(func() { _ = srv.Shutdown() })
		<-started
	}
	return &tsigE2E{zd: zd, tcpAddr: l.Addr().String(), udpAddr: pc.LocalAddr().String(),
		secrets: map[string]string{"ddns.": e2eSecret, "h1.example.test.": e2eSecret, "nogrant.": e2eSecret}}
}

func e2eRRs(t *testing.T, ss ...string) []dns.RR {
	t.Helper()
	var out []dns.RR
	for _, s := range ss {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("NewRR %q: %v", s, err)
		}
		out = append(out, rr)
	}
	return out
}

// send signs m with key (secret from the server's own table unless secret is
// given) and exchanges it. The client verifies the response TSIG, so a nil
// error on a signed request means the answer was signed correctly.
func (e *tsigE2E) send(t *testing.T, net, key, secret string, m *dns.Msg) (*dns.Msg, error) {
	t.Helper()
	if secret == "" {
		secret = e.secrets[key]
	}
	m.SetTsig(key, dns.HmacSHA256, 300, time.Now().Unix())
	addr := e.tcpAddr
	if net == "udp" {
		addr = e.udpAddr
	}
	c := &dns.Client{Net: net, TsigSecret: map[string]string{key: secret}, Timeout: 10 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	return resp, err
}

func (e *tsigE2E) mustSend(t *testing.T, net, key string, m *dns.Msg, want int) {
	t.Helper()
	resp, err := e.send(t, net, key, "", m)
	if err != nil {
		t.Fatalf("%s/%s: exchange: %v", net, key, err)
	}
	if resp.Rcode != want {
		_, ede, _ := edns0.ExtractEDEFromMsg(resp)
		t.Fatalf("%s/%s: rcode %s (EDE %d), want %s", net, key, dns.RcodeToString[resp.Rcode], ede, dns.RcodeToString[want])
	}
	if resp.IsTsig() == nil {
		t.Fatalf("%s/%s: answer not TSIG-signed", net, key)
	}
}

// published returns the rdata of owner's rrtype in the served zone, sorted,
// and the RRset's TTL.
func (e *tsigE2E) published(owner string, rrtype uint16) ([]string, uint32) {
	snap := e.zd.publishedSnapshot()
	if snap == nil {
		return nil, 0
	}
	od := getOwnerFrom(snap, owner)
	if od == nil {
		return nil, 0
	}
	rs, ok := od.RRtypes.Get(rrtype)
	if !ok {
		return nil, 0
	}
	var out []string
	var ttl uint32
	for _, rr := range rs.RRs {
		f := strings.Fields(rr.String())
		out = append(out, strings.Join(f[4:], " "))
		ttl = rr.Header().Ttl
	}
	sort.Strings(out)
	return out, ttl
}

func upd(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate(zone)
	return m
}

func TestTsigUpdateEndToEnd(t *testing.T) {
	e := startTsigE2E(t)
	zone := e.zd.ZoneName

	t.Run("dynamic-DNS updater: delete RRset and add, TCP", func(t *testing.T) {
		m := upd(zone)
		m.RemoveRRset(e2eRRs(t, "host1.example.test. 0 IN A 0.0.0.0", "host1.example.test. 0 IN AAAA ::"))
		m.Insert(e2eRRs(t, "host1.example.test. 60 IN A 192.0.2.10", "host1.example.test. 60 IN SSHFP 4 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
		e.mustSend(t, "tcp", "ddns.", m, dns.RcodeSuccess)
		got, ttl := e.published("host1.example.test.", dns.TypeA)
		if len(got) != 1 || got[0] != "192.0.2.10" {
			t.Errorf("host1 A = %v", got)
		}
		if ttl != 120 {
			t.Errorf("host1 A TTL = %d, want the zone policy's 120 (the client asked for 60)", ttl)
		}
		if got, _ := e.published("host1.example.test.", dns.TypeSSHFP); len(got) != 1 {
			t.Errorf("host1 SSHFP = %v", got)
		}

		m = upd(zone)
		m.RemoveRRset(e2eRRs(t, "host1.example.test. 0 IN A 0.0.0.0"))
		m.Insert(e2eRRs(t, "host1.example.test. 60 IN A 192.0.2.11"))
		e.mustSend(t, "tcp", "ddns.", m, dns.RcodeSuccess)
		if got, _ := e.published("host1.example.test.", dns.TypeA); len(got) != 1 || got[0] != "192.0.2.11" {
			t.Errorf("host1 A after replace = %v", got)
		}
	})

	t.Run("deletes of what is not there answer NOERROR", func(t *testing.T) {
		m := upd(zone)
		m.RemoveRRset(e2eRRs(t, "nohost.example.test. 0 IN A 0.0.0.0"))
		e.mustSend(t, "tcp", "ddns.", m, dns.RcodeSuccess)
		m = upd(zone)
		m.Remove(e2eRRs(t, `ports.example.test. 60 IN TXT "never-there"`))
		e.mustSend(t, "tcp", "ddns.", m, dns.RcodeSuccess)
	})

	t.Run("lego style: RemoveRRset+Insert TXT, then Remove, UDP", func(t *testing.T) {
		const name = "_acme-challenge.www.example.test."
		m := upd(zone)
		m.RemoveRRset(e2eRRs(t, name+` 0 IN TXT ""`))
		m.Insert(e2eRRs(t, name+` 120 IN TXT "lego-token"`))
		e.mustSend(t, "udp", "ddns.", m, dns.RcodeSuccess)
		if got, _ := e.published(name, dns.TypeTXT); len(got) != 1 || got[0] != `"lego-token"` {
			t.Fatalf("challenge TXT = %v", got)
		}
		m = upd(zone)
		m.Remove(e2eRRs(t, name+` 120 IN TXT "lego-token"`))
		e.mustSend(t, "udp", "ddns.", m, dns.RcodeSuccess)
		if got, _ := e.published(name, dns.TypeTXT); len(got) != 0 {
			t.Errorf("challenge TXT after cleanup = %v", got)
		}
	})

	t.Run("certbot style: add keeps other values, delete one value, TCP", func(t *testing.T) {
		const name = "_acme-challenge.example.test."
		for _, v := range []string{"one", "two"} {
			m := upd(zone)
			m.Insert(e2eRRs(t, name+` 10 IN TXT "`+v+`"`))
			e.mustSend(t, "tcp", "ddns.", m, dns.RcodeSuccess)
		}
		if got, _ := e.published(name, dns.TypeTXT); len(got) != 2 {
			t.Fatalf("two adds: TXT = %v", got)
		}
		m := upd(zone)
		m.Remove(e2eRRs(t, name+` 10 IN TXT "one"`))
		e.mustSend(t, "tcp", "ddns.", m, dns.RcodeSuccess)
		if got, _ := e.published(name, dns.TypeTXT); len(got) != 1 || got[0] != `"two"` {
			t.Errorf("after deleting one value: TXT = %v", got)
		}
	})

	t.Run("self grant", func(t *testing.T) {
		m := upd(zone)
		m.Insert(e2eRRs(t, "h1.example.test. 60 IN A 192.0.2.21"))
		e.mustSend(t, "tcp", "h1.example.test.", m, dns.RcodeSuccess)
		if got, _ := e.published("h1.example.test.", dns.TypeA); len(got) != 1 {
			t.Errorf("h1 A = %v", got)
		}
		m = upd(zone)
		m.Insert(e2eRRs(t, "h2.example.test. 60 IN A 192.0.2.22"))
		e.mustSend(t, "tcp", "h1.example.test.", m, dns.RcodeRefused)
		if got, _ := e.published("h2.example.test.", dns.TypeA); len(got) != 0 {
			t.Errorf("a refused self update changed h2: %v", got)
		}
	})

	t.Run("refused: key without a grant, narrow ANY", func(t *testing.T) {
		m := upd(zone)
		m.Insert(e2eRRs(t, "x.example.test. 60 IN A 192.0.2.30"))
		e.mustSend(t, "tcp", "nogrant.", m, dns.RcodeRefused)
		m = upd(zone)
		m.Insert(e2eRRs(t, "example.test. 60 IN CDS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
		e.mustSend(t, "tcp", "ddns.", m, dns.RcodeRefused)
		if got, _ := e.published("x.example.test.", dns.TypeA); len(got) != 0 {
			t.Errorf("x A = %v", got)
		}
		if got, _ := e.published("example.test.", dns.TypeCDS); len(got) != 0 {
			t.Errorf("apex CDS = %v", got)
		}
	})

	t.Run("refused at the TSIG layer: unknown key, bad MAC", func(t *testing.T) {
		before := e.zd.CurrentSerial
		for _, c := range []struct {
			key, secret string
			tsigErr     uint16
		}{
			{"unknown.", e2eSecret, dns.RcodeBadKey},
			{"ddns.", "YWJjZGVmZ2hpamtsbW5vcA==", dns.RcodeBadSig},
		} {
			m := upd(zone)
			m.Insert(e2eRRs(t, "y.example.test. 60 IN A 192.0.2.40"))
			resp, _ := e.send(t, "tcp", c.key, c.secret, m) // miekg's client reports ErrAuth for any NOTAUTH
			if resp == nil || resp.Rcode != dns.RcodeNotAuth {
				t.Errorf("key %s: response %v, want NOTAUTH", c.key, resp)
				continue
			}
			if ts := resp.IsTsig(); ts == nil || ts.Error != c.tsigErr {
				t.Errorf("key %s: TSIG error %v, want %d", c.key, ts, c.tsigErr)
			}
		}
		if e.zd.CurrentSerial != before {
			t.Error("the zone changed on a request whose TSIG failed")
		}
	})

	t.Run("DELNAME under an ANY grant", func(t *testing.T) {
		m := upd(zone)
		m.RemoveName(e2eRRs(t, "host1.example.test. 0 IN A 0.0.0.0"))
		e.mustSend(t, "tcp", "ddns.", m, dns.RcodeSuccess)
		for _, rt := range []uint16{dns.TypeA, dns.TypeSSHFP} {
			if got, _ := e.published("host1.example.test.", rt); len(got) != 0 {
				t.Errorf("host1 %s after DELNAME = %v", dns.TypeToString[rt], got)
			}
		}
	})
}
