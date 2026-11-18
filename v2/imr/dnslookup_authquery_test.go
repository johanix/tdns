/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// AuthDNSQuery, both the function and the Imr's, asks over UDP with a 4096-byte
// buffer. A reply with TC set is not an answer: what it carries is some of
// what the server would say, or none of it, and an empty one read as "no data"
// (#998). Post-quantum DNSKEY RRsets are what take a reply past the buffer.
//
// The double below is an authoritative server on loopback, one port for UDP and
// TCP. What it answers is chosen by the first label of the name asked, and
// every name in tcZone has three A records when the answer is whole:
//
//	plain      whole over UDP
//	nodata     NOERROR, an SOA, no records: an answer in itself
//	emptytc    UDP: TC set and nothing else.   TCP: whole
//	partialtc  UDP: TC set and one of the three. TCP: whole
//	cuttc      UDP: TC set, and the packet ends inside the third record. TCP: whole
//	cutplain   UDP: the packet ends inside the third record, TC not set
//	tcpcut     UDP: TC set and nothing else.   TCP: the packet ends inside the third record
//	tcboth     TC set over UDP and over TCP
const tcZone = "tc.test."

const tcWhole = 3 // the A records of a whole answer

type tcDouble struct {
	mu   sync.Mutex
	udp  map[string]int // first label of the name asked -> queries over UDP
	tcp  map[string]int // the same over TCP
	addr string         // host:port, the port of both transports
}

func (d *tcDouble) queries(overTCP bool, label string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if overTCP {
		return d.tcp[label]
	}
	return d.udp[label]
}

func (d *tcDouble) serve(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	label := dns.SplitDomainName(q.Name)[0]
	_, overTCP := w.RemoteAddr().(*net.TCPAddr)
	d.mu.Lock()
	if overTCP {
		d.tcp[label]++
	} else {
		d.udp[label]++
	}
	d.mu.Unlock()

	a := func(i int) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, byte(i)),
		}
	}
	whole := func(m *dns.Msg) {
		for i := 1; i <= tcWhole; i++ {
			m.Answer = append(m.Answer, a(i))
		}
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	switch label {
	case "plain":
		whole(m)
	case "nodata":
		m.Ns = append(m.Ns, &dns.SOA{
			Hdr: dns.RR_Header{Name: tcZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns." + tcZone, Mbox: "hostmaster." + tcZone,
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
		})
	case "emptytc":
		if overTCP {
			whole(m)
		} else {
			m.Truncated = true
		}
	case "partialtc":
		if overTCP {
			whole(m)
		} else {
			m.Truncated = true
			m.Answer = append(m.Answer, a(1))
		}
	case "cuttc":
		if overTCP {
			whole(m)
			break
		}
		m.Truncated = true
		whole(m)
		wire, err := m.Pack()
		if err != nil {
			return
		}
		// five bytes: the last record's data, and a byte of its header
		_, _ = w.Write(wire[:len(wire)-5])
		return
	case "cutplain":
		whole(m)
		wire, err := m.Pack()
		if err != nil {
			return
		}
		_, _ = w.Write(wire[:len(wire)-5])
		return
	case "tcpcut":
		if !overTCP {
			m.Truncated = true
			break
		}
		whole(m)
		wire, err := m.Pack()
		if err != nil {
			return
		}
		// over TCP the length prefix is the packet's, so cut before it is added
		_, _ = w.Write(wire[:len(wire)-5])
		return
	case "tcboth":
		m.Truncated = true
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

// startTCDouble starts the double; without withTCP nothing listens on its TCP
// port, so a connection is refused.
func startTCDouble(t *testing.T, withTCP bool) *tcDouble {
	t.Helper()
	d := &tcDouble{udp: map[string]int{}, tcp: map[string]int{}}
	mux := dns.NewServeMux()
	mux.HandleFunc(tcZone, d.serve)

	// the same port number for both: take a TCP port and the UDP one beside it
	var ln net.Listener
	var pc net.PacketConn
	for i := 0; ; i++ {
		var err error
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		if pc, err = net.ListenPacket("udp", ln.Addr().String()); err == nil {
			break
		}
		_ = ln.Close()
		if i == 50 {
			t.Fatalf("no port free for both UDP and TCP: %v", err)
		}
	}
	d.addr = ln.Addr().String()

	servers := []*dns.Server{{PacketConn: pc, Handler: mux}}
	if withTCP {
		servers = append(servers, &dns.Server{Listener: ln, Handler: mux})
	} else {
		_ = ln.Close()
	}
	for _, srv := range servers {
		started := make(chan struct{})
		served := make(chan error, 1)
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { served <- srv.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("auth double did not start")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.ShutdownContext(ctx); err != nil {
				t.Errorf("auth double shutdown: %v", err)
			}
			select {
			case err := <-served:
				if err != nil {
					t.Errorf("auth double serve: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("auth double serve goroutine did not exit")
			}
		})
	}
	return d
}

// tcWriter sends what a logger writes to the test's log.
type tcWriter struct{ t *testing.T }

func (w tcWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// tcResult is what an AuthDNSQuery says of an A query. cached is the Imr's
// cache entry for it afterwards, nil for the function, which has no cache.
type tcResult struct {
	rrs    int
	rcode  int
	err    error
	cached *cache.CachedRRset
}

// tcAsk asks addrs for name's A RRset.
type tcAsk func(t *testing.T, name string, addrs []string, verbose bool) tcResult

// tcAskers are the two AuthDNSQuery, by name.
var tcAskers = []struct {
	name string
	ask  tcAsk
}{
	{"AuthDNSQuery", func(t *testing.T, name string, addrs []string, verbose bool) tcResult {
		lg := log.New(tcWriter{t}, "", 0)
		rrset, rcode, err := AuthDNSQuery(name, lg, addrs, dns.TypeA, verbose)
		res := tcResult{rcode: rcode, err: err}
		if rrset != nil {
			res.rrs = len(rrset.RRs)
		}
		return res
	}},
	{"Imr.AuthDNSQuery", func(t *testing.T, name string, addrs []string, verbose bool) tcResult {
		lg := log.New(tcWriter{t}, "", 0)
		imr := newTestImr(t)
		rrset, rcode, _, err := imr.AuthDNSQuery(context.Background(), name, dns.TypeA, addrs, lg, verbose)
		res := tcResult{rcode: rcode, err: err, cached: imr.Cache.Peek(name, dns.TypeA)}
		if rrset != nil {
			res.rrs = len(rrset.RRs)
		}
		return res
	}},
}

// cachedRRs is how many records the cache holds for the answer, 0 for none.
func (r tcResult) cachedRRs() int {
	if r.cached == nil || r.cached.RRset == nil {
		return 0
	}
	return len(r.cached.RRset.RRs)
}

// A reply with TC set is asked again over TCP, and the TCP reply is the answer:
// nothing of the truncated one is kept, not its records and not their absence.
// One truncated over TCP too, or that no TCP reaches, is no answer at all.
func TestAuthDNSQueryTruncated(t *testing.T) {
	cases := []struct {
		label   string
		rrs     int  // records the answer holds
		wantErr bool // no server has answered
		tcp     int  // queries over TCP the double saw
	}{
		{"plain", tcWhole, false, 0},
		{"nodata", 0, false, 0},
		{"emptytc", tcWhole, false, 1},
		{"partialtc", tcWhole, false, 1},
		{"cuttc", tcWhole, false, 1},
		{"cutplain", 0, true, 0},
		{"tcpcut", 0, true, 1},
		{"tcboth", 0, true, 1},
	}
	for _, f := range tcAskers {
		for _, verbose := range []bool{false, true} {
			for _, c := range cases {
				t.Run(fmt.Sprintf("%s/verbose=%t/%s", f.name, verbose, c.label), func(t *testing.T) {
					d := startTCDouble(t, true)
					res := f.ask(t, c.label+"."+tcZone, []string{d.addr}, verbose)

					if res.rrs != c.rrs {
						t.Errorf("%d records in the answer, want %d", res.rrs, c.rrs)
					}
					if (res.err != nil) != c.wantErr {
						t.Errorf("error %v, want an error: %t", res.err, c.wantErr)
					}
					if got := d.queries(false, c.label); got != 1 {
						t.Errorf("%d queries over UDP, want 1", got)
					}
					if got := d.queries(true, c.label); got != c.tcp {
						t.Errorf("%d queries over TCP, want %d", got, c.tcp)
					}
					if f.name == "Imr.AuthDNSQuery" && !c.wantErr && c.rrs > 0 {
						if got := res.cachedRRs(); got != c.rrs {
							t.Errorf("the cache holds %d records, want %d", got, c.rrs)
						}
					}
					if f.name == "Imr.AuthDNSQuery" && c.wantErr && res.cached != nil {
						t.Errorf("an answer nobody gave is in the cache: %+v", res.cached)
					}
				})
			}
		}
	}
}

// A server that cannot be asked over TCP has not answered: the next is asked.
func TestAuthDNSQueryTruncatedNoTCP(t *testing.T) {
	for _, f := range tcAskers {
		for _, verbose := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/verbose=%t", f.name, verbose), func(t *testing.T) {
				first := startTCDouble(t, false)
				name := "emptytc." + tcZone

				res := f.ask(t, name, []string{first.addr}, verbose)
				if res.err == nil || res.rrs != 0 {
					t.Errorf("one server, no TCP: %d records, error %v; want no records and an error", res.rrs, res.err)
				}
				if res.cached != nil {
					t.Errorf("an answer nobody gave is in the cache: %+v", res.cached)
				}

				second := startTCDouble(t, true)
				res = f.ask(t, name, []string{first.addr, second.addr}, verbose)
				if res.err != nil || res.rrs != tcWhole {
					t.Errorf("then a second server: %d records, error %v; want %d and none", res.rrs, res.err, tcWhole)
				}
				if got := second.queries(true, "emptytc"); got != 1 {
					t.Errorf("%d queries over TCP to the second server, want 1", got)
				}
			})
		}
	}
}
