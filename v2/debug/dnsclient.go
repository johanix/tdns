/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// Sig0Signer signs RFC 2136 updates with a SIG(0) key loaded from the files a
// churn test provisioned (KEY RR + PEM private key). It reuses tdns's own
// CreateUpdate + SignMsg so the wire format is byte-for-byte what a tdns
// server validates.
type Sig0Signer struct {
	Zone    string
	KeyName string
	sak     *tdns.Sig0ActiveKeys
}

func LoadSig0Signer(zone, keyName, keyFile, privFile string) (*Sig0Signer, error) {
	pub, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading SIG(0) public key %s: %w", keyFile, err)
	}
	priv, err := os.ReadFile(privFile)
	if err != nil {
		return nil, fmt.Errorf("reading SIG(0) private key %s: %w", privFile, err)
	}
	pkc, err := tdns.PrepareKeyCache(string(priv), strings.TrimSpace(string(pub)))
	if err != nil {
		return nil, fmt.Errorf("preparing SIG(0) key: %w", err)
	}
	return &Sig0Signer{
		Zone:    dns.Fqdn(zone),
		KeyName: dns.Fqdn(keyName),
		sak:     &tdns.Sig0ActiveKeys{Keys: []*tdns.PrivateKeyCache{pkc}},
	}, nil
}

// Send builds, SIG(0)-signs, and sends an update; returns the response rcode.
// Falls back to TCP when the signed message exceeds the EDNS UDP limit (the
// same rule tdns's own SendUpdate uses — relevant for large PQ signatures).
func (s *Sig0Signer) Send(ctx context.Context, server string, adds, removes []dns.RR) (int, error) {
	m, err := tdns.CreateUpdate(s.Zone, adds, removes)
	if err != nil {
		return 0, err
	}
	signed, err := tdns.SignMsg(*m, s.KeyName, s.sak)
	if err != nil {
		return 0, fmt.Errorf("signing update: %w", err)
	}
	client := &dns.Client{Timeout: 5 * time.Second}
	limit := 1232
	if opt := signed.IsEdns0(); opt != nil {
		limit = int(opt.UDPSize())
	}
	if signed.Len() > limit {
		client.Net = "tcp"
	}
	r, _, err := client.ExchangeContext(ctx, signed, server)
	if err != nil {
		return 0, err
	}
	return r.Rcode, nil
}

// churnTXT builds the TXT RR for a churn record (unique owner + payload).
func churnTXT(rec ChurnRecord) (dns.RR, error) {
	return dns.NewRR(fmt.Sprintf("%s 60 IN TXT %q", rec.Owner, rec.Rdata))
}

// --- read side -------------------------------------------------------------

// querySOASerial returns the zone's current SOA serial (also a liveness probe).
func querySOASerial(ctx context.Context, server, zone string) (uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.SetEdns0(1232, false)
	c := &dns.Client{Timeout: 5 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return 0, err
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, nil
		}
	}
	return 0, fmt.Errorf("no SOA in answer for %s (rcode %s)", zone, dns.RcodeToString[r.Rcode])
}

// queryName returns whether a churn owner currently has a TXT record, and the
// record if present. It queries over UDP with an EDNS0 buffer of 1232 bytes;
// a single _churn TXT answer is far too small to truncate, so the TC path is
// unreachable here. (A dedicated TCP-query actor is a separate actor in the
// library — real traffic is a UDP/TCP mix — not a change to this UDP hammer.)
func queryName(ctx context.Context, server, owner string) (bool, ChurnRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(owner), dns.TypeTXT)
	m.SetEdns0(1232, false)
	c := &dns.Client{Timeout: 5 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return false, ChurnRecord{}, err
	}
	for _, rr := range r.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			return true, ChurnRecord{Owner: dns.Fqdn(owner), Rdata: strings.Join(txt.Txt, "")}, nil
		}
	}
	return false, ChurnRecord{}, nil
}

// axfrChurn performs an AXFR and extracts the churn records plus SOA framing.
// churnSuffix is "_churn.<zone>." — only owners within it are ledger-owned.
func axfrChurn(ctx context.Context, server, zone, churnSuffix string) (recs []ChurnRecord, openSOA, closeSOA uint32, err error) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	ch, err := tr.In(m, server)
	if err != nil {
		return nil, 0, 0, err
	}
	first := true
	sawSOA := false
	for env := range ch {
		if env.Error != nil {
			return nil, 0, 0, env.Error
		}
		for _, rr := range env.RR {
			if soa, ok := rr.(*dns.SOA); ok {
				if first {
					openSOA = soa.Serial
					first = false
				}
				closeSOA = soa.Serial
				sawSOA = true
				continue
			}
			if txt, ok := rr.(*dns.TXT); ok {
				owner := strings.ToLower(rr.Header().Name)
				if strings.HasSuffix(owner, strings.ToLower(churnSuffix)) {
					recs = append(recs, ChurnRecord{Owner: owner, Rdata: strings.Join(txt.Txt, "")})
				}
			}
		}
	}
	if !sawSOA {
		return nil, 0, 0, fmt.Errorf("AXFR of %s produced no SOA", zone)
	}
	return recs, openSOA, closeSOA, nil
}

// SignednessObs is what axfrSignedness extracts from one transfer: whether the
// zone came back signed (apex DNSKEY present and at least one RRSIG seen) and
// the serial. The reload test's I10 checker uses it to catch a signed zone
// transiently transferring UNSIGNED content during a reload re-sign window.
type SignednessObs struct {
	Serial    uint32
	HasDNSKEY bool // apex DNSKEY RRset present
	HasRRSIG  bool // at least one RRSIG anywhere in the transfer
}

// axfrSignedness performs an AXFR and reports whether the zone is served
// signed. It checks RRSIG/DNSKEY PRESENCE only, never signature validity —
// enough to catch the unsigned window and needing no algorithm support in the
// tool (miekg/dns parses RRSIG/DNSKEY RRs regardless of algorithm).
func axfrSignedness(ctx context.Context, server, zone string) (SignednessObs, error) {
	apex := dns.Fqdn(zone)
	m := new(dns.Msg)
	m.SetAxfr(apex)
	// Generous read timeout: a large PQ-signed zone (e.g. 10k SQISIGN RRSIGs) is
	// many MB and slow to transfer.
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second}
	ch, err := tr.In(m, server)
	if err != nil {
		return SignednessObs{}, err
	}
	// dns.Transfer.In has no ctx parameter and its receive loop can block up to
	// ReadTimeout (60s), so an elapsed run duration or shutdown could not
	// otherwise interrupt an in-flight AXFR. Close the connection when ctx is
	// cancelled to unblock the range below; the done channel stops the watcher
	// on the normal path.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			tr.Close()
		case <-done:
		}
	}()
	var obs SignednessObs
	sawSOA := false
	for env := range ch {
		if ctx.Err() != nil {
			return SignednessObs{}, ctx.Err()
		}
		if env.Error != nil {
			return SignednessObs{}, env.Error
		}
		for _, rr := range env.RR {
			switch v := rr.(type) {
			case *dns.SOA:
				obs.Serial = v.Serial
				sawSOA = true
			case *dns.DNSKEY:
				if strings.EqualFold(rr.Header().Name, apex) {
					obs.HasDNSKEY = true
				}
			case *dns.RRSIG:
				obs.HasRRSIG = true
			}
		}
	}
	if !sawSOA {
		return SignednessObs{}, fmt.Errorf("AXFR of %s produced no SOA", zone)
	}
	return obs, nil
}

// QuerySignednessObs is what queryApexSignedness extracts from one +dnssec
// query for the apex SOA: whether the answer carried an RRSIG covering the SOA,
// and the serial. A signed zone always has an RRSIG(SOA), so its presence is a
// crisp "the server is serving signed answers" signal. The reload test's I10
// checker cross-references it against axfrSignedness: a zone that answers
// queries signed but transfers unsigned is masking a signing failure.
type QuerySignednessObs struct {
	Serial   uint32
	HasRRSIG bool // an RRSIG(SOA) accompanied the apex SOA in the answer
}

// queryApexSignedness sends a DO-bit (+dnssec) query for the apex SOA and
// reports whether the answer carried an RRSIG covering it. It checks RRSIG
// PRESENCE only, never signature validity — enough to tell a signed answer from
// an unsigned one and needing no algorithm support in the tool (miekg/dns
// parses RRSIG regardless of algorithm). A large PQ RRSIG(SOA) overflows the
// UDP buffer, so a truncated answer is retried over TCP rather than misread as
// unsigned.
func queryApexSignedness(ctx context.Context, server, zone string) (QuerySignednessObs, error) {
	apex := dns.Fqdn(zone)
	m := new(dns.Msg)
	m.SetQuestion(apex, dns.TypeSOA)
	m.SetEdns0(1232, true) // DO bit: ask the server for DNSSEC records
	c := &dns.Client{Timeout: 5 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return QuerySignednessObs{}, err
	}
	if r.Truncated {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(ctx, m, server)
		if err != nil {
			return QuerySignednessObs{}, err
		}
	}
	var obs QuerySignednessObs
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.SOA:
			obs.Serial = v.Serial
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeSOA && strings.EqualFold(rr.Header().Name, apex) {
				obs.HasRRSIG = true
			}
		}
	}
	return obs, nil
}
