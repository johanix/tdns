/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A bootstrap offers the parent a key that the parent then looks for in DNS:
// at the child's apex, and at the signal names under the child's nameservers.
// A KEY there that is not the offered one is a verdict the parent does not
// revisit (judgeChildKeyAnswer). So the child offers a new key only once the
// zone's nameservers serve it (#917).
//
// The child used to bootstrap in the same second it handed the key to
// publication: it asked the parent, heard "unknown", and sent the bootstrap.
// A zone that still published its previous key had that key looked up at a
// nameserver that had not yet taken the new one, and the parent refused every
// later update signed with the new key.

// keyServedState is what one look at the zone's nameservers found.
type keyServedState int

const (
	// keyServed: every nameserver that answered serves the key at the apex,
	// and no signal name serves another KEY.
	keyServed keyServedState = iota
	// keyNotServedYet: a nameserver serves the apex without the key, or a
	// signal name serves another KEY. The parent would find that now.
	keyNotServedYet
	// keyServedUnknown: nothing could be looked at, the zone's nameservers
	// not known or none of them answering. Waiting would not change what the
	// child can tell, so the bootstrap is not held for it.
	keyServedUnknown
)

// keyServedPace is how the child waits for its key to be served before it
// bootstraps it: a first look at once, then again after first, doubling up to
// max, and at most limit in all. After limit the bootstrap goes ahead all the
// same, as it did before the wait, so a nameserver that never takes the key
// delays the bootstrap and does not stop it.
type keyServedPace struct {
	first, max, limit time.Duration
}

// keyServedWait is the pace in use. A variable so a test need not wait out
// the real one.
var keyServedWait = keyServedPace{first: 2 * time.Second, max: 30 * time.Second, limit: 10 * time.Minute}

// keyServedCheck looks at what the zone's nameservers serve of the key the
// child is about to offer. The lookups are fields so a test can answer them.
type keyServedCheck struct {
	zone  string
	keyRR string // the offered key, as the bootstrap hands it to the parent
	// nameservers is the zone's NS RRset, as this server holds the zone.
	nameservers func() ([]string, error)
	// addresses is where one nameserver is reached, as host:port.
	addresses func(ctx context.Context, ns string) []string
	// askServer asks one server for the KEY RRset at qname. An authoritative
	// answer that there is none is an empty answer, not an error.
	askServer func(ctx context.Context, qname, addr string) ([]dns.RR, error)
	// askFresh asks through the resolver past its cache, the way the parent
	// asks for a signal name (childKeyQuery).
	askFresh func(ctx context.Context, qname string) ([]dns.RR, error)
}

// look asks every address of every nameserver of the zone for the KEY at the
// apex, and the resolver for the KEY at each nameserver's signal name.
//
// The apex is asked of each server, not through the resolver: the parent's
// fresh lookup may reach any one of them, and the one it reaches decides.
// A server that does not answer is left out, since the parent cannot get an
// answer from it either.
//
// A signal name is not the child's to publish, and need not carry the key at
// all: the parent finds nothing there and looks again. Only another KEY there
// holds the bootstrap.
func (c keyServedCheck) look(ctx context.Context) (keyServedState, string) {
	nsNames, err := c.nameservers()
	if err != nil {
		return keyServedUnknown, fmt.Sprintf("the zone's nameservers are not known: %v", err)
	}
	if len(nsNames) == 0 {
		return keyServedUnknown, "the zone has no NS RRset"
	}
	apex := dns.Fqdn(c.zone)
	var without, silent []string
	answered := 0
	for _, ns := range nsNames {
		addrs := c.addresses(ctx, ns)
		if len(addrs) == 0 {
			silent = append(silent, ns+" (no address)")
			continue
		}
		for _, addr := range addrs {
			rrs, err := c.askServer(ctx, apex, addr)
			if err != nil {
				silent = append(silent, fmt.Sprintf("%s (%s): %v", ns, addr, err))
				continue
			}
			answered++
			if !matchKeyRR(rrs, c.keyRR) {
				without = append(without, fmt.Sprintf("%s (%s)", ns, addr))
			}
		}
	}
	if answered == 0 {
		return keyServedUnknown, "no nameserver of the zone answered: " + strings.Join(silent, "; ")
	}
	if len(without) > 0 {
		return keyServedNotYet(without, silent, "serves the apex without the key")
	}

	var other []string
	for _, ns := range nsNames {
		name := signalOwnerName(signalPrefixSig0Key, c.zone, ns)
		rrs, err := c.askFresh(ctx, name)
		if err != nil || len(rrs) == 0 {
			continue
		}
		if !matchKeyRR(rrs, c.keyRR) {
			other = append(other, name)
		}
	}
	if len(other) > 0 {
		return keyServedNotYet(other, nil, "serves another KEY")
	}
	return keyServed, fmt.Sprintf("%d nameserver addresses serve the key at the apex", answered)
}

func keyServedNotYet(where, silent []string, what string) (keyServedState, string) {
	why := strings.Join(where, ", ") + " " + what
	if len(silent) > 0 {
		why += "; no answer from " + strings.Join(silent, "; ")
	}
	return keyNotServedYet, why
}

// waitUntilKeyServed holds a bootstrap until look finds the key served, or
// finds nothing to look at, or the pace's limit has passed. It returns false
// only when ctx ends first.
func waitUntilKeyServed(ctx context.Context, zone ZoneName, keyid uint16, look func(context.Context) (keyServedState, string),
	wait func(context.Context, time.Duration) bool, pace keyServedPace) bool {
	delay, waited := pace.first, time.Duration(0)
	for {
		state, why := look(ctx)
		if ctx.Err() != nil {
			// A look cut short by the shutdown finds nothing to look at; that
			// is not "nothing to look at".
			return false
		}
		switch {
		case state == keyServed:
			lgElect.Info("ParentSyncAfterKeyPublication: the zone's nameservers serve our key; bootstrapping",
				"zone", zone, "keyid", keyid, "waited", waited, "detail", why)
			return true
		case state == keyServedUnknown:
			lgElect.Warn("ParentSyncAfterKeyPublication: cannot tell whether the zone's nameservers serve our key; bootstrapping",
				"zone", zone, "keyid", keyid, "detail", why)
			return true
		case waited >= pace.limit:
			lgElect.Warn("ParentSyncAfterKeyPublication: the zone's nameservers still do not all serve our key; bootstrapping all the same",
				"zone", zone, "keyid", keyid, "waited", waited, "detail", why)
			return true
		case waited == 0:
			lgElect.Info("ParentSyncAfterKeyPublication: waiting for the zone's nameservers to serve our key before bootstrapping",
				"zone", zone, "keyid", keyid, "detail", why)
		default:
			lgElect.Debug("ParentSyncAfterKeyPublication: our key is not served yet",
				"zone", zone, "keyid", keyid, "waited", waited, "detail", why)
		}
		if !wait(ctx, delay) {
			return false
		}
		waited += delay
		delay = min(2*delay, pace.max)
	}
}

// imrKeyServedCheck is the check for zone's key keyRR in a running server:
// the zone's NS RRset from this server's copy of the zone, their addresses and
// the signal names through the IMR, and the apex asked of each address.
func imrKeyServedCheck(imr *Imr, zone, keyRR string) keyServedCheck {
	return keyServedCheck{
		zone:  zone,
		keyRR: keyRR,
		nameservers: func() ([]string, error) {
			zd, ok := Zones.Get(zone)
			if !ok || zd == nil {
				return nil, fmt.Errorf("zone %s is not held here", zone)
			}
			rrset, err := zd.GetRRset(zd.ZoneName, dns.TypeNS)
			if err != nil {
				return nil, err
			}
			var out []string
			if rrset != nil {
				for _, rr := range rrset.RRs {
					if ns, ok := rr.(*dns.NS); ok {
						out = append(out, ns.Ns)
					}
				}
			}
			return out, nil
		},
		addresses: func(ctx context.Context, ns string) []string {
			var out []string
			for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				resp, err := imr.ImrQuery(ctx, ns, rrtype, dns.ClassINET, nil)
				if err != nil || resp == nil || resp.RRset == nil {
					continue
				}
				for _, rr := range resp.RRset.RRs {
					switch rr := rr.(type) {
					case *dns.A:
						out = append(out, net.JoinHostPort(rr.A.String(), "53"))
					case *dns.AAAA:
						out = append(out, net.JoinHostPort(rr.AAAA.String(), "53"))
					}
				}
			}
			return out
		},
		askServer: askServerForKey,
		askFresh: func(ctx context.Context, qname string) ([]dns.RR, error) {
			resp, err := childKeyQuery(ctx, imr, qname)
			switch {
			case err != nil:
				return nil, err
			case resp == nil:
				return nil, errors.New("no answer")
			case resp.Error:
				return nil, errors.New(resp.ErrorMsg)
			case resp.RRset == nil:
				return nil, nil
			}
			return resp.RRset.RRs, nil
		},
	}
}

// askServerForKey asks one server for the KEY RRset at qname, over TCP, and
// takes only an authoritative answer: NOERROR with the records, or with none,
// or NXDOMAIN.
func askServerForKey(ctx context.Context, qname, addr string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeKEY)
	m.RecursionDesired = false
	c := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if !r.Authoritative {
		return nil, errors.New("not an authoritative answer")
	}
	switch r.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
	}
	var out []dns.RR
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeKEY && core.EqualNames(rr.Header().Name, qname) {
			out = append(out, rr)
		}
	}
	return out, nil
}
