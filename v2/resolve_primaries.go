package tdns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// primaryResolveTimeout bounds a single primary's IMR resolution so a dead
// name cannot stall config parsing / startup indefinitely.
const primaryResolveTimeout = 10 * time.Second

// PrimaryResolveResult holds the output of resolvePrimaries.
type PrimaryResolveResult struct {
	Resolved      []PeerConf
	Unresolved    []string // as-written addr values that produced no address
	KeyCollisions []string // addr:port dropped because a duplicate carried a different key
}

// resolvePrimaries expands each as-written entry into one-or-more addr:port
// tuples, copying the per-entry key to each. A literal IP passes through
// unchanged (no lookup). Hostnames are resolved via the in-process IMR (NOT
// the OS stub resolver), A before AAAA, so primaries resolve the same way the
// rest of tdns resolves names. Resolved tuples are deduplicated on addr:port,
// keeping the first occurrence.
func resolvePrimaries(ctx context.Context, imr *Imr, primaries []PeerConf) PrimaryResolveResult {
	var result PrimaryResolveResult
	seen := make(map[string]string) // addr:port -> key kept

	for _, p := range primaries {
		expanded, ok := expandPrimaryEntry(ctx, imr, p)
		if !ok {
			result.Unresolved = append(result.Unresolved, p.Addr)
			continue
		}
		for _, up := range expanded {
			if prevKey, exists := seen[up.Addr]; exists {
				if prevKey != up.Key {
					result.KeyCollisions = append(result.KeyCollisions, up.Addr)
				}
				continue
			}
			seen[up.Addr] = up.Key
			result.Resolved = append(result.Resolved, up)
		}
	}
	return result
}

func expandPrimaryEntry(ctx context.Context, imr *Imr, p PeerConf) ([]PeerConf, bool) {
	host, port := splitHostPortDefault(p.Addr)
	if ip := net.ParseIP(host); ip != nil {
		return []PeerConf{{Addr: net.JoinHostPort(host, port), Key: p.Key}}, true
	}

	// Hostname. Resolution is the IMR's job; without one (e.g. imr disabled)
	// the name cannot be resolved here and the entry is reported unresolved.
	if imr == nil {
		return nil, false
	}
	addrs := imrLookupAddrs(ctx, imr, host)
	if len(addrs) == 0 {
		return nil, false
	}
	lg.Info("resolved hostname primary", "hostname", host, "addresses", addrs)
	return buildUpstreams(addrs, port, p.Key), true
}

// imrLookupAddrs returns host's A and AAAA addresses resolved through the IMR,
// v4 before v6. Empty if neither type resolves (or the lookup errors/times out).
func imrLookupAddrs(ctx context.Context, imr *Imr, host string) []string {
	cctx, cancel := context.WithTimeout(ctx, primaryResolveTimeout)
	defer cancel()

	fqdn := dns.Fqdn(host)
	var addrs []string
	if rrset, err := imr.DefaultRRsetFetcher(cctx, fqdn, dns.TypeA); err == nil && rrset != nil {
		for _, rr := range rrset.RRs {
			if a, ok := rr.(*dns.A); ok {
				addrs = append(addrs, a.A.String())
			}
		}
	}
	if rrset, err := imr.DefaultRRsetFetcher(cctx, fqdn, dns.TypeAAAA); err == nil && rrset != nil {
		for _, rr := range rrset.RRs {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				addrs = append(addrs, aaaa.AAAA.String())
			}
		}
	}
	return sortV4First(addrs)
}

// sortV4First returns addrs reordered so every IPv4 literal precedes every
// IPv6 literal, preserving relative order within each family. v4-first is what
// fixes the broken-outbound-v6 case: the working family is tried first.
func sortV4First(addrs []string) []string {
	var v4s, v6s []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			v4s = append(v4s, a)
		} else {
			v6s = append(v6s, a)
		}
	}
	return append(v4s, v6s...)
}

// buildUpstreams turns resolved IP literals into addr:port PeerConfs, copying
// key to each and preserving input order.
func buildUpstreams(addrs []string, port, key string) []PeerConf {
	out := make([]PeerConf, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, PeerConf{Addr: net.JoinHostPort(a, port), Key: key})
	}
	return out
}

func splitHostPortDefault(addr string) (host, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "53"
	}
	return host, port
}

func clonePeerConfs(in []PeerConf) []PeerConf {
	if len(in) == 0 {
		return nil
	}
	out := make([]PeerConf, len(in))
	copy(out, in)
	return out
}
