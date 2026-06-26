package tdns

import (
	"net"
)

// PrimaryResolveResult holds the output of resolvePrimaries.
type PrimaryResolveResult struct {
	Resolved      []PeerConf
	Unresolved    []string // as-written addr values that produced no address
	KeyCollisions []string // addr:port dropped because a duplicate carried a different key
}

// resolvePrimaries expands each as-written entry into one-or-more addr:port
// tuples, copying the per-entry key to each. A literal IP passes through
// unchanged (no lookup). Hostnames are resolved via net.LookupHost with v4
// addresses before v6. Resolved tuples are deduplicated on addr:port, keeping
// the first occurrence.
func resolvePrimaries(primaries []PeerConf) PrimaryResolveResult {
	var result PrimaryResolveResult
	seen := make(map[string]string) // addr:port -> key kept

	for _, p := range primaries {
		expanded, ok := expandPrimaryEntry(p)
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

func expandPrimaryEntry(p PeerConf) ([]PeerConf, bool) {
	host, port := splitHostPortDefault(p.Addr)
	if ip := net.ParseIP(host); ip != nil {
		return []PeerConf{{Addr: net.JoinHostPort(host, port), Key: p.Key}}, true
	}

	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return nil, false
	}

	var v4s, v6s []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			v4s = append(v4s, a)
		} else {
			v6s = append(v6s, a)
		}
	}
	ordered := append(v4s, v6s...)
	out := make([]PeerConf, 0, len(ordered))
	for _, a := range ordered {
		out = append(out, PeerConf{Addr: net.JoinHostPort(a, port), Key: p.Key})
	}
	return out, true
}

func splitHostPortDefault(addr string) (host, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "53"
	}
	return host, port
}
