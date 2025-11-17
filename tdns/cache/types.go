package cache

import (
	"log"
	"sync"
	"time"
	"context"

	core "github.com/johanix/tdns/tdns/core"
	transport "github.com/johanix/tdns/tdns/transport"
)

type RRsetCacheT struct {
        RRsets    *core.ConcurrentMap[string, CachedRRset]
        Servers   *core.ConcurrentMap[string, []string]
        ServerMap *core.ConcurrentMap[string, map[string]*AuthServer] // map[zone]map[nsname]*AuthServer
        DNSClient map[core.Transport]*transport.DNSClient
        // Optional injected DNSKEY fetcher for validation; if nil, legacy path is used
        DNSKEYFetcher func(ctx context.Context, name string) (*core.RRset, error)
        // Optional injected DS getter for validation; if nil, legacy path (cache lookup) is used
        DSGetter func(name string) (rrset *core.RRset, validated bool)
        Primed   bool
        Logger   *log.Logger
        Verbose  bool
        Debug    bool
}

type CachedRRset struct {
	Name       string
	RRtype     uint16
	Rcode      uint8
	RRset      *core.RRset
	Ttl        uint32
	Context    core.CacheContext
	Validated  bool
	Expiration time.Time
}

type AuthServer struct {
	Name              string
	Addrs             []string
	Alpn              []string // {"do53", "doq", "dot", "doh"}
	Transports        []core.Transport
	PrefTransport     core.Transport
	TransportWeights  map[core.Transport]uint8 // percentage per transport
	TransportSignal   string                   `yaml:"transport" mapstructure:"transport"`
	mu                sync.Mutex
	TransportCounters map[core.Transport]uint64 // total queries attempted per transport
	Src               string                    // "answer", "glue", "hint", "priming", "stub", ...
	Expire            time.Time
}

func (as *AuthServer) SnapshotCounters() map[core.Transport]uint64 {
	as.mu.Lock()
	defer as.mu.Unlock()
	out := make(map[core.Transport]uint64, len(as.TransportCounters))

	for t, c := range as.TransportCounters {
		out[t] = c
	}
	return out
}

func (as *AuthServer) IncrementTransportCounter(t core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	if as.TransportCounters == nil {
		as.TransportCounters = make(map[core.Transport]uint64)
	}
	as.TransportCounters[t]++
	as.mu.Unlock()
}
