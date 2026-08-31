/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The /imr API payloads and Imr methods behind `tdns-cli {imr,auth,agent}
 * imr {forward,stub} {list,status,probe}`.
 *
 * The two probes deliberately differ in side effects. The forward probe is
 * the same exchange as live traffic and RECORDS into the per-upstream
 * reachability state (counters, unreachable flag, the Upstream/ImrForward
 * aggregate), so an operator can confirm a recovery — or refresh a stale
 * DEGRADED — by probing. The stub probe is strictly REPORT-ONLY: recording a
 * probe failure into the AuthServer backoff machinery would let a diagnostic
 * poison resolution, which is exactly the failure mode of the 2026-08-11
 * stub outage (a stray query booking a backoff on the stub's only server).
 */
package tdns

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// --- forward zones ---------------------------------------------------------

// ImrForwardUpstreamInfo is the config view of one forward upstream.
type ImrForwardUpstreamInfo struct {
	Upstream      string `json:"upstream"` // "addr:port/transport"
	TLSServerName string `json:"tls_server_name,omitempty"`
	Insecure      bool   `json:"insecure,omitempty"`
}

// ImrForwardZoneInfo is the config view of one forward zone (imr-forward-list).
type ImrForwardZoneInfo struct {
	Zone      string                   `json:"zone"`
	TrustAD   bool                     `json:"trust_ad,omitempty"`
	Upstreams []ImrForwardUpstreamInfo `json:"upstreams"`
}

// ImrForwardProbeResult is one upstream's outcome of imr-forward-probe.
type ImrForwardProbeResult struct {
	Zone     string `json:"zone"`
	Upstream string `json:"upstream"`
	OK       bool   `json:"ok"`
	RTT      string `json:"rtt"`
	Error    string `json:"error,omitempty"`
}

// ForwardZoneList returns the configured forward table (config view).
func (imr *Imr) ForwardZoneList() []ImrForwardZoneInfo {
	if imr == nil {
		return nil
	}
	var out []ImrForwardZoneInfo
	for _, fz := range imr.ForwardZones() {
		info := ImrForwardZoneInfo{Zone: fz.Zone, TrustAD: fz.TrustAD}
		for _, up := range fz.Upstreams {
			info.Upstreams = append(info.Upstreams, ImrForwardUpstreamInfo{
				Upstream:      up.Label,
				TLSServerName: up.TLSServerName,
				Insecure:      up.Insecure,
			})
		}
		out = append(out, info)
	}
	return out
}

// forwardZonesMatching returns the forward zones selected by zoneFilter
// ("" = all), or an error naming the filter when nothing matches.
func (imr *Imr) forwardZonesMatching(zoneFilter string) ([]*ForwardZone, error) {
	forwards := imr.ForwardZones()
	if zoneFilter == "" {
		return forwards, nil
	}
	zf := dns.Fqdn(core.CanonicalizeName(zoneFilter))
	for _, fz := range forwards {
		if fz.Zone == zf {
			return []*ForwardZone{fz}, nil
		}
	}
	return nil, fmt.Errorf("no forward zone %q is configured", zf)
}

// probeForwardUpstream is one startup/on-demand probe: a recursive SOA query
// for the FORWARD ZONE itself, through the upstream's own client — not
// ". NS", which an upstream serving only that zone may legitimately refuse
// to resolve (a timeout there would DEGRADE a healthy zone-scoped forward).
// Records into the upstream's reachability state; the caller updates the
// aggregate error afterwards.
//
// A cancelled ctx skips the exchange and records NOTHING — shutdown is not
// evidence about the upstream. Cancellation is checked before the exchange
// only: Exchange itself is not cancellable (#435), so an in-flight probe
// still runs to the client timeout.
func (imr *Imr) probeForwardUpstream(ctx context.Context, zone string, up *ForwardUpstream) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeSOA) // RD=1 via SetQuestion
	m.SetEdns0(4096, true)
	start := time.Now()
	r, _, err := up.Client.Exchange(m, up.Addr, false)
	rtt := time.Since(start)
	if err == nil && r == nil {
		err = fmt.Errorf("nil response")
	}
	if err != nil {
		up.recordFailure(start, err)
		lgImr.Warn("forward upstream unreachable", "zone", zone, "upstream", up.Label, "err", err)
		return rtt, err
	}
	up.recordSuccess()
	lgImr.Debug("forward upstream probe ok", "zone", zone, "upstream", up.Label, "rtt", rtt)
	return rtt, nil
}

// ProbeForwardUpstreamsReport probes the selected forward zones' upstreams
// (zoneFilter "" = all) in parallel and returns the per-upstream outcome.
// Same recording semantics as the startup probe. ctx cancellation stops
// probes that have not started their exchange yet (see probeForwardUpstream).
func (imr *Imr) ProbeForwardUpstreamsReport(ctx context.Context, zoneFilter string) ([]ImrForwardProbeResult, error) {
	zones, err := imr.forwardZonesMatching(zoneFilter)
	if err != nil {
		return nil, err
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []ImrForwardProbeResult
	)
	for _, fz := range zones {
		for _, up := range fz.Upstreams {
			wg.Add(1)
			go func(zone string, up *ForwardUpstream) {
				defer wg.Done()
				rtt, err := imr.probeForwardUpstream(ctx, zone, up)
				res := ImrForwardProbeResult{
					Zone:     zone,
					Upstream: up.Label,
					OK:       err == nil,
					RTT:      rtt.Truncate(time.Millisecond).String(),
				}
				if err != nil {
					res.Error = err.Error()
				}
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}(fz.Zone, up)
		}
	}
	wg.Wait()
	imr.updateForwardUpstreamError()
	sort.Slice(results, func(i, j int) bool {
		if results[i].Zone != results[j].Zone {
			return results[i].Zone < results[j].Zone
		}
		return results[i].Upstream < results[j].Upstream
	})
	return results, nil
}

// --- stub zones ------------------------------------------------------------

// ImrStubServerInfo is the config view of one stub server.
type ImrStubServerInfo struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	Alpn  []string `json:"alpn,omitempty"`
}

// ImrStubZoneInfo is the config view of one stub zone (imr-stub-list).
type ImrStubZoneInfo struct {
	Zone    string              `json:"zone"`
	Servers []ImrStubServerInfo `json:"servers"`
}

// ImrStubServerStatus is the live view of one stub server: the per-transport
// counters the resolver has accumulated against it, and any active
// (address, transport) backoffs — the state that silently disabled stubs in
// the 2026-08-11 outage, now inspectable.
type ImrStubServerStatus struct {
	Name       string            `json:"name"`
	Addrs      []string          `json:"addrs"`
	Transports []string          `json:"transports"`
	Attempted  map[string]uint64 `json:"attempted,omitempty"`
	Used       map[string]uint64 `json:"used,omitempty"`
	Failed     map[string]uint64 `json:"failed,omitempty"`
	Truncated  uint64            `json:"truncated,omitempty"`
	Backoffs   []string          `json:"backoffs,omitempty"` // "addr/transport: until <t> (N failures)"
}

// ImrStubZoneStatus is the live view of one stub zone (imr-stub-status).
type ImrStubZoneStatus struct {
	Zone    string                `json:"zone"`
	Servers []ImrStubServerStatus `json:"servers"`
}

// ImrStubProbeResult is one (server, address, transport) outcome of
// imr-stub-probe: an RD=0 SOA query for the stub zone, reporting whether the
// server answers authoritatively.
type ImrStubProbeResult struct {
	Zone      string `json:"zone"`
	Server    string `json:"server"`
	Addr      string `json:"addr"`
	Transport string `json:"transport"`
	OK        bool   `json:"ok"` // response received, NOERROR, AA set
	Rcode     string `json:"rcode,omitempty"`
	AA        bool   `json:"aa,omitempty"`
	RTT       string `json:"rtt"`
	Error     string `json:"error,omitempty"`
}

// stubZonesMatching returns the configured stub zones selected by zoneFilter
// ("" = all), or an error naming the filter when nothing matches.
func (imr *Imr) stubZonesMatching(zoneFilter string) ([]string, error) {
	stubs := imr.StubZones()
	if zoneFilter == "" {
		return stubs, nil
	}
	zf := dns.Fqdn(core.CanonicalizeName(zoneFilter))
	for _, sz := range stubs {
		if sz == zf {
			return []string{sz}, nil
		}
	}
	return nil, fmt.Errorf("no stub zone %q is configured", zf)
}

// stubServers returns the (private, stub-specific) AuthServer instances for
// one stub zone, sorted by name for stable output.
func (imr *Imr) stubServers(zone string) []*cache.AuthServer {
	if imr.Cache == nil {
		return nil
	}
	m, ok := imr.Cache.ServerMapCopy(zone)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	servers := make([]*cache.AuthServer, 0, len(names))
	for _, name := range names {
		servers = append(servers, m[name])
	}
	return servers
}

// StubZoneList returns the configured stub table (config view).
func (imr *Imr) StubZoneList() []ImrStubZoneInfo {
	if imr == nil {
		return nil
	}
	var out []ImrStubZoneInfo
	for _, zone := range imr.StubZones() {
		info := ImrStubZoneInfo{Zone: zone}
		for _, server := range imr.stubServers(zone) {
			info.Servers = append(info.Servers, ImrStubServerInfo{
				Name:  server.Name,
				Addrs: append([]string(nil), server.Addrs...),
				Alpn:  append([]string(nil), server.Alpn...),
			})
		}
		out = append(out, info)
	}
	return out
}

// StubZoneStatus returns the live view of the configured stub zones:
// per-server transport counters and active backoffs.
func (imr *Imr) StubZoneStatus() []ImrStubZoneStatus {
	if imr == nil {
		return nil
	}
	now := time.Now()
	var out []ImrStubZoneStatus
	for _, zone := range imr.StubZones() {
		zs := ImrStubZoneStatus{Zone: zone}
		for _, server := range imr.stubServers(zone) {
			ts := server.SnapshotTransportStats()
			ss := ImrStubServerStatus{
				Name:      server.Name,
				Addrs:     append([]string(nil), server.Addrs...),
				Attempted: transportCountsToStrings(ts.Attempted),
				Used:      transportCountsToStrings(ts.Used),
				Failed:    transportCountsToStrings(ts.Failed),
				Truncated: ts.Truncated,
			}
			for _, t := range server.Transports {
				ss.Transports = append(ss.Transports, core.TransportToString[t])
			}
			backoffs := server.SnapshotAddressBackoffs(now)
			keys := make([]cache.AddrXport, 0, len(backoffs))
			for k := range backoffs {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				if keys[i].Addr != keys[j].Addr {
					return keys[i].Addr < keys[j].Addr
				}
				return keys[i].Transport < keys[j].Transport
			})
			for _, k := range keys {
				b := backoffs[k]
				ss.Backoffs = append(ss.Backoffs, fmt.Sprintf("%s/%s: until %s (%d failure(s))",
					k.Addr, core.TransportToString[k.Transport],
					b.NextTry.Format(TimeLayout), b.FailureCount))
			}
			zs.Servers = append(zs.Servers, ss)
		}
		out = append(out, zs)
	}
	return out
}

// ProbeStubServers sends an RD=0 SOA query for the stub zone to every
// (server, address, advertised transport) tuple of the selected stub zones,
// in parallel, and reports the outcome. STRICTLY report-only: nothing is
// recorded into the AuthServer state (see the file comment). ctx
// cancellation skips tuples whose exchange has not started (in-flight
// exchanges run to the client timeout, #435).
func (imr *Imr) ProbeStubServers(ctx context.Context, zoneFilter string) ([]ImrStubProbeResult, error) {
	zones, err := imr.stubZonesMatching(zoneFilter)
	if err != nil {
		return nil, err
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []ImrStubProbeResult
	)
	for _, zone := range zones {
		for _, server := range imr.stubServers(zone) {
			transports := server.Transports
			if len(transports) == 0 {
				transports = []core.Transport{core.TransportDo53}
			}
			for _, addr := range server.Addrs {
				for _, transport := range transports {
					client, ok := imr.Cache.DNSClient[transport]
					if !ok {
						continue
					}
					wg.Add(1)
					go func(zone, serverName, addr string, transport core.Transport, client core.DNSClienter) {
						defer wg.Done()
						if ctx.Err() != nil {
							return
						}
						m := new(dns.Msg)
						m.SetQuestion(zone, dns.TypeSOA)
						m.RecursionDesired = false // authoritative probe, not a recursive query
						m.SetEdns0(4096, true)
						start := time.Now()
						r, _, err := client.Exchange(m, addr, false)
						rtt := time.Since(start)
						res := ImrStubProbeResult{
							Zone:      zone,
							Server:    serverName,
							Addr:      addr,
							Transport: core.TransportToString[transport],
							RTT:       rtt.Truncate(time.Millisecond).String(),
						}
						if err == nil && r == nil {
							err = fmt.Errorf("nil response")
						}
						if err != nil {
							res.Error = err.Error()
						} else {
							res.Rcode = dns.RcodeToString[r.MsgHdr.Rcode]
							res.AA = r.MsgHdr.Authoritative
							res.OK = r.MsgHdr.Rcode == dns.RcodeSuccess && r.MsgHdr.Authoritative
						}
						mu.Lock()
						results = append(results, res)
						mu.Unlock()
					}(zone, server.Name, addr, transport, client)
				}
			}
		}
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Zone != b.Zone {
			return a.Zone < b.Zone
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Addr != b.Addr {
			return a.Addr < b.Addr
		}
		return a.Transport < b.Transport
	})
	return results, nil
}
