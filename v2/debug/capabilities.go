/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

// Package debug is the library behind the tdns-debug test tool. It is a pure
// client: everything here talks to a target server over standard DNS or the
// tdns mgmt API. This package must never be linked into a production binary
// (enforced by a CI depcheck, not just convention).
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// CapStatus is the probe verdict for one capability. Per the design doc (§5):
// an absent capability disables its actors and checks (reported as SKIPPED),
// it never produces a violation or aborts a run.
type CapStatus string

const (
	CapAvailable CapStatus = "available"
	CapAbsent    CapStatus = "absent"
	CapDegraded  CapStatus = "degraded" // worked at probe time, failed mid-run
	CapUnknown   CapStatus = "unknown"
)

// Capability names. These are the keys actors declare in Actor.Requires().
const (
	CapDns          = "dns"                // pure DNS reachability (query/UPDATE/AXFR)
	CapApi          = "mgmt-api"           // the mgmt API answers at all
	CapZoneBump     = "zone-bump"          // POST /zone Command=bump
	CapZoneResign   = "zone-resign"        // POST /zone Command=resign-zone
	CapDebugTxlog   = "debug-zone-txlog"   // POST /debug Command=zone-txlog (snapshot branch)
	CapNone         = ""                   // actor needs nothing beyond pure DNS
)

type Capability struct {
	Name   string    `json:"name"`
	Status CapStatus `json:"status"`
	Detail string    `json:"detail,omitempty"`
}

// CapabilityMatrix is the startup probe result. It is printed at the head of
// every run and included verbatim in the report, so a green run against a
// limited target cannot masquerade as full coverage.
type CapabilityMatrix struct {
	Target    string       `json:"target"`
	DnsServer string       `json:"dns_server,omitempty"`
	Probed    time.Time    `json:"probed"`
	Endpoints []string     `json:"api_endpoints,omitempty"`
	Caps      []Capability `json:"capabilities"`
}

func (m *CapabilityMatrix) set(name string, status CapStatus, detail string) {
	for i := range m.Caps {
		if m.Caps[i].Name == name {
			m.Caps[i].Status = status
			m.Caps[i].Detail = detail
			return
		}
	}
	m.Caps = append(m.Caps, Capability{Name: name, Status: status, Detail: detail})
}

func (m *CapabilityMatrix) Get(name string) CapStatus {
	for _, c := range m.Caps {
		if c.Name == name {
			return c.Status
		}
	}
	return CapUnknown
}

func (m *CapabilityMatrix) Available(name string) bool {
	return name == CapNone || m.Get(name) == CapAvailable
}

// Degrade marks a capability that failed mid-run (probe said available). The
// checkers that depend on it are tainted, not failed.
func (m *CapabilityMatrix) Degrade(name, detail string) {
	m.set(name, CapDegraded, detail)
}

// Render prints the matrix in a compact human-readable form.
func (m *CapabilityMatrix) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Capability matrix for target %q", m.Target)
	if m.DnsServer != "" {
		fmt.Fprintf(&b, " (dns %s)", m.DnsServer)
	}
	fmt.Fprintf(&b, ":\n")
	for _, c := range m.Caps {
		fmt.Fprintf(&b, "  %-18s %-10s %s\n", c.Name, c.Status, c.Detail)
	}
	return b.String()
}

// ProbeZone is a name that can never exist on any target: probing a
// multiplexed API command against it proves whether the *command* exists
// ("unknown command" vs "zone not found") without any side effect. This is
// what makes probing mutating commands like "zone bump" safe.
const ProbeZone = "_tdns-debug-probe.invalid."

// probeResp is a deliberately minimal mirror of the tdns API response shape:
// decoding into it works against any server version (unknown fields ignored,
// missing fields zero) — the same mirror-type strategy as txlog_view.go.
type probeResp struct {
	Error        bool
	ErrorMsg     string
	Msg          string
	ApiEndpoints []string
}

// ClassifyCommandProbe implements the §5 classification rule for a
// command-level probe against ProbeZone:
//   - transport error / HTTP-level failure → endpoint (or API) absent
//   - structured "Unknown ... command" error → endpoint exists, command absent
//   - anything else (zone-not-found error, or success) → command available
func ClassifyCommandProbe(httpStatus int, transportErr error, respError bool, errorMsg string) (CapStatus, string) {
	if transportErr != nil {
		return CapAbsent, fmt.Sprintf("transport: %v", transportErr)
	}
	if httpStatus == 404 {
		return CapAbsent, "endpoint not found (404)"
	}
	if httpStatus != 200 {
		return CapAbsent, fmt.Sprintf("http status %d", httpStatus)
	}
	if respError && strings.Contains(errorMsg, "Unknown") && strings.Contains(errorMsg, "command") {
		return CapAbsent, errorMsg
	}
	if respError {
		// An error *about the probe zone* (not about the command) proves the
		// command is routed and handled.
		return CapAvailable, fmt.Sprintf("probed (%s)", errorMsg)
	}
	return CapAvailable, "probed"
}

// apiProbe sends one multiplexed command probe and classifies the result.
func apiProbe(ctx context.Context, api *tdns.ApiClient, endpoint string, payload any) (CapStatus, string) {
	status, buf, err := api.RequestNGWithContext(ctx, "POST", endpoint, payload, false)
	var pr probeResp
	if err == nil && len(buf) > 0 {
		_ = json.Unmarshal(buf, &pr) // best-effort; zero values classify fine
	}
	return ClassifyCommandProbe(status, err, pr.Error, pr.ErrorMsg)
}

// ProbeApi probes the mgmt API of one target: walker first (endpoint list),
// then a command-level probe per capability the actors may need. All probes
// are side-effect-free by construction (ProbeZone cannot exist).
func ProbeApi(ctx context.Context, targetName string, api *tdns.ApiClient) *CapabilityMatrix {
	m := &CapabilityMatrix{Target: targetName, Probed: time.Now()}

	if api == nil {
		m.set(CapApi, CapAbsent, "no API client configured for target")
		for _, c := range []string{CapZoneBump, CapZoneResign, CapDebugTxlog} {
			m.set(c, CapAbsent, "no mgmt API")
		}
		return m
	}

	// Endpoint-level: the built-in API walker.
	status, buf, err := api.RequestNGWithContext(ctx, "POST", "/command",
		tdns.CommandPost{Command: "api"}, false)
	var pr probeResp
	if err == nil && len(buf) > 0 {
		_ = json.Unmarshal(buf, &pr)
	}
	if err != nil || status != 200 {
		detail := fmt.Sprintf("http status %d", status)
		if err != nil {
			detail = err.Error()
		}
		m.set(CapApi, CapAbsent, detail)
		for _, c := range []string{CapZoneBump, CapZoneResign, CapDebugTxlog} {
			m.set(c, CapAbsent, "mgmt API unreachable")
		}
		return m
	}
	m.set(CapApi, CapAvailable, fmt.Sprintf("%d endpoints announced", len(pr.ApiEndpoints)))
	m.Endpoints = pr.ApiEndpoints

	// Command-level: the walker cannot see through the inline Command:
	// multiplexing, so probe the actual commands against ProbeZone.
	st, detail := apiProbe(ctx, api, "/zone", tdns.ZonePost{Command: "bump", Zone: ProbeZone})
	m.set(CapZoneBump, st, detail)

	st, detail = apiProbe(ctx, api, "/zone", tdns.ZonePost{Command: "resign-zone", Zone: ProbeZone})
	m.set(CapZoneResign, st, detail)

	st, detail = apiProbe(ctx, api, "/debug", tdns.DebugPost{Command: "zone-txlog", Zone: ProbeZone})
	m.set(CapDebugTxlog, st, detail)

	return m
}

// ProbeDns checks plain-DNS reachability of the target (SOA query for zone,
// or for "." if no zone is known yet). Any parseable DNS response — including
// REFUSED — proves a DNS server is listening.
func ProbeDns(ctx context.Context, m *CapabilityMatrix, server, zone string) {
	m.DnsServer = server
	if zone == "" {
		zone = "."
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	c := &dns.Client{Timeout: 3 * time.Second}
	r, _, err := c.ExchangeContext(ctx, q, server)
	if err != nil {
		m.set(CapDns, CapAbsent, err.Error())
		return
	}
	m.set(CapDns, CapAvailable, fmt.Sprintf("%s for %s SOA", dns.RcodeToString[r.Rcode], zone))
}
