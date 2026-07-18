/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// FakeDNSClient is a programmable DNSClienter for tests. Lookup precedence on
// Exchange: exact (qname, server) → qname-only → server-only → default ("",
// ""). If no entry matches, Exchange returns an error.
type FakeDNSClient struct {
	mu        sync.Mutex
	transport Transport
	Responses map[FakeKey]FakeResponse
	QueryLog  []FakeQuery
}

// FakeKey is the lookup key into FakeDNSClient.Responses. Either Qname or
// Addr (or both) may be empty to install a wildcard match.
type FakeKey struct {
	Qname string
	Addr  string
}

// FakeResponse is a programmed Exchange outcome.
type FakeResponse struct {
	Msg *dns.Msg
	RTT time.Duration
	Err error
}

// FakeQuery is a record of an Exchange call (appended in order).
type FakeQuery struct {
	Qname     string
	Addr      string
	Transport Transport
	At        time.Time
}

// NewFakeDNSClient creates a FakeDNSClient that reports itself as transport t.
func NewFakeDNSClient(t Transport) *FakeDNSClient {
	return &FakeDNSClient{
		transport: t,
		Responses: make(map[FakeKey]FakeResponse),
	}
}

// TransportKind satisfies DNSClienter.
func (f *FakeDNSClient) TransportKind() Transport { return f.transport }

// Exchange satisfies DNSClienter by serving a programmed response.
func (f *FakeDNSClient) Exchange(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var qname string
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
	}
	f.QueryLog = append(f.QueryLog, FakeQuery{
		Qname:     qname,
		Addr:      server,
		Transport: f.transport,
		At:        time.Now(),
	})
	if r, ok := f.Responses[FakeKey{Qname: qname, Addr: server}]; ok {
		return r.Msg, r.RTT, r.Err
	}
	if r, ok := f.Responses[FakeKey{Qname: qname}]; ok {
		return r.Msg, r.RTT, r.Err
	}
	if r, ok := f.Responses[FakeKey{Addr: server}]; ok {
		return r.Msg, r.RTT, r.Err
	}
	if r, ok := f.Responses[FakeKey{}]; ok {
		return r.Msg, r.RTT, r.Err
	}
	return nil, 0, fmt.Errorf("FakeDNSClient: no programmed response for %s @ %s", qname, server)
}

// ExchangeWithResult satisfies DNSClienter. The fake performs no real UDP->TCP
// fallback; it reports its own transport as the wire transport, and flags a
// truncation (with a Do53TCP wire transport) when a programmed Do53 response
// has the TC bit set — enough to exercise truncation-stat paths in tests.
func (f *FakeDNSClient) ExchangeWithResult(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, ExchangeResult, error) {
	r, rtt, err := f.Exchange(msg, server, debug)
	res := ExchangeResult{WireTransport: f.transport}
	if err == nil && r != nil && r.Truncated && (f.transport == TransportDo53 || f.transport == TransportDo53TCP) {
		res.WireTransport = TransportDo53TCP
		res.Truncated = true
	}
	return r, rtt, res, err
}

// Set installs a response. Convenience wrapper around direct map assignment.
func (f *FakeDNSClient) Set(qname, addr string, resp FakeResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Responses[FakeKey{Qname: qname, Addr: addr}] = resp
}

// Calls returns a copy of the query log.
func (f *FakeDNSClient) Calls() []FakeQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FakeQuery, len(f.QueryLog))
	copy(out, f.QueryLog)
	return out
}
