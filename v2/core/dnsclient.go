/*
 * Copyright (c) 2024, 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Transport represents the DNS transport protocol
type Transport uint8

const (
	TransportDo53 Transport = iota + 1
	TransportDoT
	TransportDoH
	TransportDoQ
	// TransportDo53TCP is an internal transport: plain DNS over TCP only.
	// Not selectable via config; used when parent DS signals a large algorithm.
	TransportDo53TCP
)

var TransportToString = map[Transport]string{
	TransportDo53:    "do53",
	TransportDoT:     "dot",
	TransportDoH:     "doh",
	TransportDoQ:     "doq",
	TransportDo53TCP: "do53-tcp",
}

// StringToTransport converts a string transport name to Transport type
func StringToTransport(s string) (Transport, error) {
	switch s {
	case "do53", "Do53":
		return TransportDo53, nil
	case "do53-tcp", "Do53-TCP":
		return TransportDo53TCP, nil
	case "tcp", "TCP":
		return TransportDo53TCP, nil
	case "dot", "DoT", "DoT-TCP":
		return TransportDoT, nil
	case "doh", "DoH", "DoH-TCP":
		return TransportDoH, nil
	case "doq", "DoQ", "DoQ-TCP":
		return TransportDoQ, nil
	default:
		return TransportDo53, fmt.Errorf("unknown transport: %s", s)
	}
}

// IsEncryptedTransport returns true if the transport is encrypted (doq, dot, doh), false for do53
func IsEncryptedTransport(t Transport) bool {
	return t == TransportDoT || t == TransportDoH || t == TransportDoQ
}

// DNSClienter abstracts a single network exchange so callers can be tested
// with a fake. The concrete *DNSClient implements it.
//
// Note on Exchange not taking a context.Context: CodeRabbit suggested
// adding one so callers can cancel mid-exchange. Deliberately not done.
// Exchange is a single network round-trip bounded by c.Timeout
// (default 5s), and DoQ's internal context is already derived from
// that timeout. Cancellation at the layer above — tryServer checks
// ctx.Done() before the call, and the W2 query budget on
// IterativeDNSQuery bounds the wider walk — is enough in practice
// and avoids threading ctx through ~50 call sites for negligible
// benefit. If a use case ever appears where mid-Exchange
// cancellation matters (very long DoH bodies?), an ExchangeContext
// variant can be added without breaking this interface.
type DNSClienter interface {
	Exchange(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, error)
	ExchangeWithResult(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, ExchangeResult, error)
	TransportKind() Transport
}

// DNSClient represents a DNS client that supports multiple transport protocols
type DNSClient struct {
	Port            string
	Transport       Transport
	TLSConfig       *tls.Config
	HTTPClient      *http.Client
	QUICConfig      *quic.Config
	Timeout         time.Duration
	DNSClientUDP    *dns.Client
	DNSClientTCP    *dns.Client
	DNSClientTLS    *dns.Client
	DisableFallback bool
	ForceTCP        bool
}

type DNSClientOption func(*DNSClient)

func WithDisableFallback() DNSClientOption {
	return func(c *DNSClient) {
		c.DisableFallback = true
	}
}

func WithForceTCP() DNSClientOption {
	return func(c *DNSClient) {
		c.ForceTCP = true
	}
}

// WithTsigSecret enables TSIG on the underlying miekg clients (Do53 / Do53-TCP /
// DoT). A query signed with msg.SetTsig(keyname, algo, ...) is then MAC'd on
// send, and the response's TSIG is verified on receive, using the base64 secret
// looked up by keyname. keyname is canonicalised to an FQDN to match the wire
// key name. No effect on DoH/DoQ, which use non-dns.Client transports.
func WithTsigSecret(keyname, secret string) DNSClientOption {
	return func(c *DNSClient) {
		m := map[string]string{dns.Fqdn(keyname): secret}
		for _, cl := range []*dns.Client{c.DNSClientUDP, c.DNSClientTCP, c.DNSClientTLS} {
			if cl != nil {
				cl.TsigSecret = m
			}
		}
	}
}

// NewDNSClient creates a new DNS client with the specified transport
// XXX: Once we can do cert validation we should add a WithVerifyCertificates() option.
func NewDNSClient(transport Transport, port string, tlsConfig *tls.Config, opts ...DNSClientOption) *DNSClient {
	if tlsConfig == nil {
		switch transport {
		case TransportDoT, TransportDoH:
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			}
		case TransportDoQ:
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"doq"},
				MinVersion:         tls.VersionTLS12,
			}
		default:
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
	}

	client := &DNSClient{
		Transport: transport,
		Port:      port,
		TLSConfig: tlsConfig,
		Timeout:   5 * time.Second,
	}

	// Initialize transport-specific configurations
	switch transport {
	case TransportDo53:
		client.DNSClientUDP = &dns.Client{Net: "udp", Timeout: client.Timeout}
		client.DNSClientTCP = &dns.Client{Net: "tcp", Timeout: client.Timeout}
	case TransportDo53TCP:
		client.DNSClientTCP = &dns.Client{Net: "tcp", Timeout: client.Timeout}
		client.ForceTCP = true
	case TransportDoT:
		client.DNSClientTLS = &dns.Client{
			Net:       "tcp-tls",
			TLSConfig: tlsConfig,
			Timeout:   client.Timeout,
		}
	case TransportDoH:
		client.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: client.Timeout,
		}
	case TransportDoQ:
		// Ensure TLS 1.3 for DoQ per RFC 9250
		if client.TLSConfig != nil && client.TLSConfig.MinVersion < tls.VersionTLS13 {
			client.TLSConfig.MinVersion = tls.VersionTLS13
		}
		client.QUICConfig = &quic.Config{
			MaxIdleTimeout:  client.Timeout,
			KeepAlivePeriod: client.Timeout / 2,
		}
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// TransportKind returns the transport this client was configured for.
// Satisfies the DNSClienter interface.
func (c *DNSClient) TransportKind() Transport { return c.Transport }

// ExchangeResult describes what actually happened on the wire for an Exchange:
// the transport that carried the returned response (Do53 vs Do53TCP after an
// internal fallback) and whether a Do53/UDP response was TC=1 truncated and
// retried over TCP. The IMR uses this to record accurate per-server
// transport-usage and truncation statistics; the plain Exchange wrapper below
// discards it so existing callers are unaffected.
type ExchangeResult struct {
	WireTransport Transport // transport that carried the returned response
	Truncated     bool      // a Do53/UDP response had TC=1 and was retried over TCP
}

// Exchange sends a DNS message and returns the response. Thin wrapper over
// ExchangeWithResult that discards the wire-transport/truncation detail.
func (c *DNSClient) Exchange(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, error) {
	r, rtt, _, err := c.ExchangeWithResult(msg, server, debug)
	return r, rtt, err
}

// ExchangeWithResult is Exchange plus an ExchangeResult reporting the actual
// wire transport used and whether a TC=1 truncation drove a UDP->TCP upgrade.
// The (msg, rtt, err) return values are identical to Exchange's.
func (c *DNSClient) ExchangeWithResult(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, ExchangeResult, error) {
	if debug {
		fmt.Printf("*** Exchange: sending %s message to %s:%s opcode: %s qname: %s rrtype: %s\n",
			TransportToString[c.Transport], server, c.Port,
			dns.OpcodeToString[msg.Opcode],
			msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
	}

	switch c.Transport {
	case TransportDo53, TransportDo53TCP:
		if debug {
			log.Printf("*** Do53 sending message to %s:%s opcode: %s qname: %s rrtype: %s",
				server, c.Port,
				dns.OpcodeToString[msg.Opcode],
				msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
		}
		addr := net.JoinHostPort(server, c.Port)
		if c.ForceTCP {
			r, rtt, err := c.DNSClientTCP.Exchange(msg, addr)
			return r, rtt, ExchangeResult{WireTransport: TransportDo53TCP}, err
		}
		r, rtt, err := c.DNSClientUDP.Exchange(msg, addr)
		if err == nil && r != nil && r.Truncated && !c.DisableFallback && c.DNSClientTCP != nil {
			log.Printf("Do53: UDP response from %s truncated (TC=1); retrying over TCP", addr)
			tr, trtt, terr := c.DNSClientTCP.Exchange(msg, addr)
			return tr, trtt, ExchangeResult{WireTransport: TransportDo53TCP, Truncated: true}, terr
		}
		// Timeout / transient-error fallback: a single dropped UDP packet
		// (or a network blocking UDP) makes the UDP exchange return a transient
		// error. Take one shot over TCP against the same address before giving
		// up. This consolidates what used to live in the IMR tryServer path.
		// (This is NOT a truncation — Truncated stays false.)
		if err != nil && !c.DisableFallback && c.DNSClientTCP != nil && IsTransientNetErr(err) {
			if debug {
				log.Printf("Do53: UDP transient error from %s (%v); retrying over TCP", addr, err)
			}
			tr, trtt, terr := c.DNSClientTCP.Exchange(msg, addr)
			if terr == nil {
				return tr, trtt, ExchangeResult{WireTransport: TransportDo53TCP}, nil
			}
			// Prefer the original UDP error if TCP also fails (operators usually
			// want to know the primary-path symptom).
			return r, rtt, ExchangeResult{WireTransport: TransportDo53}, err
		}
		return r, rtt, ExchangeResult{WireTransport: TransportDo53}, err
	case TransportDoT:
		r, rtt, err := c.DNSClientTLS.Exchange(msg, net.JoinHostPort(server, c.Port))
		return r, rtt, ExchangeResult{WireTransport: TransportDoT}, err
	case TransportDoH:
		r, rtt, err := c.exchangeDoH(msg, server, debug)
		return r, rtt, ExchangeResult{WireTransport: TransportDoH}, err
	case TransportDoQ:
		r, rtt, err := c.exchangeDoQ(msg, net.JoinHostPort(server, c.Port), debug)
		return r, rtt, ExchangeResult{WireTransport: TransportDoQ}, err
	default:
		return nil, 0, ExchangeResult{WireTransport: c.Transport}, fmt.Errorf("unsupported transport protocol: %d", c.Transport)
	}
}

// exchangeDoT handles DNS over TLS
// func (c *DNSClientNG) exchangeDoT(msg *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
//	if Globals.Debug {
//		fmt.Printf("*** DoT sending message to %s opcode: %s qname: %s rrtype: %s\n", server, dns.OpcodeToString[msg.Opcode], msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
//	}
//	return c.DNSClient.Exchange(msg, net.JoinHostPort(server, "853"))
// }

// exchangeDoH handles DNS over HTTPS
func (c *DNSClient) exchangeDoH(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// Determine port (default to 443 for HTTPS if not specified)
	port := c.Port
	if port == "" {
		port = "443"
	}

	// Use net.JoinHostPort to properly handle IPv6 addresses (adds brackets if needed)
	// This returns format like "[::1]:8443" which is correct for URLs
	hostPort := net.JoinHostPort(server, port)

	// Create HTTP request
	url := fmt.Sprintf("https://%s/dns-query", hostPort)
	if debug {
		fmt.Printf("*** DoH sending HTTPS POST to %s opcode: %s qname: %s rrtype: %s\n", url, dns.OpcodeToString[msg.Opcode], msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(packed))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("HTTP request failed with status: %s", resp.Status)
	}

	// Read response (DNS messages cannot exceed 65535 bytes)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read HTTP response: %v", err)
	}

	// Unpack DNS message
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("failed to unpack DNS response: %v", err)
	}

	return response, 0, nil
}

// exchangeDoQ handles DNS over QUIC
func (c *DNSClient) exchangeDoQ(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	if debug {
		fmt.Printf("*** DoQ sending message to %s opcode: %s qname: %s rrtype: %s\n", server, dns.OpcodeToString[msg.Opcode], msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
	}

	// Connect to the QUIC server
	conn, err := quic.DialAddr(ctx, server, c.TLSConfig, c.QUICConfig)
	if err != nil {
		log.Printf("*** DoQ failed to connect to QUIC server: %v", err)
		return nil, 0, fmt.Errorf("failed to connect to QUIC server: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// Open a new stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Printf("*** DoQ failed to open QUIC stream: %v", err)
		return nil, 0, fmt.Errorf("failed to open QUIC stream: %v", err)
	}
	defer stream.Close()

	// Pack the DNS message
	packed, err := msg.Pack()
	if err != nil {
		log.Printf("*** DoQ failed to pack DNS message: %v", err)
		return nil, 0, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// Write the length prefix (2 bytes) and the message
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
	if _, err := stream.Write(lenBuf); err != nil {
		log.Printf("*** DoQ failed to write message length: %v", err)
		return nil, 0, fmt.Errorf("failed to write message length: %v", err)
	}
	if _, err := stream.Write(packed); err != nil {
		log.Printf("*** DoQ failed to write DNS message: %v", err)
		return nil, 0, fmt.Errorf("failed to write DNS message: %v", err)
	}

	// Read the response length
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		log.Printf("*** DoQ failed to read response length: %v", err)
		return nil, 0, fmt.Errorf("failed to read response length: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	if respLen == 0 {
		return nil, 0, fmt.Errorf("DoQ response length is zero")
	}

	// Read the response
	respBuf := make([]byte, respLen)
	n, err := io.ReadFull(stream, respBuf)
	if err != nil {
		log.Printf("*** DoQ failed to read response: %v", err)
		return nil, 0, fmt.Errorf("failed to read response: %v", err)
	}
	if n != int(respLen) {
		return nil, 0, fmt.Errorf("DoQ response length mismatch: expected %d, got %d", respLen, n)
	}

	if debug {
		fmt.Printf("*** DoQ received response length: %d. Now closing stream\n", respLen)
	}

	// Unpack the response
	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		log.Printf("*** DoQ failed to unpack response: %v", err)
		// stream.Close()
		return nil, 0, fmt.Errorf("failed to unpack response: %v", err)
	}

	// Properly close the stream after we're done with it
	stream.CancelRead(0)
	// stream.Close()

	return response, 0, nil
}
