package tdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Transport represents the DNS transport protocol
type Transport int

const (
	TransportDo53 Transport = iota
	TransportDoT
	TransportDoH
	TransportDoQ
)

// DNSClient represents a DNS client that supports multiple transport protocols
type DNSClient struct {
	Transport  Transport
	Server     string
	TLSConfig  *tls.Config
	HTTPClient *http.Client
	QUICConfig *quic.Config
	Timeout    time.Duration
}

// NewDNSClient creates a new DNS client with the specified transport
func NewDNSClient(transport Transport, server string, tlsConfig *tls.Config) *DNSClient {
	client := &DNSClient{
		Transport: transport,
		Server:    server,
		TLSConfig: tlsConfig,
		Timeout:   5 * time.Second,
	}

	// Initialize transport-specific configurations
	switch transport {
	case TransportDoH:
		client.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: client.Timeout,
		}
	case TransportDoQ:
		client.QUICConfig = &quic.Config{
			MaxIdleTimeout:  client.Timeout,
			KeepAlivePeriod: client.Timeout / 2,
		}
	}

	return client
}

// Exchange sends a DNS message and returns the response
func (c *DNSClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	switch c.Transport {
	case TransportDo53:
		return c.exchangeDo53(msg)
	case TransportDoT:
		return c.exchangeDoT(msg)
	case TransportDoH:
		return c.exchangeDoH(msg)
	case TransportDoQ:
		return c.exchangeDoQ(msg)
	default:
		return nil, fmt.Errorf("unsupported transport protocol")
	}
}

// exchangeDo53 handles traditional DNS over UDP/TCP
func (c *DNSClient) exchangeDo53(msg *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Timeout: c.Timeout,
	}
	resp, _, err := client.Exchange(msg, c.Server)
	return resp, err
}

// exchangeDoT handles DNS over TLS
func (c *DNSClient) exchangeDoT(msg *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: c.TLSConfig,
		Timeout:   c.Timeout,
	}
	resp, _, err := client.Exchange(msg, c.Server)
	return resp, err
}

// exchangeDoH handles DNS over HTTPS
func (c *DNSClient) exchangeDoH(msg *dns.Msg) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("https://%s/dns-query", c.Server)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %s", resp.Status)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %v", err)
	}

	// Unpack DNS message
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %v", err)
	}

	return response, nil
}

// exchangeDoQ handles DNS over QUIC
func (c *DNSClient) exchangeDoQ(msg *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	// Connect to the QUIC server
	conn, err := quic.DialAddr(ctx, c.Server, c.TLSConfig, c.QUICConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to QUIC server: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// Open a new stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open QUIC stream: %v", err)
	}
	defer stream.Close()

	// Pack the DNS message
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// Write the length prefix (2 bytes) and the message
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
	if _, err := stream.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("failed to write message length: %v", err)
	}
	if _, err := stream.Write(packed); err != nil {
		return nil, fmt.Errorf("failed to write DNS message: %v", err)
	}

	// Read the response length
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	// Read the response
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Unpack the response
	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("failed to unpack response: %v", err)
	}

	return response, nil
}

// StringToTransport converts a string transport name to Transport type
func StringToTransport(s string) (Transport, error) {
	switch s {
	case "do53":
		return TransportDo53, nil
	case "tcp":
		return TransportDo53, nil // TCP is still Do53, just forced TCP
	case "dot":
		return TransportDoT, nil
	case "doh":
		return TransportDoH, nil
	case "doq":
		return TransportDoQ, nil
	default:
		return TransportDo53, fmt.Errorf("unknown transport: %s", s)
	}
}
