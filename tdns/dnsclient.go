package tdns

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
)

// DNSClient represents a DNS client that supports multiple transport protocols
type DNSClient struct {
	Port      string
	Transport Transport
	// Server     string
	TLSConfig  *tls.Config
	HTTPClient *http.Client
	QUICConfig *quic.Config
	Timeout    time.Duration
	DNSClient  *dns.Client
}

// NewDNSClient creates a new DNS client with the specified transport
func NewDNSClient(transport Transport, port string, tlsConfig *tls.Config) *DNSClient {
	if tlsConfig == nil {
		switch transport {
		case TransportDoT, TransportDoH:
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:	    tls.VersionTLS12,
			}
		case TransportDoQ:
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"doq"},
				MinVersion:	    tls.VersionTLS12,
			}
		default:
			tlsConfig = &tls.Config{
				MinVersion:	    tls.VersionTLS12,
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
		client.DNSClient = &dns.Client{
			Timeout: client.Timeout,
		}
	case TransportDoT:
		client.DNSClient = &dns.Client{
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
		client.QUICConfig = &quic.Config{
			MaxIdleTimeout:  client.Timeout,
			KeepAlivePeriod: client.Timeout / 2,
		}
	}

	// dump.P(client)
	return client
}

// Exchange sends a DNS message and returns the response
func (c *DNSClient) Exchange(msg *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	if !Globals.Debug {
		fmt.Printf("*** Exchange: Globals.Debug is NOT set\n")
	} else {
		fmt.Printf("*** Exchange: Globals.Debug is set\n")
	}
	if Globals.Debug {
		fmt.Printf("*** Exchange: sending %s message to %s:%s opcode: %s qname: %s rrtype: %s\n",
			TransportToString[c.Transport], server, c.Port,
			dns.OpcodeToString[msg.Opcode],
			msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
	}

	switch c.Transport {
	case TransportDo53:
		if Globals.Debug {
			log.Printf("*** Do53 sending message to %s:%s opcode: %s qname: %s rrtype: %s",
				server, c.Port,
				dns.OpcodeToString[msg.Opcode],
				msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
		}
		return c.DNSClient.Exchange(msg, net.JoinHostPort(server, c.Port))
	case TransportDoT:
		return c.DNSClient.Exchange(msg, net.JoinHostPort(server, c.Port))
	case TransportDoH:
		return c.exchangeDoH(msg, server)
	case TransportDoQ:
		return c.exchangeDoQ(msg, net.JoinHostPort(server, c.Port))
	default:
		return nil, 0, fmt.Errorf("unsupported transport protocol: %d", c.Transport)
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
func (c *DNSClient) exchangeDoH(msg *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("https://%s/dns-query", server)
	if Globals.Debug {
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

	// Read response
	body, err := io.ReadAll(resp.Body)
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
func (c *DNSClient) exchangeDoQ(msg *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	if Globals.Debug {
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

	// Read the response
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		log.Printf("*** DoQ failed to read response: %v", err)
		return nil, 0, fmt.Errorf("failed to read response: %v", err)
	}

	if Globals.Debug {
		fmt.Printf("*** DoQ received response length: %d. Now closing stream\n", respLen)
	}

	// Unpack the response
	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		log.Printf("*** DoQ failed to unpack response: %v", err)
		stream.Close()
		return nil, 0, fmt.Errorf("failed to unpack response: %v", err)
	}

	// Properly close the stream after we're done with it
	stream.CancelRead(0)
	stream.Close()

	return response, 0, nil
}

// StringToTransport converts a string transport name to Transport type
func StringToTransport(s string) (Transport, error) {
	switch s {
	case "do53", "Do53", "Do53-TCP":
		return TransportDo53, nil
	case "tcp", "TCP":
		return TransportDo53, nil // TCP is still Do53, just forced TCP
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

var TransportToString = map[Transport]string{
	TransportDo53: "do53",
	TransportDoT:  "dot",
	TransportDoH:  "doh",
	TransportDoQ:  "doq",
}
