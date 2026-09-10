/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"testing"
	"time"
)

// WithTimeout has to reach the transport clients, not just the field.
//
// NewDNSClient builds dns.Client / http.Client / quic.Config from
// DefaultClientTimeout BEFORE any option runs, so an implementation that set
// only c.Timeout would leave every transport on the default while the field
// claimed otherwise -- a timeout that reports as configured and does nothing.
// The flag parsing is covered in cmdv2/dog; this covers the part that actually
// bounds a query.
func TestWithTimeoutReachesTheTransportClients(t *testing.T) {
	const want = 2 * time.Second

	for _, tc := range []struct {
		name      string
		transport Transport
		check     func(*testing.T, *DNSClient)
	}{
		{"Do53", TransportDo53, func(t *testing.T, c *DNSClient) {
			if c.DNSClientUDP.Timeout != want {
				t.Errorf("UDP timeout = %s, want %s", c.DNSClientUDP.Timeout, want)
			}
			if c.DNSClientTCP.Timeout != want {
				t.Errorf("TCP timeout = %s, want %s", c.DNSClientTCP.Timeout, want)
			}
		}},
		{"Do53-TCP", TransportDo53TCP, func(t *testing.T, c *DNSClient) {
			if c.DNSClientTCP.Timeout != want {
				t.Errorf("TCP timeout = %s, want %s", c.DNSClientTCP.Timeout, want)
			}
		}},
		{"DoT", TransportDoT, func(t *testing.T, c *DNSClient) {
			if c.DNSClientTLS.Timeout != want {
				t.Errorf("TLS timeout = %s, want %s", c.DNSClientTLS.Timeout, want)
			}
		}},
		{"DoH", TransportDoH, func(t *testing.T, c *DNSClient) {
			if c.HTTPClient.Timeout != want {
				t.Errorf("HTTP timeout = %s, want %s", c.HTTPClient.Timeout, want)
			}
		}},
		{"DoQ", TransportDoQ, func(t *testing.T, c *DNSClient) {
			// Mirrors what NewDNSClient does with DefaultClientTimeout, so the
			// two cannot describe the connection differently.
			if c.QUICConfig.MaxIdleTimeout != want {
				t.Errorf("QUIC MaxIdleTimeout = %s, want %s", c.QUICConfig.MaxIdleTimeout, want)
			}
			if c.QUICConfig.KeepAlivePeriod != want/2 {
				t.Errorf("QUIC KeepAlivePeriod = %s, want %s", c.QUICConfig.KeepAlivePeriod, want/2)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewDNSClient(tc.transport, "853", nil, WithTimeout(want))
			if c.Timeout != want {
				t.Errorf("client timeout = %s, want %s", c.Timeout, want)
			}
			tc.check(t, c)
		})
	}
}

// A non-positive duration leaves the default alone rather than producing a
// client that times out instantly.
func TestWithTimeoutIgnoresNonPositive(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		c := NewDNSClient(TransportDo53, "53", nil, WithTimeout(d))
		if c.Timeout != DefaultClientTimeout {
			t.Errorf("WithTimeout(%s) set the field to %s, want the default %s", d, c.Timeout, DefaultClientTimeout)
		}
		if c.DNSClientUDP.Timeout != DefaultClientTimeout {
			t.Errorf("WithTimeout(%s) set the UDP client to %s, want the default", d, c.DNSClientUDP.Timeout)
		}
	}
}
