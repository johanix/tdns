/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// startStrictDoQServer starts a DoQ listener that behaves like a server which
// reads the query stream to its end before it answers (H root does; RFC 9250
// 4.2 lets a server do so, because the client MUST send a STREAM FIN after the
// query). A query whose stream is still open is never answered.
//
// tdns-auth's own DoQ server is not like this: it reads the length prefix and
// that many bytes and answers, so it never noticed a client that forgot the
// FIN. A test against it would pass with or without the fix.
func startStrictDoQServer(t *testing.T) (string, func()) {
	t.Helper()
	return startStrictDoQServerOn(t, "127.0.0.1:0")
}

// startStrictDoQServerOn is startStrictDoQServer on a chosen listen address,
// which is what lets a test put the same server on ::1.
func startStrictDoQServerOn(t *testing.T, listen string) (string, func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doq-fin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	l, err := quic.ListenAddr(listen, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept(ctx)
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.CloseWithError(0, "")
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				// ReadAll returns only at the FIN (or on the deadline, which
				// is how a client that never sends one is left unanswered).
				_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
				wire, err := io.ReadAll(stream)
				if err != nil || len(wire) < 2 ||
					int(binary.BigEndian.Uint16(wire)) != len(wire)-2 {
					return
				}
				q := new(dns.Msg)
				if q.Unpack(wire[2:]) != nil || len(q.Question) == 0 {
					return
				}
				r := new(dns.Msg)
				r.SetReply(q)
				rr, err := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.1")
				if err != nil {
					return
				}
				r.Answer = append(r.Answer, rr)
				packed, err := r.Pack()
				if err != nil {
					return
				}
				out := make([]byte, 2, 2+len(packed))
				binary.BigEndian.PutUint16(out, uint16(len(packed)))
				_, _ = stream.Write(append(out, packed...))
				_ = stream.Close()
				// Closing the connection now would discard the response
				// that is still in flight. The client closes it once it
				// has read the answer.
				select {
				case <-conn.Context().Done():
				case <-ctx.Done():
				case <-time.After(3 * time.Second):
				}
			}()
		}
	}()

	return l.Addr().String(), func() {
		cancel()
		_ = l.Close()
		wg.Wait()
	}
}

// The DoQ client must end the query stream with a FIN before it reads the
// response (RFC 9250 4.2). Without it, a server that reads the stream to its
// end waits for the FIN that never comes and the exchange runs into its
// timeout: "failed to read response length: Application error 0x0 (local):
// context done", which is what `dog @h.root-servers.net se ns +doq` printed.
func TestExchangeDoQSendsFINBeforeReading(t *testing.T) {
	addr, stop := startStrictDoQServer(t)
	defer stop()

	// Long enough that a working exchange is nowhere near it, short enough
	// that a regression fails the test in seconds.
	const timeout = 3 * time.Second
	c := NewDNSClient(TransportDoQ, "853", nil, WithTimeout(timeout))

	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)

	start := time.Now()
	r, _, err := c.Exchange(q, addr, false)
	if err != nil {
		t.Fatalf("DoQ exchange against a server that waits for the FIN: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= timeout {
		t.Errorf("exchange took %v, which is the timeout and not an answer", elapsed)
	}
	if r == nil || r.Id != q.Id || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("unexpected response: %v", r)
	}
}
