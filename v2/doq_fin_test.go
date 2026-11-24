/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// A DoQ client ends the query stream with a STREAM FIN (RFC 9250 4.2), and the
// last bytes of the query can arrive together with it. quic-go then returns
// them from one Read as (n, io.EOF). The server's read helper used to return
// that error although its buffer was full, so it dropped a complete query and
// the client saw "failed to read response length: EOF" (#1174 made the tdns
// client send the FIN, and so made every query to tdns-auth end like this).

// doqTestListener starts a DoQ listener on 127.0.0.1 and calls serve for every
// connection it accepts. It returns the address and stops the listener when
// the test ends.
func doqTestListener(t *testing.T, serve func(ctx context.Context, conn *quic.Conn)) string {
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
	l, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
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
				serve(ctx, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		wg.Wait()
	})
	return l.Addr().String()
}

// doqTestClientConn dials the listener at addr.
func doqTestClientConn(t *testing.T, addr string) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
		MinVersion:         tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

// The tdns DoQ client against tdns's own DoQ server: the query is answered.
func TestDoQServerAnswersAQueryEndedWithAFIN(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		rr, err := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1")
		if err != nil {
			t.Errorf("build answer: %v", err)
			return
		}
		resp.Answer = append(resp.Answer, rr)
		if err := w.WriteMsg(resp); err != nil {
			t.Errorf("write answer: %v", err)
		}
	}
	addr := doqTestListener(t, func(ctx context.Context, conn *quic.Conn) {
		handleDoQConnection(ctx, conn, handler)
	})

	// Long enough that a working exchange is nowhere near it, short enough
	// that a regression fails the test in seconds.
	const timeout = 3 * time.Second
	c := core.NewDNSClient(core.TransportDoQ, "853", nil, core.WithTimeout(timeout))
	// The FIN and the last bytes of the query travel in one packet only when
	// the client writes without a pause, which it does; repeat so that a
	// server that depends on the timing fails at least once.
	for i := 0; i < 20; i++ {
		q := new(dns.Msg)
		q.SetQuestion("example.org.", dns.TypeA)
		r, _, err := c.Exchange(q, addr, false)
		if err != nil {
			t.Fatalf("query %d: DoQ exchange with tdns's own server: %v", i, err)
		}
		if r == nil || r.Id != q.Id || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
			t.Fatalf("query %d: unexpected response: %v", i, r)
		}
	}
}

// readFromDoQStream sends payload on a new stream, ends it with a FIN, waits
// until the server has all of it (so that the bytes and the FIN are read
// together) and returns what readExactWithContext makes of a buffer of size
// bytes on the server.
func readFromDoQStream(t *testing.T, payload []byte, size int) ([]byte, error) {
	t.Helper()

	type result struct {
		got []byte
		err error
	}
	sent := make(chan struct{})
	done := make(chan result, 1)
	addr := doqTestListener(t, func(ctx context.Context, conn *quic.Conn) {
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		select {
		case <-sent:
		case <-ctx.Done():
			return
		}
		// Everything, FIN included, has been delivered by now.
		time.Sleep(300 * time.Millisecond)
		buf := make([]byte, size)
		err = readExactWithContext(ctx, stream, buf)
		done <- result{got: buf, err: err}
	})

	conn := doqTestClientConn(t, addr)
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close (FIN): %v", err)
	}
	close(sent)

	select {
	case r := <-done:
		return r.got, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not finish reading")
		return nil, nil
	}
}

// The last bytes of a message arrive with the FIN: the buffer is full, so the
// read has succeeded.
func TestReadExactWithContextLastBytesArriveWithTheFIN(t *testing.T) {
	payload := []byte("0123456789")
	got, err := readFromDoQStream(t, payload, len(payload))
	if err != nil {
		t.Fatalf("readExactWithContext with the last bytes and the FIN together: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %q, want %q", got, payload)
	}
}

// The stream ends after some of the bytes but before all of them: an
// unexpected end, as io.ReadFull reports it.
func TestReadExactWithContextTruncatedStreamIsAnUnexpectedEOF(t *testing.T) {
	_, err := readFromDoQStream(t, []byte("012"), 5)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a stream that ended 2 bytes short: got %v, want io.ErrUnexpectedEOF", err)
	}
}

// The stream ends before any byte: a clean end, as io.ReadFull reports it.
func TestReadExactWithContextEmptyStreamIsEOF(t *testing.T) {
	_, err := readFromDoQStream(t, nil, 2)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("a stream that ended before any byte: got %v, want io.EOF", err)
	}
}
