/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Raw-wire exchange.
//
// dns.Client.Exchange unpacks the response and throws the wire buffer away, but
// SIG(0) verification needs those exact bytes: dns.SIG.Verify(k, buf) recomputes
// the signature over the message as received, and re-packing the parsed message
// is NOT guaranteed to reproduce it (name compression, option and record
// ordering, and any field the parser normalises can all differ). Verifying
// against a re-packed buffer would produce sporadic false "forged" verdicts,
// which is precisely the verdict the mutual-authentication cases (A3, G2-G4)
// turn on. So the transport is done here, keeping the buffer.
//
// This is also why the delsync client does not simply reuse Sig0Signer.Send:
// that returns an rcode, which is all the churn tests needed.

// exchangeCapturingWire sends m and returns both the parsed response and the
// raw bytes it was parsed from. transport is "tcp" or "udp" ("" means udp).
func exchangeCapturingWire(server string, m *dns.Msg, transport string, timeout time.Duration) (*dns.Msg, []byte, error) {
	return exchangeCapturingWireContext(context.Background(), server, m, transport, timeout)
}

func exchangeCapturingWireContext(ctx context.Context, server string, m *dns.Msg, transport string, timeout time.Duration) (*dns.Msg, []byte, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	network := "udp"
	if transport == "tcp" {
		network = "tcp"
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("packing request: %w", err)
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, nil, fmt.Errorf("dialing %s/%s: %w", server, network, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	var wire []byte
	if network == "tcp" {
		wire, err = exchangeTCP(conn, buf)
	} else {
		wire, err = exchangeUDP(conn, buf)
	}
	if err != nil {
		return nil, nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(wire); err != nil {
		return nil, wire, fmt.Errorf("unpacking response (%d bytes): %w", len(wire), err)
	}
	return resp, wire, nil
}

// exchangeTCP writes the RFC 1035 §4.2.2 two-byte length prefix followed by the
// message, then reads one length-prefixed response and returns it verbatim.
func exchangeTCP(conn net.Conn, buf []byte) ([]byte, error) {
	if len(buf) > 65535 {
		return nil, fmt.Errorf("message too large for TCP framing: %d bytes", len(buf))
	}
	framed := make([]byte, 2+len(buf))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(buf)))
	copy(framed[2:], buf)
	if _, err := conn.Write(framed); err != nil {
		return nil, fmt.Errorf("writing tcp request: %w", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading tcp response length: %w", err)
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("tcp response declared zero length")
	}
	wire := make([]byte, n)
	if _, err := io.ReadFull(conn, wire); err != nil {
		return nil, fmt.Errorf("reading tcp response body (%d bytes): %w", n, err)
	}
	return wire, nil
}

// exchangeUDP writes the message and reads one datagram. The read buffer is
// generously sized: a PQ SIG(0) signature (ML-DSA, SQIsign) makes these
// messages far larger than a classic 4096-byte assumption, and a short buffer
// would truncate the datagram and produce an unpack error that looks like a
// malformed response rather than a sizing mistake here.
func exchangeUDP(conn net.Conn, buf []byte) ([]byte, error) {
	if _, err := conn.Write(buf); err != nil {
		return nil, fmt.Errorf("writing udp request: %w", err)
	}
	read := make([]byte, 65535)
	n, err := conn.Read(read)
	if err != nil {
		return nil, fmt.Errorf("reading udp response: %w", err)
	}
	return read[:n], nil
}

// verifySig0 checks every SIG(0) RR on a response against the given KEY and
// reports whether the message was signed at all, and whether a signature made
// by that key verified over the wire bytes.
//
// A message may carry more than one SIG: tdns's SignMsg appends one per active
// key, so a receiver mid-rollover legitimately sends several. Treating "the
// first SIG did not verify" as a forgery would then be a false positive, so
// this accepts if ANY signature verifies under the expected key. It reports the
// verified signer and keytag so a caller can say which key vouched.
func verifySig0(msg *dns.Msg, wire []byte, key *dns.KEY) (signed, verified bool, signer string, keytag uint16) {
	if msg == nil {
		return false, false, "", 0
	}
	var firstSigner string
	var firstKeytag uint16
	for _, rr := range msg.Extra {
		sig, ok := rr.(*dns.SIG)
		if !ok {
			continue
		}
		signed = true
		if firstSigner == "" {
			firstSigner, firstKeytag = sig.SignerName, sig.KeyTag
		}
		if key == nil || wire == nil {
			continue
		}
		if err := sig.Verify(key, wire); err == nil {
			return true, true, sig.SignerName, sig.KeyTag
		}
	}
	return signed, false, firstSigner, firstKeytag
}
