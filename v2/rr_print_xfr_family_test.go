/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// captureStdoutForTest returns what f writes to os.Stdout. ZoneTransferPrint
// reports its failures with fmt.Printf, so the wording is only observable here.
func captureStdoutForTest(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

// A transfer restricted to a family dials before transfer.In. When that dial
// fails the message must say so: "Error from transfer.In" would name a call
// that was never made, and the same sentence below is what a real In failure
// prints. The failure is also the restriction at work -- -4 cannot reach an
// IPv6 literal -- so it shows the restricted dial is the one in use.
func TestZoneTransferPrintRestrictedDialFailureSaysSo(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer l.Close()
	upstream := l.Addr().String()

	var xerr error
	out := captureStdoutForTest(t, func() {
		xerr = ZoneTransferPrint("example.org.", upstream, 0, dns.TypeAXFR,
			map[string]string{core.OptionAddrFamily: "4"}, "", "", "", nil)
	})
	if xerr == nil {
		t.Fatalf("-4 transfer from the IPv6 address %s succeeded; output: %q", upstream, out)
	}
	if want := "cannot connect to " + upstream + " (tcp4)"; !strings.Contains(out, want) {
		t.Errorf("output %q does not contain %q", out, want)
	}
	if strings.Contains(out, "transfer.In") {
		t.Errorf("a failed dial is reported as a transfer.In failure: %q", out)
	}
}

// Without a family nothing changes: In dials, and its failure is still
// reported as In's.
func TestZoneTransferPrintUnrestrictedFailureIsFromIn(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	upstream := l.Addr().String()
	l.Close() // nothing listens here now: the connect is refused

	var xerr error
	out := captureStdoutForTest(t, func() {
		xerr = ZoneTransferPrint("example.org.", upstream, 0, dns.TypeAXFR,
			map[string]string{}, "", "", "", nil)
	})
	if xerr == nil {
		t.Fatalf("transfer from a closed port succeeded; output: %q", out)
	}
	if !strings.Contains(out, "Error from transfer.In") {
		t.Errorf("output %q does not name transfer.In", out)
	}
	if strings.Contains(out, "cannot connect to") {
		t.Errorf("unrestricted failure used the restricted-dial message: %q", out)
	}
}

// A bad family in the option map stops the transfer before any dial rather
// than falling back to dual-stack.
func TestZoneTransferPrintRejectsBadFamily(t *testing.T) {
	var xerr error
	out := captureStdoutForTest(t, func() {
		xerr = ZoneTransferPrint("example.org.", "127.0.0.1:1", 0, dns.TypeAXFR,
			map[string]string{core.OptionAddrFamily: "7"}, "", "", "", nil)
	})
	if xerr == nil || !strings.Contains(out, "unknown address family") {
		t.Errorf("err=%v output=%q, want a refusal naming the family", xerr, out)
	}
}
