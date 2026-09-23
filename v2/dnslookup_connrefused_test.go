package tdns

import (
	"errors"
	"net"
	"os"
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/edns0"
)

// A refused connection is the host answering, so it must not count against the
// address family (#703). These are the shapes it arrives in.
func TestIsConnRefused(t *testing.T) {
	udpRead := &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("read", syscall.ECONNREFUSED)}
	tcpDial := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"udp read refused", udpRead, true},
		{"tcp dial refused", tcpDial, true},
		{"wrapped", errors.Join(errors.New("exchange"), udpRead), true},
		{"text only", errors.New("read udp 10.0.0.1:1->10.0.0.2:53: read: connection refused"), true},
		{"timeout", errors.New("read udp 10.0.0.1:1->10.0.0.2:53: i/o timeout"), false},
		{"unreachable", &net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, false},
	}
	for _, tc := range cases {
		if got := isConnRefused(tc.err); got != tc.want {
			t.Errorf("%s: isConnRefused = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The case #703 was filed from: the zone's one nameserver has a v4 address in
// server backoff and a v6 address on a family the tracker holds suspect. Neither
// is usable, and the explanation has to say why for BOTH, not leave the second
// unaccounted for.
func TestExplainNoTuplesNamesASuspectFamily(t *testing.T) {
	const v4, v6 = "192.0.2.1", "2001:db8::1"
	srv := &cache.AuthServer{Name: "ns1.example.", Addrs: []string{v4, v6}}
	for _, tr := range candidateTransports(srv, "www.example.", edns0.PrivacyNone) {
		srv.RecordAddressFailure(v4, tr, errors.New("read: connection refused"))
	}
	ft := cache.NewFamilyTracker(time.Minute, time.Minute, time.Second, 1)
	ft.RecordResult(v6, false)
	if !ft.IsSuspect(cache.FamilyV6) {
		t.Fatal("setup: v6 should be suspect after one failure with threshold 1")
	}
	got := explainNoTuples(map[string]*cache.AuthServer{"ns1.example.": srv}, nil, ft, "www.example.", edns0.PrivacyNone)
	if !regexp.MustCompile(`[1-9][0-9]* in server backoff`).MatchString(got) {
		t.Errorf("explanation %q does not count the v4 address in server backoff", got)
	}
	if !regexp.MustCompile(`[1-9][0-9]* on a suspect address family`).MatchString(got) {
		t.Errorf("explanation %q does not count the v6 address on the suspect family", got)
	}
}
