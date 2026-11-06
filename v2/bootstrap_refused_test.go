package tdns

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A parent that refuses the bootstrap ceremony refuses it: the child does not
// read REFUSED as success. The ceremony handed the refusal back with a nil
// error, and BootstrapWithParent, the BADKEY re-bootstrap and the API's
// bootstrap read only the error. A child whose retired key the parent refused
// (EDE Sig0KeyRetired) logged success and polled the parent five times.

// ceremonyChild is a child with an active SIG(0) key, ready to send its
// bootstrap ceremony.
func ceremonyChild(t *testing.T) (*ZoneData, *Sig0ActiveKeys) {
	t.Helper()
	const zone = "child.parent.example."
	kdb := newTestKeyDB(t)
	generateSig0Key(t, kdb, zone, Sig0StateActive)
	sak, err := kdb.GetSig0Keys(zone, Sig0StateActive)
	if err != nil || len(sak.Keys) != 1 {
		t.Fatalf("active SIG(0) key: err=%v keys=%+v", err, sak)
	}
	zd := &ZoneData{ZoneName: zone, KeyDB: kdb, Logger: log.New(io.Discard, "", 0)}
	zd.SetParent("parent.example.")
	return zd, sak
}

// retiredKeyParent is a parent that refuses every UPDATE because the key was
// retired, the way #999's parent answers a tombstoned key.
func retiredKeyParent(t *testing.T) string {
	t.Helper()
	return startRcodeEDEResponder(t, dns.RcodeRefused, edns0.EDESig0KeyRetired)
}

func TestBootstrapOutcomeTellsARetiredKeyApart(t *testing.T) {
	_, ur, err := SendUpdate(context.Background(), testUpdateMsg(t), "child.parent.example.", []string{retiredKeyParent(t)})
	if err != nil {
		t.Fatalf("SendUpdate: %v", err)
	}
	out := bootstrapOutcome(ur, nil)
	if !errors.Is(out, ErrSig0KeyTombstoned) {
		t.Fatalf("outcome %v, want ErrSig0KeyTombstoned", out)
	}
	if errors.Is(out, errBootstrapTransient) {
		t.Error("a retired key reads as not final; retrying it only repeats the refusal")
	}
	if !strings.Contains(out.Error(), "make a new SIG(0) key") {
		t.Errorf("outcome %q does not say what to do", out)
	}
}

func TestTheCeremonyReportsARefusalAsAnError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rcode     int
		ede       uint16
		want      error // nil: any error
		transient bool
	}{
		{"retired key", dns.RcodeRefused, edns0.EDESig0KeyRetired, ErrSig0KeyTombstoned, false},
		{"still verifying", dns.RcodeRefused, edns0.EDESig0KeyKnownButNotTrusted, errBootstrapTransient, true},
		{"validation failed", dns.RcodeRefused, edns0.EDESig0KeyValidationFailed, errBootstrapValidationFailed, false},
		{"plain REFUSED", dns.RcodeRefused, 0, nil, false},
		{"SERVFAIL", dns.RcodeServerFailure, 0, errBootstrapTransient, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd, sak := ceremonyChild(t)
			var addr string
			if tc.ede != 0 {
				addr = startRcodeEDEResponder(t, tc.rcode, tc.ede)
			} else {
				addr = startRcodeResponder(t, tc.rcode)
			}
			_, ur, err := zd.sendSig0BootstrapCeremony(context.Background(), sak, []string{addr})
			if err == nil {
				t.Fatalf("the parent answered %s and the ceremony reported no error", dns.RcodeToString[tc.rcode])
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
			if got := errors.Is(err, errBootstrapTransient); got != tc.transient {
				t.Errorf("not final=%v, want %v (%v)", got, tc.transient, err)
			}
			// The parent's answer is still there for callers that read it.
			if ur.Rcode != tc.rcode || (tc.ede != 0 && ur.EDECode != tc.ede) {
				t.Errorf("UpdateResult rcode %s EDE %d, want %s EDE %d",
					dns.RcodeToString[ur.Rcode], ur.EDECode, dns.RcodeToString[tc.rcode], tc.ede)
			}
		})
	}

	t.Run("unreachable parent", func(t *testing.T) {
		zd, sak := ceremonyChild(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		dead := ln.Addr().String()
		ln.Close()
		_, _, err = zd.sendSig0BootstrapCeremony(context.Background(), sak, []string{dead})
		if !errors.Is(err, errBootstrapTransient) {
			t.Errorf("error %v, want one that is not final", err)
		}
	})

	t.Run("NOERROR", func(t *testing.T) {
		zd, sak := ceremonyChild(t)
		if _, _, err := zd.sendSig0BootstrapCeremony(context.Background(), sak,
			[]string{startRcodeResponder(t, dns.RcodeSuccess)}); err != nil {
			t.Errorf("an accepted ceremony reported %v", err)
		}
	})
}

// The rig's case: the parent reports the retired key unknown, the poll
// bootstraps, and the parent refuses it. The poll ends there, with the
// reason, instead of polling a parent that will never take the key.
func TestAPollEndsAtTheFirstRefusalOfARetiredKey(t *testing.T) {
	zd, sak := ceremonyChild(t)
	parent := retiredKeyParent(t)
	inquiries, bootstraps := 0, 0
	poll := parentKeyStatePoll{
		zone:  ZoneName(zd.ZoneName),
		keyid: sak.Keys[0].KeyRR.KeyTag(),
		query: func(context.Context) (*edns0.KeyStateOption, bool, error) {
			inquiries++
			return &edns0.KeyStateOption{KeyState: edns0.KeyStateUnknown}, true, nil
		},
		record: func(uint8) {},
		bootstrap: func(ctx context.Context) error {
			bootstraps++
			_, _, err := zd.sendSig0BootstrapCeremony(ctx, sak, []string{parent})
			return err
		},
		pollDelay:        time.Millisecond,
		wait:             func(context.Context, time.Duration) bool { return true },
		reBootstrapDelay: childReBootstrapDelay,
	}
	err := (&Config{}).pollParentKeyState(context.Background(), poll)
	if !errors.Is(err, ErrSig0KeyTombstoned) {
		t.Fatalf("poll ended with %v, want ErrSig0KeyTombstoned", err)
	}
	if inquiries != 1 || bootstraps != 1 {
		t.Errorf("%d inquiries and %d bootstraps, want 1 and 1", inquiries, bootstraps)
	}
}

// A re-bootstrap after a failed validation that the parent refuses for a
// retired key ends the poll too; it does not poll the parent anyway.
func TestTheReBootstrapRoundEndsOnARetiredKey(t *testing.T) {
	kp := &keyStateParent{t: t, waitOK: true, answers: [][]uint8{
		{edns0.KeyStateValidationFail}, {edns0.KeyStateUnknown},
	}}
	poll := kp.poll()
	poll.bootstrapped = true
	poll.bootstrap = func(context.Context) error {
		kp.bootstraps++
		kp.asked = 0
		return bootstrapOutcome(UpdateResult{Rcode: dns.RcodeRefused, EDEFound: true, EDECode: edns0.EDESig0KeyRetired}, nil)
	}
	err := (&Config{}).pollParentKeyState(context.Background(), poll)
	if !errors.Is(err, ErrSig0KeyTombstoned) {
		t.Fatalf("poll ended with %v, want ErrSig0KeyTombstoned", err)
	}
	if kp.bootstraps != 1 || kp.asked != 0 {
		t.Errorf("%d re-bootstraps and %d inquiries after it, want 1 and 0", kp.bootstraps, kp.asked)
	}
}

// No answer, SERVFAIL, or a parent still verifying the key is not a verdict:
// the poll asks again rather than giving up.
func TestAPollRetriesABootstrapThatIsNotFinal(t *testing.T) {
	answers := []uint8{edns0.KeyStateUnknown, edns0.KeyStateUnknown, edns0.KeyStateTrusted}
	asked, bootstraps := 0, 0
	poll := parentKeyStatePoll{
		zone:  "child.example.",
		keyid: 4711,
		query: func(context.Context) (*edns0.KeyStateOption, bool, error) {
			s := answers[min(asked, len(answers)-1)]
			asked++
			return &edns0.KeyStateOption{KeyState: s}, true, nil
		},
		record: func(uint8) {},
		bootstrap: func(context.Context) error {
			bootstraps++
			if bootstraps == 1 {
				return bootstrapOutcome(UpdateResult{Rcode: dns.RcodeServerFailure}, nil)
			}
			return nil
		},
		pollDelay:        time.Millisecond,
		wait:             func(context.Context, time.Duration) bool { return true },
		reBootstrapDelay: childReBootstrapDelay,
	}
	if err := (&Config{}).pollParentKeyState(context.Background(), poll); err != nil {
		t.Fatalf("poll ended with %v", err)
	}
	if bootstraps != 2 {
		t.Errorf("%d bootstraps, want 2: the one the parent failed, then the one it took", bootstraps)
	}
}

// A BADKEY whose re-bootstrap the parent refuses for a retired key ends the
// UPDATE with that reason. The refusal used to count as a re-bootstrap, and
// the UPDATE ended "still BADKEY after re-bootstrap".
func TestABADKEYReBootstrapOfARetiredKeyEndsTheUpdate(t *testing.T) {
	zd, sak := ceremonyChild(t)
	parent := retiredKeyParent(t)
	sends, reboots := 0, 0
	_, _, err := sendUpdateWithRetry(context.Background(), 5, time.Millisecond,
		func() (int, UpdateResult, error) { sends++; return dns.RcodeBadKey, UpdateResult{}, nil },
		func() error {
			reboots++
			_, _, err := zd.sendSig0BootstrapCeremony(context.Background(), sak, []string{parent})
			return err
		})
	if !errors.Is(err, ErrSig0KeyTombstoned) {
		t.Fatalf("UPDATE ended with %v, want ErrSig0KeyTombstoned", err)
	}
	if sends != 1 || reboots != 1 {
		t.Errorf("%d sends and %d re-bootstraps, want 1 and 1", sends, reboots)
	}
}
