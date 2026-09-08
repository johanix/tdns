package tdns

import (
	"context"
	"errors"
	"testing"
	"time"
)

// #575: the child-authoritative bootstrap needs the IMR, because the parent
// zone is discovered rather than configured. At startup DELEGATION-SYNC-SETUP
// routinely arrives before InitImrEngine has published the engine, and the
// failure was logged and the request DROPPED -- "ignoring sync request".
// Nothing retried it, so a child never bootstrapped unaided: every key had to
// be presented to the parent by hand after the daemon settled.
//
// The proxy arm of the same loop already deferred for this. This is the same
// signal, for the setup arm.
func TestBootstrapSetupComesBackOnceTheImrIsReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := make(chan DelegationSyncRequest, 1)
	ready := NewImrReadiness()
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."}

	_ = deferForImr(ctx, q, ready, ds)

	select {
	case got := <-q:
		t.Fatalf("the setup request came back before the IMR was ready: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}

	ready.Publish()

	select {
	case got := <-q:
		if got.Command != "DELEGATION-SYNC-SETUP" || got.ZoneName != "child.example." {
			t.Errorf("re-enqueued the wrong request: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the setup request never came back; this is the one chance the child gets" +
			" to bootstrap, and losing it means the key is never presented to the parent")
	}
}

// The failure is matched on the condition, not on its prose, so a caller cannot
// stop recognising it by someone rewording the message.
func TestMissingImrIsAMatchableCondition(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.example."}

	// No IMR anywhere: exactly the state the first seconds of a process are in.
	prev := Globals.ImrEngine
	Globals.ImrEngine = nil
	t.Cleanup(func() { Globals.ImrEngine = prev })
	prevConf := Conf.Internal.ImrEngine
	Conf.Internal.ImrEngine = nil
	t.Cleanup(func() { Conf.Internal.ImrEngine = prevConf })

	err := zd.resolveParentZone()
	if err == nil {
		t.Skip("this build resolves a parent without an IMR")
	}
	if !errors.Is(err, ErrNoImrEngine) {
		t.Errorf("resolveParentZone reported %v, which does not match ErrNoImrEngine."+
			" The syncher then cannot tell 'the IMR is not up yet' from a real failure,"+
			" and drops a request that should have been deferred", err)
	}
}
