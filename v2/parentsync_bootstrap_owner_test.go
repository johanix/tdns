package tdns

import (
	"context"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// An agent polls the parent for its SIG(0) key for many minutes, bootstrapping
// and re-bootstrapping as the parent answers. The zone's owner may take the
// delegation sync over meanwhile (HSYNCPARAM parentsync=owner). The poll asked
// HSYNCPARAM only at its start, and so went on sending the agent's bootstrap
// UPDATE to the parent of a zone whose owner syncs it.

// agentsZone registers a zone whose HSYNCPARAM says parentsync=agent, and
// returns what serves it again with parentsync=owner, as a refresh does that
// brings the owner's edit.
func agentsZone(t *testing.T, zone string) (ownerTakesOver func()) {
	t.Helper()
	hsyncparam := func(who string) dns.RR {
		return mustRR(t, zone+` 3600 IN HSYNCPARAM parentsync="`+who+`"`)
	}
	zd := newMapZone(zone, Secondary, map[string][]dns.RR{zone: {hsyncparam("agent")}})
	registerZones(t, zd)
	if !ZoneHasParentSyncAgent(ZoneName(zone)) {
		t.Fatal("the zone does not say parentsync=agent to start with")
	}
	return func() {
		apex, _ := zd.Data.Get(zone)
		apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{Name: zone, RRtype: core.TypeHSYNCPARAM,
			RRs: []dns.RR{hsyncparam("owner")}})
		zd.Data.Set(zone, apex)
		zd.InstallInitialSnapshot()
	}
}

// sentToParent counts what the agent's poll sent the parent, and asked for.
type sentToParent struct {
	inquiries, bootstraps, delegationSyncs int
}

func TestTheAgentsPollStopsWhenTheOwnerTakesTheSyncOver(t *testing.T) {
	const zone = "child.example."
	for _, tc := range []struct {
		name    string
		answers [][]uint8 // per bootstrap round, as keyStateParent plays them
		// after: the inquiry after whose answer the owner takes over; 0 is
		// while the poll waits to re-bootstrap.
		after int
		// what the poll sends while the agents sync the zone, and when the
		// owner takes over
		agents, owner sentToParent
	}{
		{"the parent does not know the key",
			[][]uint8{{edns0.KeyStateUnknown}, {edns0.KeyStateTrusted}}, 1,
			sentToParent{2, 1, 1}, sentToParent{1, 0, 0}},
		{"the parent is verifying the key",
			[][]uint8{{edns0.KeyStateBootstrapAutoOngoing, edns0.KeyStateBootstrapAutoOngoing, edns0.KeyStateTrusted}}, 2,
			sentToParent{3, 0, 1}, sentToParent{2, 0, 0}},
		{"the parent failed the key",
			[][]uint8{{edns0.KeyStateValidationFail}, {edns0.KeyStateTrusted}}, 0,
			sentToParent{2, 1, 1}, sentToParent{1, 0, 0}},
		{"the parent trusts the key",
			[][]uint8{{edns0.KeyStateTrusted}}, 1,
			sentToParent{1, 0, 1}, sentToParent{1, 0, 0}},
	} {
		for _, takeOver := range []bool{false, true} {
			name := tc.name + ", the agents sync"
			want := tc.agents
			if takeOver {
				name, want = tc.name+", the owner takes over", tc.owner
			}
			t.Run(name, func(t *testing.T) {
				ownerTakesOver := agentsZone(t, zone)
				conf := &Config{}
				conf.Internal.DelegationSyncQ = make(chan DelegationSyncRequest, 1)
				kp := &keyStateParent{t: t, waitOK: true, answers: tc.answers}
				parent := kp.poll()

				// The agent's own poll, with keyStateParent as the parent.
				poll := agentKeyStatePoll(nil, nil, zone, zone, 4711, dns.ED25519)
				var got sentToParent
				poll.query = func(ctx context.Context) (*edns0.KeyStateOption, bool, error) {
					got.inquiries++
					ks, auth, err := parent.query(ctx)
					if takeOver && got.inquiries == tc.after {
						ownerTakesOver()
					}
					return ks, auth, err
				}
				poll.record = parent.record
				poll.bootstrap = parent.bootstrap
				poll.pollDelay = time.Millisecond
				poll.wait = func(ctx context.Context, d time.Duration) bool {
					if takeOver && tc.after == 0 {
						ownerTakesOver()
					}
					return parent.wait(ctx, d)
				}

				if err := conf.pollParentKeyState(context.Background(), poll); err != nil {
					t.Fatalf("the poll ended with %v", err)
				}
				got.bootstraps = kp.bootstraps
				got.delegationSyncs = len(conf.Internal.DelegationSyncQ)
				if got != want {
					t.Errorf("sent the parent %+v, want %+v", got, want)
				}
			})
		}
	}
}
