package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// johanix/tdns-mp#211, step P3: an application that reads the zone owner's
// instructions by its own rules tells tdns whether the agents sync a zone's
// delegation, and tdns asks it, in place of its own copy of the zone. Both
// readers ask it: the start of the agent's key poll, and the poll's check
// before every step (#926).

// parentSyncZone registers a zone whose HSYNCPARAM says parentsync=who, or a
// zone with no HSYNCPARAM when who is "".
func parentSyncZone(t *testing.T, zone, who string) {
	t.Helper()
	owners := map[string][]dns.RR{zone: {mustRR(t, zone+` 3600 IN TXT "no HSYNCPARAM"`)}}
	if who != "" {
		owners[zone] = []dns.RR{mustRR(t, zone+` 3600 IN HSYNCPARAM parentsync="`+who+`"`)}
	}
	registerZones(t, newMapZone(zone, Secondary, owners))
}

func TestTheParentSyncHookOverridesTheCopy(t *testing.T) {
	const agents, owners = "agents.hook.example.", "owner.hook.example."
	parentSyncZone(t, agents, "agent")
	parentSyncZone(t, owners, "owner")
	t.Cleanup(func() { RegisterParentSyncAgentFunc(nil) })

	var asked []ZoneName
	RegisterParentSyncAgentFunc(func(zone ZoneName) bool {
		asked = append(asked, zone)
		return zone == owners // the opposite of each copy
	})
	if ZoneHasParentSyncAgent(agents) {
		t.Errorf("%s: the copy says agent, the hook says not; got agent", agents)
	}
	if !ZoneHasParentSyncAgent(owners) {
		t.Errorf("%s: the copy says owner, the hook says agent; got owner", owners)
	}
	// the poll's check before each step asks the hook too
	if agentKeyStatePoll(nil, nil, agents, agents, 1, dns.ED25519).agentsSync() {
		t.Errorf("%s: the poll's check read the copy, not the hook", agents)
	}
	if len(asked) != 3 {
		t.Errorf("the hook was asked %d times (%v), want 3", len(asked), asked)
	}

	RegisterParentSyncAgentFunc(nil)
	if !ZoneHasParentSyncAgent(agents) || ZoneHasParentSyncAgent(owners) {
		t.Error("with the hook cleared, the copies are not read again")
	}
}

func TestNoHookReadsTheCopy(t *testing.T) {
	const agents, owners, none = "agents.nohook.example.", "owner.nohook.example.", "none.nohook.example."
	parentSyncZone(t, agents, "agent")
	parentSyncZone(t, owners, "owner")
	parentSyncZone(t, none, "")
	for zone, want := range map[ZoneName]bool{agents: true, owners: false, none: false, "unknown.nohook.example.": false} {
		if got := ZoneHasParentSyncAgent(zone); got != want {
			t.Errorf("%s: %v, want %v", zone, got, want)
		}
		if got := agentKeyStatePoll(nil, nil, zone, string(zone), 1, dns.ED25519).agentsSync(); got != want {
			t.Errorf("%s, the poll's check: %v, want %v", zone, got, want)
		}
	}
}
