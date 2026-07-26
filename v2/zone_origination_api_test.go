package tdns

import (
	"strings"
	"testing"
)

// Fix C: the API origination gate. Actions that write into a zone or advance
// its serial are refused on a tdns-auth secondary; read-only and
// legitimately-secondary actions are not.

// TestOriginationAPICommandSet pins exactly which commands are gated. The list
// is deliberately explicit: it is short by several in the original audit, and
// the two easy mistakes are forgetting policy-reset (an origination action that
// reads as bookkeeping) and gating write-zone (which is legitimate on a
// secondary).
func TestOriginationAPICommandSet(t *testing.T) {
	gated := []string{
		"bump", "sign-zone", "resign-zone",
		"policy-set", "change-policy", "policy-reset", "generate-nsec",
		"publish-dsync-rrset", "unpublish-dsync-rrset",
	}
	for _, cmd := range gated {
		if !originationAPICommands[cmd] {
			t.Errorf("%q must be gated as an origination action", cmd)
		}
	}

	ungated := []string{
		"write-zone",      // dumping a transferred zone to disk is legitimate
		"list-zones",      // read-only
		"show-nsec-chain", // read-only
		"reload",          // re-pull from upstream: the opposite of originating
		"status",          // read-only (dsync handler)
		"freeze", "thaw",  // gated, but at their own cases (ordering matters)
	}
	for _, cmd := range ungated {
		if originationAPICommands[cmd] {
			t.Errorf("%q must NOT be in the blanket origination set", cmd)
		}
	}
}

// TestZoneOriginationRefusal covers the helper every Fix C call site uses.
func TestZoneOriginationRefusal(t *testing.T) {
	secondary := &ZoneData{ZoneName: "sec.example.", ZoneType: Secondary, Options: map[ZoneOption]bool{}}
	primary := &ZoneData{ZoneName: "pri.example.", ZoneType: Primary, Options: map[ZoneOption]bool{}}
	inline := &ZoneData{ZoneName: "sig.example.", ZoneType: Secondary,
		Options: map[ZoneOption]bool{OptInlineSigning: true}}

	withAppType(t, AppTypeAuth)

	msg := zoneOriginationRefusal(secondary, "bump")
	if msg == "" {
		t.Fatal("a plain auth secondary must be refused")
	}
	// The message has to be actionable: name the zone, the action, and why.
	for _, want := range []string{"sec.example.", "bump", "may not originate"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message missing %q: %s", want, msg)
		}
	}

	if got := zoneOriginationRefusal(primary, "bump"); got != "" {
		t.Errorf("primary must not be refused, got %q", got)
	}
	if got := zoneOriginationRefusal(inline, "bump"); got != "" {
		t.Errorf("inline-signing secondary must not be refused, got %q", got)
	}

	// §1.1: off tdns-auth nothing is refused.
	withAppType(t, AppTypeAgent)
	if got := zoneOriginationRefusal(secondary, "bump"); got != "" {
		t.Errorf("non-auth app must not be refused, got %q", got)
	}
}

// TestCatalogAuthoringRefusedOnSecondary drives the real catalog authoring
// path. regenerateCatalogZone rewrites the catalog zone's own PTR/TXT records
// and publishes, so it is authoring and must be refused on a secondary — while
// catalog CONSUMPTION (auto-create/delete of member zones) is untouched, since
// that acts on other zones and is the whole point of RFC 9432.
func TestCatalogAuthoringRefusedOnSecondary(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Secondary
	zd.Options = map[ZoneOption]bool{OptCatalogZone: true}

	err := regenerateCatalogZone(zd.ZoneName)
	if err == nil {
		t.Fatal("catalog authoring must be refused on a secondary catalog zone")
	}
	if !strings.Contains(err.Error(), "may not originate") {
		t.Errorf("unexpected refusal reason: %v", err)
	}
}

// TestCatalogAuthoringAllowedOnPrimary is the other half: the gate must not
// break the ordinary case.
func TestCatalogAuthoringAllowedOnPrimary(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Primary
	zd.Options = map[ZoneOption]bool{OptCatalogZone: true}

	// May still fail for unrelated reasons in a unit context, but it must not
	// fail with the origination refusal.
	if err := regenerateCatalogZone(zd.ZoneName); err != nil &&
		strings.Contains(err.Error(), "may not originate") {
		t.Errorf("primary catalog zone was wrongly refused: %v", err)
	}
}
