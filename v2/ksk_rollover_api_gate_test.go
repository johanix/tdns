package tdns

import (
	"errors"
	"slices"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func gateDsyncRR(scheme core.DsyncScheme, rrtype uint16, target string) *core.DSYNC {
	return &core.DSYNC{Type: rrtype, Scheme: scheme, Port: 443, Target: target}
}

func setRolloverApiAllowInsecure(t *testing.T, v bool) {
	t.Helper()
	prevCS, prevPS := *ChildSyncConfig(), *ParentSyncConfig()
	next := prevPS
	next.Api.AllowInsecure = v
	SetDelegationSyncConfig(prevCS, next)
	t.Cleanup(func() { SetDelegationSyncConfig(prevCS, prevPS) })
}

// The DS delivery must not use the API scheme off an unvalidated DSYNC
// lookup. The DSYNC RR names the target whose URI carries the endpoint the
// push posts a bearer credential to, so an unvalidated lookup lets whoever
// answers the query choose where the credential goes.
//
// UPDATE and NOTIFY carry no secret and must stay available either way;
// gating them too would take a zone that can still sync and strand it. The
// gate is the parent sync plan's; this pins that the rollover's delivery
// goes through it.
func TestDSDeliveryApiSchemeRequiresAValidatedDsyncLookup(t *testing.T) {
	zd := dsSyncTestZone(t)
	setChildApiCredentials(t, ParentSyncApiCredentialConf{Parent: "example.", Username: "u", Key: "k"})
	all := []*core.DSYNC{
		gateDsyncRR(core.SchemeUpdate, dns.TypeANY, "upd.example."),
		gateDsyncRR(core.SchemeNotify, dns.TypeCDS, "ntf.example."),
		gateDsyncRR(core.SchemeAPI, dns.TypeANY, "api.example."),
	}
	apiOnly := all[2:]
	auto := dsSyncPolicy(DsyncSchemePreferenceAuto)

	t.Run("unvalidated: API is dropped, the others survive", func(t *testing.T) {
		setRolloverApiAllowInsecure(t, false)
		choices, _, _, err := rolloverSchemeChoices(dsSyncPlanFor(t, zd, DsyncResult{Validated: false, Rdata: all}, nil), auto)
		if err != nil {
			t.Fatalf("scheme choice: %v", err)
		}
		if got := dsSyncChoiceTargets(choices); !slices.Equal(got, []string{"UPDATE upd.example.", "NOTIFY ntf.example."}) {
			t.Errorf("choices %v; UPDATE and NOTIFY carry no secret and need no validation", got)
		}
		_, _, _, err = rolloverSchemeChoices(dsSyncPlanFor(t, zd, DsyncResult{Validated: false, Rdata: apiOnly}, nil), auto)
		if !errors.Is(err, errNoUsableScheme) {
			t.Errorf("API only, unvalidated: err = %v; the API scheme survived an unvalidated DSYNC lookup,"+
				" the bearer credential could be posted to an attacker-chosen endpoint", err)
		}
	})

	t.Run("validated: API is available", func(t *testing.T) {
		setRolloverApiAllowInsecure(t, false)
		choices, _, _, err := rolloverSchemeChoices(dsSyncPlanFor(t, zd, DsyncResult{Validated: true, Rdata: apiOnly}, nil), auto)
		if err != nil {
			t.Fatalf("the API scheme was dropped despite a validated DSYNC lookup: %v", err)
		}
		if got := dsSyncChoiceTargets(choices); !slices.Equal(got, []string{"API api.example."}) {
			t.Errorf("choices %v, want the API target", got)
		}
	})

	t.Run("allow-insecure is the operator accepting the risk", func(t *testing.T) {
		setRolloverApiAllowInsecure(t, true)
		choices, _, _, err := rolloverSchemeChoices(dsSyncPlanFor(t, zd, DsyncResult{Validated: false, Rdata: apiOnly}, nil), auto)
		if err != nil {
			t.Fatalf("allow-insecure did not re-enable the API scheme: %v", err)
		}
		if got := dsSyncChoiceTargets(choices); !slices.Equal(got, []string{"API api.example."}) {
			t.Errorf("choices %v, want the API target", got)
		}
	})
}
