package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func gateDsyncRR(scheme core.DsyncScheme, rrtype uint16, target string) *core.DSYNC {
	return &core.DSYNC{Type: rrtype, Scheme: scheme, Port: 443, Target: target}
}

func setRolloverApiAllowInsecure(t *testing.T, v bool) {
	t.Helper()
	prev := DelegationSyncConfig()
	next := *prev
	next.Child.Api.AllowInsecure = v
	SetDelegationSyncConfig(next)
	t.Cleanup(func() { SetDelegationSyncConfig(*prev) })
}

// The rollover DS push must not use the API scheme off an unvalidated DSYNC
// lookup. The DSYNC RR names the target whose URI carries the endpoint the push
// posts a bearer credential to, so an unvalidated lookup lets whoever answers
// the query choose where the credential goes.
//
// UPDATE and NOTIFY carry no secret and must stay available either way --
// gating them too would take a zone that can still sync and strand it.
func TestRolloverApiSchemeRequiresAValidatedDsyncLookup(t *testing.T) {
	rdata := []*core.DSYNC{
		gateDsyncRR(core.SchemeUpdate, dns.TypeANY, "upd.example."),
		gateDsyncRR(core.SchemeNotify, dns.TypeCDS, "ntf.example."),
		gateDsyncRR(core.SchemeAPI, dns.TypeANY, "api.example."),
	}

	t.Run("unvalidated: API is dropped, the others survive", func(t *testing.T) {
		setRolloverApiAllowInsecure(t, false)
		upd, ntf, api := selectRolloverDsyncRRs(DsyncResult{Validated: false, Rdata: rdata}, "child.example.")
		if api != nil {
			t.Error("the API scheme survived an unvalidated DSYNC lookup;" +
				" the bearer credential could be posted to an attacker-chosen endpoint")
		}
		if upd == nil {
			t.Error("UPDATE was dropped; it carries no secret and needs no validation")
		}
		if ntf == nil {
			t.Error("NOTIFY was dropped; it carries no secret and needs no validation")
		}
	})

	t.Run("validated: API is available", func(t *testing.T) {
		setRolloverApiAllowInsecure(t, false)
		_, _, api := selectRolloverDsyncRRs(DsyncResult{Validated: true, Rdata: rdata}, "child.example.")
		if api == nil {
			t.Fatal("the API scheme was dropped despite a validated DSYNC lookup")
		}
		if api.Target != "api.example." {
			t.Errorf("API target = %q, want api.example.", api.Target)
		}
	})

	t.Run("allow-insecure is the operator accepting the risk", func(t *testing.T) {
		setRolloverApiAllowInsecure(t, true)
		_, _, api := selectRolloverDsyncRRs(DsyncResult{Validated: false, Rdata: rdata}, "child.example.")
		if api == nil {
			t.Fatal("allow-insecure did not re-enable the API scheme")
		}
	})
}
