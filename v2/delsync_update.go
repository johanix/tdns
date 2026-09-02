package tdns

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// SendDelegationUpdate is the single child-side UPDATE sender. Both the
// tdns-auth child path and the tdns-agent proxy produce a DelegationSyncStatus
// and call this; the role only supplies the mode default (child: delta, proxy:
// replace). The §10.8 UPDATE gate stays in updateGateBlocked, not here.
func (zd *ZoneData) SendDelegationUpdate(ctx context.Context, kdb *KeyDB,
	syncstate DelegationSyncStatus, target *DsyncTarget, mode string) (string, uint8, UpdateResult, error) {

	if target == nil || len(target.Addresses) == 0 {
		return "", 0, UpdateResult{}, fmt.Errorf("SendDelegationUpdate: no usable UPDATE target for %s", zd.ZoneName)
	}
	if zd.Parent == "" || zd.Parent == "." {
		return "", 0, UpdateResult{}, fmt.Errorf("SendDelegationUpdate: parent zone for %s is unknown", zd.ZoneName)
	}

	var m *dns.Msg
	var err error
	if mode == UpdateModeReplace {
		lgDns.Info("SendDelegationUpdate: using replace mode", "zone", zd.ZoneName)
		m, err = CreateChildReplaceUpdateWithDS(zd.Parent, zd.ZoneName,
			syncstate.NewNS, syncstate.NewA, syncstate.NewAAAA,
			syncstate.NewDS, syncstate.NewDSKnown)
	} else {
		lgDns.Info("SendDelegationUpdate: using delta mode", "zone", zd.ZoneName)
		adds := append([]dns.RR{}, syncstate.NsAdds...)
		adds = append(adds, syncstate.AAdds...)
		adds = append(adds, syncstate.AAAAAdds...)
		adds = append(adds, syncstate.DSAdds...)
		removes := append([]dns.RR{}, syncstate.NsRemoves...)
		removes = append(removes, syncstate.ARemoves...)
		removes = append(removes, syncstate.AAAARemoves...)
		removes = append(removes, syncstate.DSRemoves...)
		m, err = CreateChildUpdate(zd.Parent, zd.ZoneName, adds, removes)
	}
	if err != nil {
		return "", 0, UpdateResult{}, err
	}

	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return "", 0, UpdateResult{}, fmt.Errorf("keystore lookup for %s: %w", zd.ZoneName, err)
	}
	if sak == nil || len(sak.Keys) == 0 {
		return "", 0, UpdateResult{}, fmt.Errorf("no active SIG(0) key for %s", zd.ZoneName)
	}
	smsg, err := SignMsg(*m, zd.ZoneName, sak)
	if err != nil {
		return "", 0, UpdateResult{}, err
	}
	if smsg == nil {
		return "", 0, UpdateResult{}, fmt.Errorf("signing UPDATE for %s produced no message and no error", zd.ZoneName)
	}

	lgDns.Info("SendDelegationUpdate: sending the signed update",
		"zone", zd.ZoneName, "target", target.Name, "addresses", target.Addresses, "port", target.Port)

	rcode, ur, err := zd.SendUpdateWithRetry(ctx, smsg, zd.Parent, target.Addresses)
	if err != nil {
		return "", 0, ur, err
	}
	msg := fmt.Sprintf("SendUpdate(%s) returned rcode %s", zd.Parent, dns.RcodeToString[rcode])
	lgDns.Info("SendDelegationUpdate: update sent",
		"zone", zd.ZoneName, "parent", zd.Parent, "mode", mode, "rcode", dns.RcodeToString[rcode])
	return msg, uint8(rcode), ur, nil
}

// apexKEYEnsurer is the one role-dependent step of SIG(0) bootstrap: the KEY
// RR must be at the child apex before the ceremony is sent. tdns-auth
// publishes it; the proxy waits for the operator (the §10.8 WAITING state)
// and is a no-op once READY.
type apexKEYEnsurer interface {
	EnsureApexKEY() error
}

type authApexKEY struct {
	zd  *ZoneData
	kdb *KeyDB
	alg uint8
}

func (a authApexKEY) EnsureApexKEY() error {
	return a.zd.Sig0KeyPreparation(a.zd.ZoneName, a.alg, a.kdb)
}

type proxyApexKEY struct{}

func (proxyApexKEY) EnsureApexKEY() error { return nil }

func (zd *ZoneData) bootstrapSig0Key(ctx context.Context, alg uint8, apex apexKEYEnsurer) (string, UpdateResult, error) {
	if err := apex.EnsureApexKEY(); err != nil {
		return "", UpdateResult{}, err
	}
	return zd.BootstrapSig0KeyWithParent(ctx, alg)
}
