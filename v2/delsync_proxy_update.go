/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * delegation-sync-proxy, UPDATE path (P-5): the precondition + KEY-bootstrap
 * state machine (§10.8 of the plan). Before the agent can proxy DNS UPDATEs to
 * the parent on a clueless primary's behalf it must (a) confirm the parent
 * actually advertises a DSYNC UPDATE receiver, and (b) hold a SIG(0) key whose
 * public KEY is published at the child apex so the parent trusts the UPDATE
 * (path-3 validation). Since the agent is a SECONDARY it cannot publish that KEY
 * itself — the operator must add it at the primary — so this code generates the
 * key and instructs the operator, holding off on UPDATEs until the KEY appears.
 *
 * None of these conditions hard-fails: the agent starts, the zone is served, and
 * a not-yet-operable UPDATE proxy is a per-zone WARNING (visible on `zone list`),
 * matching the resilient-config quarantine model. The NOTIFY proxy (P-2/P-3) is
 * unaffected and may still apply.
 */
package tdns

import (
	"context"
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ProxyUpdateState is the result of the UPDATE-proxy precondition check (§10.8).
type ProxyUpdateState string

const (
	// ProxyUpdateUnsupported: the parent does not advertise a DSYNC UPDATE
	// receiver. UPDATE-proxy is not applicable; NOTIFY proxy may still apply.
	// No key is generated and the operator is not asked to publish anything.
	ProxyUpdateUnsupported ProxyUpdateState = "update-unsupported"
	// ProxyUpdateReady: the parent advertises UPDATE and the agent holds the
	// private key for a KEY published at the child apex. Proxied UPDATEs can be
	// signed and sent.
	ProxyUpdateReady ProxyUpdateState = "ready"
	// ProxyUpdateForeignKey: a KEY is published at the apex but the agent does
	// not hold its private key. The agent must not mint a competing key; the
	// UPDATE proxy is not operable for this zone.
	ProxyUpdateForeignKey ProxyUpdateState = "foreign-key"
	// ProxyUpdateWaiting: the parent advertises UPDATE but no KEY is published
	// yet. The agent has generated (or already holds) a keypair and is waiting
	// for the operator to publish the KEY (+ HSYNCPARAM pubkey) at the primary.
	ProxyUpdateWaiting ProxyUpdateState = "waiting-for-key"
)

// proxyApexKEYs returns the KEY RRs published at the zone apex (empty if none).
func (zd *ZoneData) proxyApexKEYs() []dns.RR {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return nil
	}
	rrset, ok := apex.RRtypes.Get(dns.TypeKEY)
	if !ok {
		return nil
	}
	return rrset.RRs
}

// proxyHoldsPrivateKeyFor reports whether the keystore has an active SIG(0)
// private key matching one of the published apex KEYs (by keytag).
func (zd *ZoneData) proxyHoldsPrivateKeyFor(kdb *KeyDB, apexKeys []dns.RR) bool {
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil || sak == nil || len(sak.Keys) == 0 {
		return false
	}
	for _, pub := range apexKeys {
		key, ok := pub.(*dns.KEY)
		if !ok {
			continue
		}
		for _, held := range sak.Keys {
			if held.KeyRR.KeyTag() == key.KeyTag() {
				return true
			}
		}
	}
	return false
}

// ProxyUpdatePreconditionCheck runs the §10.8 state machine for a
// delegation-sync-proxy zone and returns the resulting state. It is
// side-effecting in the WAITING state only: it generates a SIG(0) keypair if the
// keystore has none, so the operator instruction (proxyBootstrapInstruction) can
// be produced. It records a per-zone WARNING for the non-ready, UPDATE-relevant
// states and clears it when ready; it never returns a hard error for an
// operationally-degraded state (only for genuine internal failures).
func (zd *ZoneData) ProxyUpdatePreconditionCheck(ctx context.Context, kdb *KeyDB, imr *Imr) (ProxyUpdateState, error) {
	// Step 1 (gate): does the parent advertise a DSYNC UPDATE receiver?
	// LookupDSYNCTarget with SchemeUpdate both detects support and would resolve
	// the target; here we only need the yes/no. A lookup error or no target ⇒
	// not supported (not a hard failure — the parent may simply not offer it).
	if imr == nil {
		return ProxyUpdateUnsupported, nil
	}
	target, err := imr.LookupDSYNCTarget(ctx, zd.ZoneName, dns.TypeANY, core.SchemeUpdate)
	if err != nil || target == nil {
		lgDns.Debug("proxy update precondition: parent advertises no DSYNC UPDATE target",
			"zone", zd.ZoneName, "err", err)
		zd.clearProxyUpdateWarning()
		return ProxyUpdateUnsupported, nil
	}

	// Step 2: inspect the apex KEY RRset.
	apexKeys := zd.proxyApexKEYs()
	if len(apexKeys) > 0 {
		if zd.proxyHoldsPrivateKeyFor(kdb, apexKeys) {
			zd.clearProxyUpdateWarning()
			lgDns.Info("proxy update precondition: ready (KEY at apex, private key held)", "zone", zd.ZoneName)
			return ProxyUpdateReady, nil
		}
		// Foreign KEY: do not mint a competing key; degrade, don't fail.
		msg := "DSYNC UPDATE proxy not operable: a foreign KEY occupies the apex (no matching private key); NOTIFY proxy may still apply"
		zd.SetError(DelegationSyncWarning, "%s", msg)
		lgDns.Warn("proxy update precondition: foreign KEY at apex", "zone", zd.ZoneName)
		return ProxyUpdateForeignKey, nil
	}

	// No KEY at the apex: ensure we have a keypair, then instruct the operator.
	if err := zd.proxyEnsureSig0Key(kdb); err != nil {
		// Keygen failure is a genuine internal error; still don't take the zone
		// down — degrade with a warning.
		msg := fmt.Sprintf("DSYNC UPDATE proxy not operable: failed to prepare SIG(0) key: %v", err)
		zd.SetError(DelegationSyncWarning, "%s", msg)
		lgDns.Error("proxy update precondition: keygen failed", "zone", zd.ZoneName, "err", err)
		return ProxyUpdateWaiting, err
	}
	instr, ierr := zd.proxyBootstrapInstruction(kdb)
	if ierr != nil {
		lgDns.Error("proxy update precondition: could not build operator instruction", "zone", zd.ZoneName, "err", ierr)
	}
	msg := "DSYNC UPDATE proxy waiting: publish the KEY + HSYNCPARAM pubkey at the primary (see log / `keystore dnssec proxy-key`)"
	zd.SetError(DelegationSyncWarning, "%s", msg)
	lgDns.Warn("proxy update precondition: waiting for KEY publication at primary",
		"zone", zd.ZoneName, "instruction", instr)
	return ProxyUpdateWaiting, nil
}

// proxyEnsureSig0Key makes sure the keystore holds an active SIG(0) key for this
// zone, generating one if absent. Reuses the keystore Sig0KeyMgmt generate path
// (the same one DelegationSyncSetup uses for the child case), but does NOT
// publish the KEY into the zone — a secondary cannot author the zone.
func (zd *ZoneData) proxyEnsureSig0Key(kdb *KeyDB) error {
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return fmt.Errorf("GetSig0Keys: %w", err)
	}
	if sak != nil && len(sak.Keys) > 0 {
		return nil
	}
	alg, err := parseKeygenAlgorithm("delegationsync.child.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		return fmt.Errorf("keygen algorithm: %w", err)
	}
	kp := KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       zd.ZoneName,
		Keyname:    zd.ZoneName,
		Algorithm:  alg,
		State:      Sig0StateActive,
		Creator:    "delsync-proxy-setup",
	}
	if _, err := kdb.Sig0KeyMgmt(nil, kp); err != nil {
		return fmt.Errorf("Sig0KeyMgmt generate: %w", err)
	}
	lgDns.Info("delegation-sync-proxy: generated SIG(0) keypair for UPDATE proxy", "zone", zd.ZoneName)
	return nil
}

// proxyBootstrapInstruction returns the two records the operator must add at the
// primary apex (§10.8 U10): the agent's KEY RR and an HSYNCPARAM with the pubkey
// flag (the signal to all providers to republish the apex KEY). Returns the
// records as zone-file text.
func (zd *ZoneData) proxyBootstrapInstruction(kdb *KeyDB) (string, error) {
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return "", fmt.Errorf("GetSig0Keys: %w", err)
	}
	if sak == nil || len(sak.Keys) == 0 {
		return "", fmt.Errorf("no active SIG(0) key for zone %s", zd.ZoneName)
	}
	keyRR := sak.Keys[0].KeyRR
	keyRR.Hdr.Name = zd.ZoneName
	return keyRR.String() + "\n" + zd.proxyHsyncparamPubkeyRR(), nil
}

// proxyHsyncparamPubkeyRR returns the zone-file text for an HSYNCPARAM record
// carrying the pubkey flag at the zone apex.
func (zd *ZoneData) proxyHsyncparamPubkeyRR() string {
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{core.NewHsyncparamPubkeyFlag()}}
	return fmt.Sprintf("%s\t3600\tIN\tHSYNCPARAM\t%s", zd.ZoneName, hp.String())
}

// clearProxyUpdateWarning removes any delegation-sync-proxy UPDATE warning set
// on the zone (when the state becomes ready or update-unsupported).
func (zd *ZoneData) clearProxyUpdateWarning() {
	zd.ClearError(DelegationSyncWarning)
}

// proxyCurrentDelegationRRs reads the current authoritative delegation RRsets
// from the SERVED zone (the freshly-transferred data): the apex NS, the in-
// bailiwick glue (A/AAAA) for those nameservers, and the DS derived from the
// apex DNSKEY SEP keys. These are the replace-form UPDATE's "new members" — the
// payload never depends on the parent's state (that is the point of replace).
// For an unsigned zone newDS is empty (no DNSKEYs), which is correct.
func (zd *ZoneData) proxyCurrentDelegationRRs() (newNS, newA, newAAAA, newDS []dns.RR) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return nil, nil, nil, nil
	}
	newNS = apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs

	// In-bailiwick glue: A/AAAA for nameservers under the zone.
	for _, rr := range newNS {
		ns, ok := rr.(*dns.NS)
		if !ok || !dns.IsSubDomain(zd.ZoneName, ns.Ns) {
			continue
		}
		if owner, oerr := zd.GetOwner(ns.Ns); oerr == nil && owner != nil {
			newA = append(newA, owner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs...)
			newAAAA = append(newAAAA, owner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs...)
		}
	}

	// DS from the apex DNSKEY SEP keys (signed zones only).
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok && dnskey.Flags&dns.SEP != 0 {
			if ds := dnskey.ToDS(dns.SHA256); ds != nil {
				newDS = append(newDS, ds)
			}
		}
	}
	return newNS, newA, newAAAA, newDS
}

// proxyUpdateMode returns the parent-update form for the proxy: the operator's
// `parent-update` auth option if set, otherwise REPLACE (the proxy default —
// replace is idempotent and self-correcting, the right behavior for forwarding
// on a clueless primary's behalf). This mirrors the tdns-auth child path, which
// reads the same option but defaults to delta.
func proxyUpdateMode(kdb *KeyDB) string {
	if mode, ok := kdb.AuthOption(AuthOptParentUpdate); ok && mode != "" {
		return mode
	}
	return UpdateModeReplace
}

// ProxyUpdateParent forwards a DNS UPDATE to the parent on behalf of a
// DSYNC-unaware primary, signed with the agent's SIG(0) key AS the child
// (SignerName = child zone — the parent trusts it via the KEY published at the
// child apex, §10.1). The form is REPLACE by default and DELTA if the operator
// sets `parent-update: delta` (proxyUpdateMode). Replace DELetes the child's
// delegation RRsets and ADDs the current authoritative members (NS + glue + DS).
//
// It is gated on the precondition state machine (§10.8): if the parent does not
// advertise UPDATE, or the agent's KEY is not published/ours, it does nothing
// and reports the state — it never sends an UPDATE the parent would REFUSE.
func (zd *ZoneData) ProxyUpdateParent(ctx context.Context, kdb *KeyDB, imr *Imr) (string, ProxyUpdateState, error) {
	state, err := zd.ProxyUpdatePreconditionCheck(ctx, kdb, imr)
	if err != nil {
		return "", state, err
	}
	if state != ProxyUpdateReady {
		return fmt.Sprintf("UPDATE proxy not ready (%s); nothing sent", state), state, nil
	}

	// Resolve the parent's UPDATE target.
	if zd.Parent == "" || zd.Parent == "." {
		p, perr := imr.ParentZone(zd.ZoneName)
		if perr != nil {
			return "", state, fmt.Errorf("ProxyUpdateParent: ParentZone(%s): %w", zd.ZoneName, perr)
		}
		zd.Parent = p
	}
	target, terr := imr.LookupDSYNCTarget(ctx, zd.ZoneName, dns.TypeANY, core.SchemeUpdate)
	if terr != nil || target == nil || len(target.Addresses) == 0 {
		return "", state, fmt.Errorf("ProxyUpdateParent: no UPDATE target for %s: %w", zd.ZoneName, terr)
	}

	// Build the UPDATE in the configured form (replace by default, delta if the
	// operator chose it). Replace reads the current authoritative records from
	// the served zone; delta needs the parent-vs-child diff (AnalyseZoneDelegation).
	var m *dns.Msg
	var berr error
	mode := proxyUpdateMode(kdb)
	if mode == UpdateModeDelta {
		dss, aerr := zd.AnalyseZoneDelegation(imr)
		if aerr != nil {
			return "", state, fmt.Errorf("ProxyUpdateParent: analyse delegation (delta): %w", aerr)
		}
		if dss.InSync {
			return "delta: parent already in sync; nothing sent", state, nil
		}
		var adds, removes []dns.RR
		adds = append(adds, dss.NsAdds...)
		adds = append(adds, dss.AAdds...)
		adds = append(adds, dss.AAAAAdds...)
		adds = append(adds, dss.DSAdds...)
		removes = append(removes, dss.NsRemoves...)
		removes = append(removes, dss.ARemoves...)
		removes = append(removes, dss.AAAARemoves...)
		removes = append(removes, dss.DSRemoves...)
		m, berr = CreateChildUpdate(zd.Parent, zd.ZoneName, adds, removes)
	} else {
		newNS, newA, newAAAA, newDS := zd.proxyCurrentDelegationRRs()
		m, berr = CreateChildReplaceUpdate(zd.Parent, zd.ZoneName, newNS, newA, newAAAA, newDS)
	}
	if berr != nil {
		return "", state, fmt.Errorf("ProxyUpdateParent: build %s UPDATE: %w", mode, berr)
	}

	// Sign as the child with the agent's SIG(0) key.
	sak, kerr := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if kerr != nil || sak == nil || len(sak.Keys) == 0 {
		return "", state, fmt.Errorf("ProxyUpdateParent: no active SIG(0) key for %s", zd.ZoneName)
	}
	smsg, serr := SignMsg(*m, zd.ZoneName, sak)
	if serr != nil || smsg == nil {
		return "", state, fmt.Errorf("ProxyUpdateParent: sign UPDATE: %w", serr)
	}

	rcode, _, uerr := SendUpdate(smsg, zd.Parent, target.Addresses)
	if uerr != nil {
		return "", state, fmt.Errorf("ProxyUpdateParent: send UPDATE to %s: %w", zd.Parent, uerr)
	}
	msg := fmt.Sprintf("proxied %s UPDATE to parent %s (rcode %s)", mode, zd.Parent, dns.RcodeToString[rcode])
	lgDns.Info("delegation-sync-proxy: "+msg, "zone", zd.ZoneName, "mode", mode)
	return msg, state, nil
}
