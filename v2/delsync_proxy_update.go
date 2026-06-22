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
