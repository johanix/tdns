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
	"strings"

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
	return zd.proxySig0PublicationState(kdb)
}

// proxySig0PublicationState is the §10.8 state machine from step 2 onwards: the
// caller has already established that the parent advertises a DSYNC UPDATE
// receiver, and this decides whether the agent can actually sign for the child.
//
// Split out so the sync plan (delsync_proxy_plan.go) can evaluate the UPDATE
// gate from a DSYNC RRset it already holds. Previously the only way to ask
// "can we UPDATE?" was ProxyUpdatePreconditionCheck, which began by discovering
// the DSYNC RRset again -- so every caller that had just discovered it paid for
// a second lookup, and the startup path paid for a third.
//
// Side-effecting in the WAITING state only: it generates a SIG(0) keypair if
// the keystore has none, so the operator instruction can be produced.
func (zd *ZoneData) proxySig0PublicationState(kdb *KeyDB) (ProxyUpdateState, error) {
	// Step 2: inspect the apex KEY RRset.
	apexKeys := zd.proxyApexKEYs()
	if len(apexKeys) > 0 {
		if zd.proxyHoldsPrivateKeyFor(kdb, apexKeys) {
			zd.clearProxyUpdateWarning()
			lgDns.Info("proxy update precondition: ready (KEY at apex, private key held)", "zone", zd.ZoneName)
			return ProxyUpdateReady, nil
		}
		zd.proxySig0ParentBootstrapped = false
		// Foreign KEY: do not mint a competing key; degrade, don't fail.
		msg := "DSYNC UPDATE proxy not operable: a foreign KEY occupies the apex (no matching private key); NOTIFY proxy may still apply"
		zd.SetError(DelegationSyncWarning, "%s", msg)
		lgDns.Warn("proxy update precondition: foreign KEY at apex", "zone", zd.ZoneName)
		return ProxyUpdateForeignKey, nil
	}

	zd.proxySig0ParentBootstrapped = false

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
	alg, err := parseKeygenAlgorithm(ParentSyncConfig().Update.Keygen.Algorithm, dns.ED25519)
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

// proxyAgentKeyRR returns the agent's active SIG(0) KEY for this zone, owned at
// the apex.
//
// (nil, nil) when the keystore holds none. That is a state to describe rather
// than an error: outside the bootstrap path -- where proxyEnsureSig0Key has
// just guaranteed one -- the report is asked for in states where no key has
// ever been generated, and a status command must not mint one as a side
// effect.
func (zd *ZoneData) proxyAgentKeyRR(kdb *KeyDB) (*dns.KEY, error) {
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return nil, fmt.Errorf("GetSig0Keys: %w", err)
	}
	if sak == nil || len(sak.Keys) == 0 {
		return nil, nil
	}
	keyRR := sak.Keys[0].KeyRR
	keyRR.Hdr.Name = zd.ZoneName
	return &keyRR, nil
}

// proxyBootstrapInstruction returns the two records the operator must add at the
// primary apex (§10.8 U10): the agent's KEY RR and an HSYNCPARAM with the pubkey
// flag (the signal to all providers to republish the apex KEY). Returns the
// records as zone-file text.
func (zd *ZoneData) proxyBootstrapInstruction(kdb *KeyDB) (string, error) {
	keyRR, err := zd.proxyAgentKeyRR(kdb)
	if err != nil {
		return "", err
	}
	if keyRR == nil {
		return "", fmt.Errorf("no active SIG(0) key for zone %s", zd.ZoneName)
	}
	return keyRR.String() + "\n" + zd.proxyHsyncparamPubkeyRR(), nil
}

// proxyHsyncparamPubkeyRR returns the zone-file text for an HSYNCPARAM record
// carrying the pubkey flag at the zone apex.
func (zd *ZoneData) proxyHsyncparamPubkeyRR() string {
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{core.NewHsyncparamPubkeyFlag()}}
	return fmt.Sprintf("%s\t3600\tIN\tHSYNCPARAM\t%s", zd.ZoneName, hp.String())
}

// proxyHsyncparamPubkeyRFC3597 renders the same HSYNCPARAM in RFC 3597
// unknown-record syntax.
//
// HSYNCPARAM is a private type (65286): a nameserver that does not know it
// cannot parse the presentation form above, so the record the report suggests
// could not simply be pasted into a zone served by anything but tdns. Every
// current nameserver does parse RFC 3597, so the report offers both.
func (zd *ZoneData) proxyHsyncparamPubkeyRFC3597() (string, error) {
	rr, err := dns.NewRR(zd.proxyHsyncparamPubkeyRR())
	if err != nil {
		return "", fmt.Errorf("parsing the generated HSYNCPARAM: %w", err)
	}
	return rrToRFC3597(rr)
}

// rrToRFC3597 renders an RR in RFC 3597 unknown-record syntax.
//
// Not dns.RFC3597.String(), which hardcodes the class as "CLASS1". That is the
// same class as IN and parses everywhere, but this output exists to be pasted
// into a zone file, and IN is what an operator expects to read there.
func rrToRFC3597(rr dns.RR) (string, error) {
	u := new(dns.RFC3597)
	if err := u.ToRFC3597(rr); err != nil {
		return "", fmt.Errorf("rendering %s in RFC 3597 form: %w",
			dns.TypeToString[rr.Header().Rrtype], err)
	}
	// Rdata is hex, so its byte count is half its length -- the length field
	// RFC 3597 puts before the data.
	return fmt.Sprintf("%s\t%d\tIN\tTYPE%d\t\\# %d %s",
		u.Hdr.Name, u.Hdr.Ttl, u.Hdr.Rrtype, len(u.Rdata)/2, u.Rdata), nil
}

// proxyKeyPublishBlock renders what the primary should serve at its apex: the
// agent's SIG(0) KEY, the HSYNCPARAM pubkey flag that tells the other providers
// to republish that key (RFC 9615), and the HSYNCPARAM once more in RFC 3597
// form for a nameserver that does not know the type.
//
// Shown in every state, not only while waiting for the key (#541). READY is the
// state an operator looks at when something is not working, and it used to
// assert that the published key and the held key agree without showing either,
// so there was nothing to compare against what the primary actually serves.
//
// Returns ("", nil) when no key has been generated -- the caller says so in
// its own words, since what that means depends on the state.
func (zd *ZoneData) proxyKeyPublishBlock(kdb *KeyDB) (string, error) {
	keyRR, err := zd.proxyAgentKeyRR(kdb)
	if err != nil {
		return "", err
	}
	if keyRR == nil {
		return "", nil
	}
	unknown, err := zd.proxyHsyncparamPubkeyRFC3597()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`Records for the primary to serve at the apex:

%s
%s

HSYNCPARAM is a private type (%d). For a primary that cannot parse it, the same
record in RFC 3597 form:

%s
`, keyRR.String(), zd.proxyHsyncparamPubkeyRR(), core.TypeHSYNCPARAM, unknown), nil
}

// clearProxyUpdateWarning removes any delegation-sync-proxy UPDATE warning set
// on the zone (when the state becomes ready or update-unsupported).
func (zd *ZoneData) clearProxyUpdateWarning() {
	zd.ClearError(DelegationSyncWarning)
}

// ProxyKeyStatus is the operator-facing report for the `proxy-key` command: the
// current UPDATE-proxy state, and the records the operator must serve at the
// primary apex -- the agent's KEY RR, the HSYNCPARAM pubkey flag, and the
// HSYNCPARAM in RFC 3597 form.
//
// The records are reported in every state, not only while waiting. READY is
// the state an operator reads when the primary looks fine and the agent still
// cannot proxy, and a verdict with no record leaves nothing to compare against
// what the primary serves.
//
// It runs the §10.8 precondition check, which is the only thing here that
// generates a keypair, and only in the waiting state. Every other state
// reports the absence of a key rather than filling it.
func (zd *ZoneData) ProxyKeyStatus(ctx context.Context, kdb *KeyDB, imr *Imr) (string, error) {
	if !zd.Options[OptParentSyncProxy] {
		return "", fmt.Errorf("zone %s does not have the delegation-sync-proxy option", zd.ZoneName)
	}
	state, err := zd.ProxyUpdatePreconditionCheck(ctx, kdb, imr)
	if err != nil {
		return "", err
	}
	return zd.proxyKeyStatusMessage(state, kdb)
}

// proxyKeyStatusMessage renders the report for a state the caller has already
// determined.
//
// Split out of ProxyKeyStatus so each arm can be exercised on its own. The
// precondition check begins with a DSYNC lookup at the parent, so anything
// going through ProxyKeyStatus without a network reaches update-unsupported
// and no other arm -- which left the assembled text for the three states this
// change is about untested.
func (zd *ZoneData) proxyKeyStatusMessage(state ProxyUpdateState, kdb *KeyDB) (string, error) {
	block, berr := zd.proxyKeyPublishBlock(kdb)
	if berr != nil {
		return "", berr
	}
	// No key at all. Only reachable outside WAITING, which generates one.
	if block == "" {
		block = "No SIG(0) key has been generated for this zone yet, so there is nothing to publish.\n"
	}

	switch state {
	case ProxyUpdateUnsupported:
		return fmt.Sprintf(
			"zone %s: UPDATE proxy not applicable — the parent advertises no DSYNC UPDATE receiver"+
				" (NOTIFY proxy may still apply).\n\n%s", zd.ZoneName, block), nil

	case ProxyUpdateReady:
		return fmt.Sprintf(
			"zone %s: UPDATE proxy READY — the agent's KEY is published at the apex and the agent"+
				" holds its private key.\n\n%s", zd.ZoneName, block), nil

	case ProxyUpdateForeignKey:
		// Both sides of the mismatch. "Remove it" that does not say which
		// record it means leaves the operator comparing key material by hand,
		// with nothing to say the key they are looking at is the one the agent
		// actually saw.
		var found strings.Builder
		for _, rr := range zd.proxyApexKEYs() {
			found.WriteString(rr.String() + "\n")
		}
		return fmt.Sprintf(
			"zone %s: UPDATE proxy NOT operable — a foreign KEY occupies the apex (the agent does not"+
				" hold its private key). Remove it, or the agent cannot proxy via UPDATE (NOTIFY may"+
				" still apply).\n\nPublished at the apex now:\n\n%s\n%s",
			zd.ZoneName, found.String(), block), nil

	case ProxyUpdateWaiting:
		return fmt.Sprintf(
			"zone %s: UPDATE proxy WAITING — publish the following at the primary apex, then the agent"+
				" will proxy UPDATEs once it sees the KEY.\n\n%s", zd.ZoneName, block), nil

	default:
		return fmt.Sprintf("zone %s: UPDATE proxy state %q\n\n%s", zd.ZoneName, state, block), nil
	}
}

// currentDelegationRRs reads the current authoritative delegation RRsets
// from the SERVED zone.
//
// Shared by the proxy path and by AnalyseZoneDelegation's declarative fields,
// deliberately: the same defect was found twice. The proxy case hit it first --
// feeding DsyncApiRRsetsFromSyncStatus an analysis produced an empty request,
// because the analysis fills deltas and not the New* fields -- and was fixed by
// reading the served zone instead. The explicit-analysis path had the same hole
// and kept it, which is #507. One implementation now, so a third path cannot
// rediscover it.
//
// Reads the apex NS, the in-bailiwick glue (A/AAAA) for those nameservers, and
// the DS derived from the apex DNSKEY SEP keys. These are the replace-form UPDATE's "new members" — the
// payload never depends on the parent's state (that is the point of replace).
// For an unsigned zone newDS is empty (no DNSKEYs), which is correct.
func (zd *ZoneData) currentDelegationRRs() (newNS, newA, newAAAA, newDS []dns.RR) {
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

// proxyReplaceSyncState is the replace-mode payload from the served zone.
//
// NewDSKnown follows hasDnskeyRRset, the same predicate the API path uses:
// no DNSKEY RRset at all is an empty-DS delete (#468); a flags-256 CSK
// (DNSKEYs present, none SEP) leaves the parent DS alone; SEP keys are
// restated and ZSKs are not hashed.
func (zd *ZoneData) proxyReplaceSyncState() DelegationSyncStatus {
	newNS, newA, newAAAA, newDS := zd.currentDelegationRRs()
	return DelegationSyncStatus{
		ZoneName:   zd.ZoneName,
		Parent:     zd.GetParent(),
		NewNS:      newNS,
		NewA:       newA,
		NewAAAA:    newAAAA,
		NewDS:      newDS,
		NewDSKnown: !zd.hasDnskeyRRset() || len(newDS) > 0,
	}
}

// ProxyStartupReconcile runs once when a delegation-sync-proxy zone first
// loads: a one-time parent-vs-child reconcile that catches delegation drift
// accumulated while the agent was down, WITHOUT re-sending on every restart
// (the InSync check gates the send even though replace-form would otherwise be
// harmless to re-send). Steady-state changes after this are handled by the
// PreRefresh diff + PROXY-SYNC dispatch (U-e), which need no parent round-trip.
//
// It used to be UPDATE-only: it ran the §10.8 precondition and gave up unless
// the state was READY, so a parent offering only API or only NOTIFY got no
// startup reconcile at all and its drift went uncorrected until the next
// transfer happened to change something. It now uses whatever transport is
// available, via the same plan the steady-state path uses.
func (zd *ZoneData) ProxyStartupReconcile(ctx context.Context, kdb *KeyDB,
	notifyq chan NotifyRequest, imr *Imr) (string, error) {
	plan, err := zd.BuildParentSyncPlan(ctx, kdb, imr, SyncRoleProxy)
	if err != nil {
		return "", fmt.Errorf("ProxyStartupReconcile: %w", err)
	}
	if !plan.Usable() {
		// Degraded, not broken: the zone is served either way, and the reasons
		// are in the summary rather than in a shrug.
		return "startup reconcile: " + plan.Summary(), nil
	}

	dss, aerr := zd.AnalyseZoneDelegation(imr)
	if aerr != nil {
		return "", fmt.Errorf("ProxyStartupReconcile: AnalyseZoneDelegation(%s): %w", zd.ZoneName, aerr)
	}
	if dss.InSync {
		lgDns.Info("delegation-sync-proxy: startup reconcile — parent already in sync", "zone", zd.ZoneName)
		return "startup reconcile: parent already in sync; nothing sent", nil
	}

	// NOTIFY needs to know WHICH signal to send, which the steady-state path
	// gets from the transfer diff. There is no transfer here, so it comes from
	// the parent-vs-child comparison just made.
	analysis := proxyAnalysisFromSyncStatus(dss)

	lgDns.Info("delegation-sync-proxy: startup reconcile — parent out of sync",
		"zone", zd.ZoneName, "plan", plan.Summary())
	msg, serr := zd.SyncWithParent(ctx, kdb, notifyq, imr, plan, analysis, &dss)
	if serr != nil {
		return "", fmt.Errorf("ProxyStartupReconcile: %w", serr)
	}
	return "startup reconcile: " + msg, nil
}

// ProxyDelegationSync is the steady-state dispatcher: on a detected change it
// forwards to the parent over whichever transport is actually usable.
//
// It no longer picks one scheme and lives with it. Synchronising a delegation
// is one task; NOTIFY, UPDATE and API are three transports for it, each with a
// gate. BuildParentSyncPlan discovers the parent's DSYNC RRset ONCE and works
// out which transports pass their gate; SyncWithParent walks them. That is what
// removed the repeated discovery (three to four per sync, all returning the
// same RRset) and the fallback that never fired.
func (zd *ZoneData) ProxyDelegationSync(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest, imr *Imr, analysis *ProxyDelegationAnalysis) (string, error) {
	plan, err := zd.BuildParentSyncPlan(ctx, kdb, imr, SyncRoleProxy)
	if err != nil {
		return "", fmt.Errorf("ProxyDelegationSync: %w", err)
	}
	return zd.SyncWithParent(ctx, kdb, notifyq, imr, plan, analysis, nil)
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
// The §10.8 precondition and the parent's UPDATE target are the CALLER's
// responsibility: both are settled while the sync plan is built, from one
// discovery. This function is only reached for a candidate that already passed
// its gate, so it never sends an UPDATE the parent would REFUSE — the check
// simply happens earlier, and once.
func (zd *ZoneData) ProxyUpdateParent(ctx context.Context, kdb *KeyDB, imr *Imr,
	target *DsyncTarget, precomputed *DelegationSyncStatus) (string, error) {

	mode := proxyUpdateMode(kdb)
	var dss DelegationSyncStatus
	if mode == UpdateModeDelta {
		if precomputed != nil {
			dss = *precomputed
		} else {
			var aerr error
			dss, aerr = zd.AnalyseZoneDelegation(imr)
			if aerr != nil {
				return "", fmt.Errorf("ProxyUpdateParent: analyse delegation (delta): %w", aerr)
			}
		}
		if dss.InSync {
			return "delta: parent already in sync; nothing sent", nil
		}
	} else {
		dss = zd.proxyReplaceSyncState()
	}

	if err := zd.proxyEnsureParentBootstrap(ctx); err != nil {
		return "", fmt.Errorf("ProxyUpdateParent: bootstrap SIG(0) key with parent: %w", err)
	}

	_, rcode, _, uerr := zd.SendDelegationUpdate(ctx, kdb, dss, target, mode)
	if uerr != nil {
		return "", fmt.Errorf("ProxyUpdateParent: send UPDATE to %s: %w", zd.GetParent(), uerr)
	}
	msg := fmt.Sprintf("proxied %s UPDATE to parent %s (rcode %s)", mode, zd.GetParent(), dns.RcodeToString[int(rcode)])
	lgDns.Info("delegation-sync-proxy: "+msg, "zone", zd.ZoneName, "mode", mode)
	return msg, nil
}

// proxyEnsureParentBootstrap runs the self-signed SIG(0) ceremony once the
// KEY is at the apex (WAITING → READY), before the first proxied UPDATE.
// BADKEY recovery stays in SendUpdateWithRetry; this is the first-time path
// so the first UPDATE is not a guaranteed failure.
func (zd *ZoneData) proxyEnsureParentBootstrap(ctx context.Context) error {
	if zd.proxySig0ParentBootstrapped {
		return nil
	}
	alg, err := parseKeygenAlgorithm(ParentSyncConfig().Update.Keygen.Algorithm, dns.ED25519)
	if err != nil {
		return fmt.Errorf("keygen algorithm: %w", err)
	}
	_, ur, err := zd.bootstrapSig0Key(ctx, alg, proxyApexKEY{})
	if err := parentBootstrapResult(ur, err); err != nil {
		return err
	}
	zd.proxySig0ParentBootstrapped = true
	return nil
}

func parentBootstrapResult(ur UpdateResult, err error) error {
	if err != nil {
		return err
	}
	if ur.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("bootstrap SIG(0) key with parent: rcode %s", dns.RcodeToString[ur.Rcode])
	}
	return nil
}
