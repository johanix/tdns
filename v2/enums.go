/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "fmt"

type ZoneOption uint8

// Range allocation for ZoneOption across the tdns ecosystem.
// Each downstream repo gets a numeric range starting one past the
// previous max. Downstream packages assign their values via:
//
//	const X tdns.ZoneOption = tdns.TdnsZoneOptionMax + 1 + iota
//
// and use a compile-time gate to ensure they stay in their range
// (see enums.go in each downstream package). Resizing a range:
// change the value here and recompile.
const (
	TdnsZoneOptionMax   ZoneOption = 32
	TdnsMpZoneOptionMax ZoneOption = 64
	TdnsNmZoneOptionMax ZoneOption = 96
	TdnsEsZoneOptionMax ZoneOption = 128
)

const (
	OptDelSyncParent ZoneOption = iota + 1
	OptDelSyncChild
	OptAllowUpdates
	OptAllowChildUpdates
	OptAllowEdits // Dynamically et if app=combiner and zone contains a HSYNC RRset
	OptFoldCase
	OptBlackLies
	OptDontPublishKey
	OptDontPublishJWK
	OptOnlineSigning
	OptInlineSigning
	OptMultiProvider
	OptDirty
	OptFrozen
	OptAutomaticZone
	// OptServerSvcb
	OptAddTransportSignal
	OptCatalogZone
	OptCatalogMemberAutoCreate
	OptCatalogMemberAutoDelete
	OptMPManualApproval
	OptMultiSigner     // Dynamically set by signer when HSYNC shows multiple signers
	OptMPNotListedErr  // Warning: zone has HSYNC3 but we are not listed as a provider
	OptMPDisallowEdits // Zone is signed but we are not a signer: no edits allowed
)

var ZoneOptionToString = map[ZoneOption]string{
	OptDelSyncParent:     "delegation-sync-parent",
	OptDelSyncChild:      "delegation-sync-child",
	OptAllowUpdates:      "allow-updates",
	OptAllowChildUpdates: "allow-child-updates",
	OptAllowEdits:        "allow-edits", // Dynamically et if app=combiner and zone contains a HSYNC RRset
	OptFoldCase:          "fold-case",
	OptBlackLies:         "black-lies",
	OptDontPublishKey:    "dont-publish-key",
	OptDontPublishJWK:    "dont-publish-jwk",
	OptOnlineSigning:     "online-signing",
	OptInlineSigning:     "inline-signing",
	OptMultiProvider:     "multi-provider",
	OptDirty:             "dirty",
	OptFrozen:            "frozen",
	OptAutomaticZone:     "automatic-zone",
	// OptServerSvcb:        "create-server-svcb",
	OptAddTransportSignal:      "add-transport-signal",
	OptCatalogZone:             "catalog-zone",
	OptCatalogMemberAutoCreate: "catalog-member-auto-create",
	OptCatalogMemberAutoDelete: "catalog-member-auto-delete",
	OptMPManualApproval:        "mp-manual-approval",
	OptMultiSigner:             "multi-signer",
	OptMPNotListedErr:          "mp-not-listed-error",
	OptMPDisallowEdits:         "mp-disallow-edits",
}

var StringToZoneOption = map[string]ZoneOption{
	"delegation-sync-parent":     OptDelSyncParent,
	"delegation-sync-child":      OptDelSyncChild,
	"allow-updates":              OptAllowUpdates,
	"allow-child-updates":        OptAllowChildUpdates,
	"allow-edits":                OptAllowEdits,
	"fold-case":                  OptFoldCase,
	"black-lies":                 OptBlackLies,
	"dont-publish-key":           OptDontPublishKey,
	"dont-publish-jwk":           OptDontPublishJWK,
	"online-signing":             OptOnlineSigning,
	"inline-signing":             OptInlineSigning,
	"multi-provider":             OptMultiProvider,
	"dirty":                      OptDirty,
	"frozen":                     OptFrozen,
	"automatic-zone":             OptAutomaticZone,
	"add-transport-signal":       OptAddTransportSignal,
	"catalog-zone":               OptCatalogZone,
	"catalog-member-auto-create": OptCatalogMemberAutoCreate,
	"catalog-member-auto-delete": OptCatalogMemberAutoDelete,
	"mp-manual-approval":         OptMPManualApproval,
	"multi-signer":               OptMultiSigner,
	"mp-not-listed-error":        OptMPNotListedErr,
	"mp-disallow-edits":          OptMPDisallowEdits,
}

type ImrOption uint8

const (
	ImrOptRevalidateNS ImrOption = iota + 1
	ImrOptQueryForTransport
	ImrOptAlwaysQueryForTransport
	ImrOptTransportSignalType
	ImrOptQueryForTransportTLSA
	ImrOptUseTransportSignals
)

var ImrOptionToString = map[ImrOption]string{
	ImrOptRevalidateNS:            "revalidate-ns",
	ImrOptQueryForTransport:       "query-for-transport",
	ImrOptAlwaysQueryForTransport: "always-query-for-transport",
	ImrOptTransportSignalType:     "transport-signal-type",
	ImrOptQueryForTransportTLSA:   "query-for-transport-tlsa",
	ImrOptUseTransportSignals:     "use-transport-signals",
}

var StringToImrOption = map[string]ImrOption{
	"revalidate-ns":              ImrOptRevalidateNS,
	"query-for-transport":        ImrOptQueryForTransport,
	"always-query-for-transport": ImrOptAlwaysQueryForTransport,
	"transport-signal-type":      ImrOptTransportSignalType,
	"query-for-transport-tlsa":   ImrOptQueryForTransportTLSA,
	"use-transport-signals":      ImrOptUseTransportSignals,
}

type AuthOption uint8

const (
	AuthOptParentUpdate AuthOption = iota + 1
)

var AuthOptionToString = map[AuthOption]string{
	AuthOptParentUpdate: "parent-update",
}

var StringToAuthOption = map[string]AuthOption{
	"parent-update": AuthOptParentUpdate,
}

// outbound_soa_serial mode values for DnsEngine.OutboundSoaSerial.
const (
	OutboundSoaSerialKeep     = "keep"     // outbound = inbound serial (default)
	OutboundSoaSerialUnixtime = "unixtime" // outbound = time.Now().Unix()
	OutboundSoaSerialPersist  = "persist"  // outbound = previous outbound serial; bumps written to OutgoingSerials
)

type CombinerOption uint8

const (
	CombinerOptAddSignature CombinerOption = iota + 1
)

var CombinerOptionToString = map[CombinerOption]string{
	CombinerOptAddSignature: "add-signature",
}

var StringToCombinerOption = map[string]CombinerOption{
	"add-signature": CombinerOptAddSignature,
}

type SignerOption uint8

var SignerOptionToString = map[SignerOption]string{}
var StringToSignerOption = map[string]SignerOption{}

type AgentOption uint8

var AgentOptionToString = map[AgentOption]string{}
var StringToAgentOption = map[string]AgentOption{}

type AppType uint8

// Range allocation for AppType across the tdns ecosystem.
// Each downstream repo gets a numeric range starting one past the
// previous max. Downstream packages assign their values via:
//
//	const X tdns.AppType = tdns.TdnsAppTypeMax + 1 + iota
//
// and use a compile-time gate to ensure they stay in their range
// (see enums.go in each downstream package). Resizing a range:
// change the value here and recompile.
const (
	TdnsAppTypeMax   AppType = 16
	TdnsMpAppTypeMax AppType = 32
	TdnsNmAppTypeMax AppType = 48
	TdnsEsAppTypeMax AppType = 64
)

const (
	AppTypeAuth AppType = iota + 1
	AppTypeAgent
	// AppTypeCombiner
	AppTypeImr // simplified recursor
	AppTypeCli
	AppTypeReporter
	AppTypeScanner
	AppTypeKdc        // Key Distribution Center
	AppTypeKrs        // Key Receiving Service (edge receiver)
	AppTypeEdgeSigner // NYI
	AppTypeMPSigner   // MP signer (tdns-mp): DNS infra from tdns, MP wiring from tdns-mp
	AppTypeMPAgent    // MP agent (tdns-mp): DNS infra from tdns, MP wiring from tdns-mp
	AppTypeMPCombiner // MP combiner (tdns-mp): DNS infra from tdns, MP wiring from tdns-mp
	AppTypeMPAuditor  // MP auditor (tdns-mp): read-only observer, no zone contributions
)

var AppTypeToString = map[AppType]string{
	AppTypeAuth:  "auth",
	AppTypeAgent: "agent",
	//AppTypeCombiner:   "combiner",
	AppTypeImr:        "imr",
	AppTypeCli:        "cli",
	AppTypeReporter:   "reporter",
	AppTypeScanner:    "scanner",
	AppTypeKdc:        "kdc",
	AppTypeKrs:        "krs",
	AppTypeEdgeSigner: "edgeSigner", // NYI
	AppTypeMPSigner:   "mpsigner",
	AppTypeMPAgent:    "mpagent",
	AppTypeMPCombiner: "mpcombiner",
	AppTypeMPAuditor:  "mpauditor",
}

var StringToAppType = map[string]AppType{
	"auth":  AppTypeAuth,
	"agent": AppTypeAgent,
	//"combiner":   AppTypeCombiner,
	"imr":        AppTypeImr,
	"cli":        AppTypeCli,
	"reporter":   AppTypeReporter,
	"scanner":    AppTypeScanner,
	"kdc":        AppTypeKdc,
	"krs":        AppTypeKrs,
	"edgeSigner": AppTypeEdgeSigner, // NYI
	"mpsigner":   AppTypeMPSigner,
	"mpagent":    AppTypeMPAgent,
	"mpcombiner": AppTypeMPCombiner,
	"mpauditor":  AppTypeMPAuditor,
}

type ErrorType uint8

const (
	NoError ErrorType = iota
	ConfigError
	RefreshError
	AgentError
	DnssecError
	// RolloverPolicyViolation: hard cache-flush invariant violation
	// (E5/E10) detected from policy + observed parent state. The
	// rollover engine refuses to advance keys for the affected zone:
	// continuing would demonstrably violate cache-flush invariants
	// and could break validation for fractions of users during the
	// rollover window. Operator must fix the policy. Manual override
	// via auto-rollover asap is also blocked for Case 1 (DS not at
	// parent) but allowed for Case 2 (operator-acknowledged
	// cache-flush bypass).
	RolloverPolicyViolation
	// RolloverPolicyWarning: rule-of-thumb violation (E11) — the
	// policy passes the hard invariants but has minimal headroom.
	// Engine keeps rolling; this is visibility-only.
	RolloverPolicyWarning
	// RolloverParentBlocker: parent's published DSYNC RRset does not
	// advertise a scheme matching the zone's
	// rollover.dsync-scheme-preference. Set immediately on
	// errNoUsableScheme; cleared on the next successful
	// pickRolloverSchemes. The engine keeps retrying — this is a
	// visibility signal, not a hardfail. Auto-rollover progression
	// gates here because no scheme means no DS push is possible.
	RolloverParentBlocker
)

var ErrorTypeToString = map[ErrorType]string{
	ConfigError:             "config",
	RefreshError:            "refresh",
	AgentError:              "agent",
	DnssecError:             "DNSSEC",
	RolloverPolicyViolation: "rollover-policy",
	RolloverPolicyWarning:   "rollover-policy-warning",
	RolloverParentBlocker:   "rollover-parent-blocker",
}

// errorTypeReportOrder defines the deterministic order in which the
// derived single-error fields (zd.ErrorType, zd.ErrorMsg) report a
// category when multiple errors coexist. Earlier in this list wins.
// The order reflects severity: ConfigError (zone unusable) before
// RefreshError (data may be stale) before per-feature blockers.
var errorTypeReportOrder = []ErrorType{
	ConfigError,
	RefreshError,
	AgentError,
	DnssecError,
	RolloverPolicyViolation,
	RolloverParentBlocker,
	RolloverPolicyWarning,
}

// rolloverGatingErrors are categories that the auto-rollover CLI
// surfaces in its status header. RolloverPolicyWarning is included so
// operators see headroom warnings, but the engine keeps rolling for
// warnings (see autoRolloverImpactingErrors).
var rolloverGatingErrors = []ErrorType{
	RolloverPolicyViolation,
	RolloverParentBlocker,
	RolloverPolicyWarning,
}

// autoRolloverImpactingErrors are categories that gate the automated
// rollover engine itself: when present, RolloverAutomatedTick and
// related per-zone state-machine entry points refuse to advance.
// Excludes RolloverPolicyWarning — that's visibility-only and the
// engine keeps rolling.
var autoRolloverImpactingErrors = []ErrorType{
	RolloverPolicyViolation,
	RolloverParentBlocker,
}

// serviceImpactingErrors are categories that make the zone unable to
// serve correctly: a NOTIFY/UPDATE/query handler should refuse with
// SERVFAIL. RefreshError and the rollover-* categories never block
// serving — a zone with stale data or an unsafe upcoming rollover is
// still authoritative for its current contents.
var serviceImpactingErrors = []ErrorType{
	ConfigError,
	AgentError,
	DnssecError,
}

// ZoneError is one entry in the per-zone error registry. Use SetError
// to upsert and ClearError to remove.
type ZoneError struct {
	Type ErrorType
	Msg  string
}

// SetError upserts an error of the given type. Calling SetError(NoError, "")
// clears every error currently set on the zone (back-compat with the prior
// single-error API). Other errors of different types are not affected when
// upserting a specific category.
//
// Derived fields (zd.Error, zd.ErrorType, zd.ErrorMsg) are recomputed
// after every change. zd.ErrorType reports the highest-priority active
// category per errorTypeReportOrder.
//
// Holds zd.mu for the duration so the registry mutation, derived-field
// recomputation, and Zones.Set are atomic against any concurrent
// HasError/ErrorList reader.
func (zd *ZoneData) SetError(errtype ErrorType, errmsg string, args ...interface{}) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if errtype == NoError {
		zd.Errors = nil
	} else {
		if zd.Errors == nil {
			zd.Errors = map[ErrorType]ZoneError{}
		}
		zd.Errors[errtype] = ZoneError{Type: errtype, Msg: fmt.Sprintf(errmsg, args...)}
	}
	zd.recomputeDerivedErrorFieldsLocked()
	Zones.Set(zd.ZoneName, zd)
}

// ClearError removes one error category. ClearError(NoError) clears
// every error.
func (zd *ZoneData) ClearError(errtype ErrorType) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if errtype == NoError {
		zd.Errors = nil
	} else if zd.Errors != nil {
		delete(zd.Errors, errtype)
		if len(zd.Errors) == 0 {
			zd.Errors = nil
		}
	}
	zd.recomputeDerivedErrorFieldsLocked()
	Zones.Set(zd.ZoneName, zd)
}

// HasError returns true if the zone has an active error of the given type.
func (zd *ZoneData) HasError(errtype ErrorType) bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.Errors == nil {
		return false
	}
	_, ok := zd.Errors[errtype]
	return ok
}

// HasErrorOtherThan returns true if the zone has any active error not
// in the allow list. Used by NOTIFY/query handlers that want "the zone
// is broken in some way that matters here" — they tolerate
// RefreshError (data may be stale but is still served) but reject
// every other category.
//
// With the multi-error registry, checking only the derived
// zd.ErrorType is wrong: the dominant category by errorTypeReportOrder
// can be RefreshError while a RolloverPolicyViolation also exists, and
// the handler would then accept a request on a rollover-blocked zone.
func (zd *ZoneData) HasErrorOtherThan(allowed ...ErrorType) bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if len(zd.Errors) == 0 {
		return false
	}
outer:
	for t := range zd.Errors {
		for _, a := range allowed {
			if t == a {
				continue outer
			}
		}
		return true
	}
	return false
}

// HasServiceImpactingError reports whether the zone is in a state that
// makes it incapable of serving correctly. Today: ConfigError,
// AgentError, DnssecError. RefreshError and the rollover-* categories
// never block serving — a zone with stale data or an unsafe upcoming
// rollover is still authoritative for its current contents.
//
// NOTIFY/UPDATE/query handlers use this to decide whether to refuse
// with SERVFAIL.
func (zd *ZoneData) HasServiceImpactingError() bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	for _, t := range serviceImpactingErrors {
		if _, ok := zd.Errors[t]; ok {
			return true
		}
	}
	return false
}

// HasAutoRolloverImpactingError reports whether the automated rollover
// engine should refuse to advance keys for this zone. Today:
// RolloverPolicyViolation (hard E5/E10 violations) and
// RolloverParentBlocker. RolloverPolicyWarning does NOT trigger this —
// warnings let the engine keep rolling.
//
// Per-zone rollover-engine entry points (RolloverAutomatedTick,
// transitionDsPublishedToStandbyForZone) call this and return early
// when true.
func (zd *ZoneData) HasAutoRolloverImpactingError() bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	for _, t := range autoRolloverImpactingErrors {
		if _, ok := zd.Errors[t]; ok {
			return true
		}
	}
	return false
}

// ErrorList returns a snapshot of every active error on the zone, in
// errorTypeReportOrder. Returns nil if no errors are set. The returned
// slice is a fresh copy — safe to retain after the call returns.
func (zd *ZoneData) ErrorList() []ZoneError {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if len(zd.Errors) == 0 {
		return nil
	}
	out := make([]ZoneError, 0, len(zd.Errors))
	for _, t := range errorTypeReportOrder {
		if e, ok := zd.Errors[t]; ok {
			out = append(out, e)
		}
	}
	return out
}

// recomputeDerivedErrorFieldsLocked refreshes zd.Error / zd.ErrorType /
// zd.ErrorMsg from zd.Errors. Caller must hold zd.mu.
func (zd *ZoneData) recomputeDerivedErrorFieldsLocked() {
	if len(zd.Errors) == 0 {
		zd.Error = false
		zd.ErrorType = NoError
		zd.ErrorMsg = ""
		return
	}
	zd.Error = true
	for _, t := range errorTypeReportOrder {
		if e, ok := zd.Errors[t]; ok {
			zd.ErrorType = t
			zd.ErrorMsg = e.Msg
			return
		}
	}
}
