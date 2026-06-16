package tdns

// JSON wire types for the /api/v1/rollover/* endpoints. Single
// definition imported by both the server (which populates) and the
// CLI (which renders). Field names lock the API contract — the
// rollover-overhaul design doc commits to these names; do not rename
// post-ship without a coordinated CLI bump.
//
// Phase 8 (this file) just defines the types and the
// ComputeRolloverStatus / ComputeRolloverWhen functions in
// rollover_api_funcs.go. Phase 9 wires the GET endpoints. Phase 10
// wires the POST endpoints. Until then these types are unused by any
// caller — present for build only.

// RolloverStatus is the full per-zone report returned by
// GET /api/v1/rollover/status.
type RolloverStatus struct {
	Zone        string `json:"zone"`
	CurrentTime string `json:"currentTime"` // RFC3339 UTC, server's wallclock at response time
	Phase       string `json:"phase"`
	PhaseAt     string `json:"phaseAt,omitempty"`
	InProgress  bool   `json:"inProgress"`

	// Headline is the operator-facing one-word state. Always populated.
	// Values: "OK" | "ACTIVE" | "SOFTFAIL".
	Headline string `json:"headline"`

	// Hint is a plain-English diagnosis line for the current state.
	// Empty for steady states; populated mid-attempt and during
	// softfail to guide the operator's reading of the timing fields.
	Hint string `json:"hint,omitempty"`

	// Submitted/confirmed hold inclusive [low, high] rollover_index
	// spans persisted from the last parent DS push / observation
	// (SQL BETWEEN semantics — every integer in the interval).
	Submitted *DSRange `json:"submitted,omitempty"`
	Confirmed *DSRange `json:"confirmed,omitempty"`
	// SubmittedKeyIDs / ConfirmedKeyIDs list SEP keyids whose
	// rollover_index lies in Submitted / Confirmed (same reconciliation
	// as the per-key table; verifiable at the parent).
	SubmittedKeyIDs []uint16 `json:"submittedKeyids,omitempty"`
	ConfirmedKeyIDs []uint16 `json:"confirmedKeyids,omitempty"`

	// CdsPublishedKeyIDs is the SEP keyids of the CDS RRset that the
	// engine published at the child apex via NOTIFY(CDS) in its most
	// recent successful publish-and-NOTIFY. Sourced from the sparse
	// RolloverCdsPublication table — the row persists across
	// Trigger-1 cleanup so the operator can still see "CDS was
	// published [keyids] sent <CdsPublishedAt>" after the rollover
	// has completed and the engine no longer owns the apex CDS.
	// Empty/nil for zones that never ran a NOTIFY publish.
	CdsPublishedKeyIDs []uint16 `json:"cdsPublishedKeyids,omitempty"`
	CdsPublishedAt     string   `json:"cdsPublishedAt,omitempty"` // RFC3339

	// ObservedKeyIDs is the SEP keyids returned by the most recent
	// QueryParentAgentDS poll, regardless of whether the polled set
	// matched the engine's expected DS set. Refreshed on every
	// successful poll; used by the operator's "DS observed" line to
	// show the latest poll rather than the latest confirmed match.
	// ObservedAt is the wallclock timestamp of that poll.
	ObservedKeyIDs []uint16 `json:"observedKeyids,omitempty"`
	ObservedAt     string   `json:"observedAt,omitempty"` // RFC3339

	// Manual-rollover schedule (asap/cancel CLI flow).
	ManualRequestedAt string `json:"manualRequestedAt,omitempty"`
	ManualEarliest    string `json:"manualEarliest,omitempty"`

	// LastAttemptScheme records which scheme(s) the most recent push
	// attempt used at the wire level. Diagnostic only — the engine
	// never decides anything from it. Values: "UPDATE", "NOTIFY", or
	// "UPDATE,NOTIFY" when a parallel send had at least one path
	// return NOERROR. Empty when no push attempt has succeeded yet.
	LastAttemptScheme string `json:"lastAttemptScheme,omitempty"`

	// ParentAdvertisesUpdate / ParentAdvertisesNotify reflect the
	// most recent observation of the parent's DSYNC RRset, captured
	// by pickRolloverSchemes on every push attempt. Tri-state via
	// the *Known fields: when *Known is false, the engine has not
	// yet observed the parent's DSYNC RRset (zone never had a push
	// attempt); when true, the bool reflects whether that scheme is
	// advertised. Status renderer uses these to distinguish "parent
	// doesn't advertise this scheme" from "engine hasn't pushed via
	// this scheme yet".
	ParentAdvertisesUpdate      bool `json:"parentAdvertisesUpdate,omitempty"`
	ParentAdvertisesUpdateKnown bool `json:"parentAdvertisesUpdateKnown,omitempty"`
	ParentAdvertisesNotify      bool `json:"parentAdvertisesNotify,omitempty"`
	ParentAdvertisesNotifyKnown bool `json:"parentAdvertisesNotifyKnown,omitempty"`

	// Active attempt timing. Populated when an attempt is in flight
	// (pending-parent-push, pending-parent-observe) or when a
	// softfail probe has been sent.
	LastUpdate         string `json:"lastUpdate,omitempty"`         // start of the most recent push attempt
	LastAttemptStarted string `json:"lastAttemptStarted,omitempty"` // alias for LastUpdate (kept for clarity at parsing)
	ExpectedBy         string `json:"expectedBy,omitempty"`         // LastUpdate + ds-publish-delay
	AttemptTimeout     string `json:"attemptTimeout,omitempty"`     // LastUpdate + confirm-timeout (= ds-publish-delay × 1.2 by default)
	AttemptIndex       int    `json:"attemptIndex,omitempty"`       // 1..max during initial flurry; 0 in softfail or idle
	AttemptMax         int    `json:"attemptMax,omitempty"`         // policy max-attempts-before-backoff

	// Softfail state (populated when phase=parent-push-softfail or
	// when last_softfail_* is present from a prior failure).
	HardfailCount      int    `json:"hardfailCount,omitempty"`
	NextPushAt         string `json:"nextPushAt,omitempty"`
	LastSoftfailAt     string `json:"lastSoftfailAt,omitempty"`
	LastSoftfailCat    string `json:"lastSoftfailCategory,omitempty"`
	LastSoftfailDetail string `json:"lastSoftfailDetail,omitempty"`

	// Polling activity.
	LastPoll string `json:"lastPoll,omitempty"`
	NextPoll string `json:"nextPoll,omitempty"`

	// Last successful confirmed observation. Across all states.
	LastSuccess string `json:"lastSuccess,omitempty"`

	// Per-key state. KSKs are SEP DNSKEYs, ZSKs are non-SEP. CSK
	// rendering deferred — current code only lists, no special
	// handling.
	KSKs []RolloverKeyEntry `json:"ksks"`
	// HiddenRemovedKskCount is how many additional SEP keys in state
	// "removed" were omitted from KSKs after the display cap (sorted
	// by active_seq, most recent first).
	HiddenRemovedKskCount int                `json:"hiddenRemovedKskCount,omitempty"`
	ZSKs                  []RolloverKeyEntry `json:"zsks"`

	// Policy summary. Verbose mode shows this; compact mode hides it.
	Policy *PolicySummary `json:"policy,omitempty"`

	// Warnings carry runtime configuration concerns the engine wants
	// to surface to the operator on every status query — currently
	// the kasp.check_interval / attempt-timeout coupling check, but
	// designed to grow as more cross-config invariants are caught.
	// Empty slice means no warnings; rendered below the hint line.
	Warnings []string `json:"warnings,omitempty"`

	// PolicyErrors carries hard rollover-engine-blocking conditions:
	// E5/E10 invariant violations and parent-DSYNC blockers. When
	// non-empty, the engine refuses to advance keys; the CLI prepends
	// an "Error: automated rollovers stopped" header.
	PolicyErrors []string `json:"policyErrors,omitempty"`
	// PolicyWarnings carries E11 rule-of-thumb concerns: the engine
	// keeps rolling, but the policy has minimal headroom. The CLI
	// prepends a "Warning: rollover-policy" header when non-empty.
	PolicyWarnings []string `json:"policyWarnings,omitempty"`
}

// DSRange is an inclusive integer [low, high] rollover_index interval
// (endpoints included).
type DSRange struct {
	Low  int `json:"low"`
	High int `json:"high"`
}

// RolloverKeyEntry is one row of the per-key table in a status
// response.
type RolloverKeyEntry struct {
	KeyID     uint16 `json:"keyid"`
	ActiveSeq *int   `json:"activeSeq,omitempty"`
	State     string `json:"state"`
	// Published: KSK — short publish label (none / DS / DS+DNSKEY).
	// ZSK — RFC3339 wall time of published_at when set (operator column published_at).
	Published       string `json:"published,omitempty"`
	StateSince      string `json:"stateSince,omitempty"` // RFC3339
	LastRolloverErr string `json:"lastRolloverError,omitempty"`

	// NextTransition / NextTransitionAt describe what the engine
	// expects to do with this key next, with a best-effort wallclock.
	// Empty for terminal states (removed) and for transitions that
	// can't be timed yet (e.g. created → ds-published, which waits
	// on parent observation). NextTransitionAt is RFC3339 when set;
	// when unset, NextTransitionNote may carry a short qualifier
	// like "after parent observes DS".
	//
	// These fields reflect the engine's current intent, not a
	// guaranteed schedule — an operator-issued asap, a parent
	// outage, or a policy reload can shift them. The renderer's job
	// is to show the engine's plan as of "now."
	NextTransition     string `json:"nextTransition,omitempty"`
	NextTransitionAt   string `json:"nextTransitionAt,omitempty"`
	NextTransitionNote string `json:"nextTransitionNote,omitempty"`

	// NextTransitionEstimate marks NextTransitionAt as projected
	// rather than confirmed — set when the time depends on prior
	// rollovers in the pipeline completing first (e.g. standby keys
	// in slot 2+). Renderer appends "estimated" to the time delta.
	NextTransitionEstimate bool `json:"nextTransitionEstimate,omitempty"`

	// IsSynthetic flags a row that does not correspond to a real
	// keystore entry. Used for the "future key" row at the top of
	// the KSK table — a visual cue that the engine will generate
	// one more KSK on the next pipeline-fill tick. Renderer shows
	// the KeyID as "-----" (any non-zero numeric would mislead) and
	// suppresses fields that don't apply to a future-key projection.
	IsSynthetic bool `json:"isSynthetic,omitempty"`
}

// PolicySummary is the slice of DnssecPolicy operators want to see
// in status output. Doesn't expose private-key-relevant fields.
type PolicySummary struct {
	Name                     string `json:"name"`
	Algorithm                string `json:"algorithm"`
	KskLifetime              string `json:"kskLifetime"`
	ZskLifetime              string `json:"zskLifetime,omitempty"`
	DsPublishDelay           string `json:"dsPublishDelay"`
	MaxAttemptsBeforeBackoff int    `json:"maxAttemptsBeforeBackoff"`
	SoftfailDelay            string `json:"softfailDelay"`
	ClampingMargin           string `json:"clampingMargin,omitempty"`
}

// RolloverWhenResponse is returned by GET /api/v1/rollover/when.
// Carries both the policy-driven scheduled rollover time and the
// gate-driven earliest-possible time. Either may be empty when not
// applicable (e.g. zone has no rollover policy, or
// ComputeEarliestRollover returned a soft error reflected in Note).
//
// During in-progress rollovers, NextScheduled and EarliestPossible
// are projections of the rollover after the current one completes;
// InProgress=true is the operator-facing signal that the times
// reflect projection rather than current schedule.
type RolloverWhenResponse struct {
	Zone             string                  `json:"zone"`
	CurrentTime      string                  `json:"currentTime,omitempty"`      // RFC3339 UTC, server's wallclock
	NextScheduled    string                  `json:"nextScheduled,omitempty"`    // RFC3339 UTC
	EarliestPossible string                  `json:"earliestPossible,omitempty"` // RFC3339 UTC
	FromKeyID        uint16                  `json:"fromKeyId,omitempty"`
	ToKeyID          uint16                  `json:"toKeyId,omitempty"`
	InProgress       bool                    `json:"inProgress,omitempty"`
	Note             string                  `json:"note,omitempty"`
	Gates            []RolloverWhenGateEntry `json:"gates,omitempty"`
	// PolicyErrors carries hard rollover-engine-blocking conditions
	// (engine stops). PolicyWarnings carries rule-of-thumb concerns
	// (engine keeps rolling). Same split as RolloverStatus.
	PolicyErrors   []string `json:"policyErrors,omitempty"`
	PolicyWarnings []string `json:"policyWarnings,omitempty"`
	// Status / Blocker distinguish Case 1 (parent DS not at parent
	// — engine cannot promote, no ETA) from Case 2 (DS observed,
	// awaiting cache-flush — Earliest is set). Status values:
	// "ready", "waiting-for-parent", "policy-blocked".
	Status  string                `json:"status,omitempty"`
	Blocker *RolloverBlockerEntry `json:"blocker,omitempty"`
}

// RolloverBlockerEntry mirrors EarliestRolloverBlocker as wire JSON.
type RolloverBlockerEntry struct {
	Reason string `json:"reason"`
	Cause  string `json:"cause,omitempty"`
	KeyID  uint16 `json:"keyid,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// RolloverWhenGateEntry mirrors one EarliestRolloverGate as wire JSON.
type RolloverWhenGateEntry struct {
	Name string `json:"name"`
	At   string `json:"at"` // RFC3339 UTC
}

// Request/response types for POST /api/v1/rollover/asap. Returns the
// computed Earliest moment plus the from/to keyid pair for the
// scheduled rollover.
type RolloverAsapRequest struct {
	Zone string `json:"zone"`
}

type RolloverAsapResponse struct {
	Zone        string `json:"zone"`
	RequestedAt string `json:"requestedAt"`
	Earliest    string `json:"earliest"`
	FromKeyID   uint16 `json:"fromKeyId"`
	ToKeyID     uint16 `json:"toKeyId"`
}

// Request/response types for POST /api/v1/rollover/cancel.
type RolloverCancelRequest struct {
	Zone string `json:"zone"`
}

type RolloverCancelResponse struct {
	Zone    string `json:"zone"`
	Cleared bool   `json:"cleared"`
}

// Request/response types for POST /api/v1/rollover/reset.
type RolloverResetRequest struct {
	Zone  string `json:"zone"`
	KeyID uint16 `json:"keyid"`
}

type RolloverResetResponse struct {
	Zone    string `json:"zone"`
	KeyID   uint16 `json:"keyid"`
	Cleared bool   `json:"cleared"`
}

// Request/response types for POST /api/v1/rollover/unstick.
type RolloverUnstickRequest struct {
	Zone string `json:"zone"`
}

type RolloverUnstickResponse struct {
	Zone    string `json:"zone"`
	Cleared bool   `json:"cleared"`
}

// ConfigPathsResponse is returned by GET /api/v1/config/paths. Tells
// the CLI where the daemon's config + keystore live so commands like
// `auto-rollover validate` can re-parse the same YAML the daemon is
// running. Per-zone PolicyName is supplied via a separate query param
// so the same response shape can be reused for multiple validation
// flows in the future.
type ConfigPathsResponse struct {
	ConfigFile string `json:"configFile"` // main YAML
	DBFile     string `json:"dbFile"`     // sqlite keystore
	// PolicyName is the dnssecpolicy attached to the zone named in
	// ?zone=. Empty when ?zone= is not provided or the zone has no
	// rollover policy. CLI uses this to pick which dnssec.policies
	// block to validate.
	PolicyName string `json:"policyName,omitempty"`
}
