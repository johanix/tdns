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

	// Submitted/confirmed DS index ranges. Submitted is diagnostic-
	// only after rollover-overhaul phase 3; Confirmed is the gate
	// input to kskIndexPushNeeded.
	Submitted *DSRange `json:"submitted,omitempty"`
	Confirmed *DSRange `json:"confirmed,omitempty"`

	// Manual-rollover schedule (asap/cancel CLI flow).
	ManualRequestedAt string `json:"manualRequestedAt,omitempty"`
	ManualEarliest    string `json:"manualEarliest,omitempty"`

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
}

// DSRange is a [low, high] range over rollover_index values used to
// describe submitted and confirmed DS RRset windows.
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
}

// PolicySummary is the slice of DnssecPolicy operators want to see
// in status output. Doesn't expose private-key-relevant fields.
type PolicySummary struct {
	Name                     string `json:"name"`
	Algorithm                string `json:"algorithm"`
	KskLifetime              string `json:"kskLifetime"`
	DsPublishDelay           string `json:"dsPublishDelay"`
	MaxAttemptsBeforeBackoff int    `json:"maxAttemptsBeforeBackoff"`
	SoftfailDelay            string `json:"softfailDelay"`
	ClampingMargin           string `json:"clampingMargin,omitempty"`
}

// RolloverWhenResponse is returned by GET /api/v1/rollover/when.
// Wraps EarliestRolloverResult into wire-friendly types.
type RolloverWhenResponse struct {
	Zone     string                  `json:"zone"`
	Earliest string                  `json:"earliest"` // RFC3339 UTC
	FromIdx  int                     `json:"fromIdx"`
	ToIdx    int                     `json:"toIdx"`
	Gates    []RolloverWhenGateEntry `json:"gates"`
}

// RolloverWhenGateEntry mirrors one EarliestRolloverGate as wire JSON.
type RolloverWhenGateEntry struct {
	Name string `json:"name"`
	At   string `json:"at"` // RFC3339 UTC
}

// Request/response types for POST /api/v1/rollover/asap. Returns the
// computed Earliest moment plus the from/to index pair for the
// scheduled rollover.
type RolloverAsapRequest struct {
	Zone string `json:"zone"`
}

type RolloverAsapResponse struct {
	Zone        string `json:"zone"`
	RequestedAt string `json:"requestedAt"`
	Earliest    string `json:"earliest"`
	FromIdx     int    `json:"fromIdx"`
	ToIdx       int    `json:"toIdx"`
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
