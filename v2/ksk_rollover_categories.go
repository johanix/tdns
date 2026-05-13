package tdns

import "time"

// RolloverFailureCategory enumerates the four kinds of failure the
// rollover engine distinguishes when recording a softfail event.
// Operator action depends on category, so the enum value is exposed
// directly in status output (no humanization layer between).
//
//	child-config           a problem on this side: missing SIG(0)
//	                       key, no DS to publish, ParentZone
//	                       unresolvable. Operator fixes child
//	                       config.
//	transport              network or DNS resolution failure
//	                       between us and the parent endpoint.
//	                       Operator checks reachability or
//	                       DSYNC configuration.
//	parent-rejected        the parent returned a negative rcode
//	                       (REFUSED, NOTAUTH, FORMERR, SERVFAIL).
//	                       Operator fixes parent policy / delegation.
//	parent-publish-failure the parent returned NOERROR but the DS
//	                       never appeared on the wire. Operator
//	                       investigates the parent's update→publish
//	                       pipeline. For tdns-vs-tdns deployments
//	                       this is often a known parent bug masked
//	                       by NOERROR; phase 11 fixes it on the
//	                       parent side, after which most cases that
//	                       land here will move to parent-rejected
//	                       with a specific EDE.
const (
	SoftfailChildConfig          = "child-config"
	SoftfailTransport            = "transport"
	SoftfailParentRejected       = "parent-rejected"
	SoftfailParentPublishFailure = "parent-publish-failure"

	// child-config subcategories (NOTIFY-scheme phase 6).
	//
	// SoftfailChildConfigWaitingForParent: parent advertises no
	// rollover-usable DSYNC scheme (or none matching the policy's
	// dsync-scheme-preference). Distinct recovery model: the engine
	// halts but probes forever with backoff capped at 1h. Never
	// increments hardfail_count and never escalates. Recovers
	// automatically when the parent restores DSYNC advertisement.
	//
	// SoftfailChildConfigLocalError: every other child-config source
	// — no SIG(0) key, no DS to publish, ParentZone unresolvable,
	// SignMsg failed, NOTIFY publish-and-sign queue failure. Existing
	// softfail-then-long-term path. Operator intervention typically
	// required.
	SoftfailChildConfigWaitingForParent = "child-config:waiting-for-parent"
	SoftfailChildConfigLocalError       = "child-config:local-error"
)

// waitingForParentBackoffCap is the upper bound on softfail-delay
// when category is SoftfailChildConfigWaitingForParent. The 1h cap
// matches the natural IMR DSYNC re-fetch cadence (typical parent
// DSYNC TTL); the probe IS the poll. No separate slow-tick
// infrastructure needed.
const waitingForParentBackoffCap = time.Hour
