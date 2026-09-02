/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto"
	"database/sql"
	"log"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

type ZoneStore uint8

const (
	XfrZone ZoneStore = iota + 1
	MapZone
)

var ZoneStoreToString = map[ZoneStore]string{
	XfrZone: "XfrZone",
	MapZone: "MapZone",
}

// zoneStoreToConfigToken maps a ZoneStore to its CANONICAL config-file token
// ("map"/"slice"/"xfr") — the form parseZoneStore reads. This is deliberately
// distinct from ZoneStoreToString, which is the human/display form ("MapZone")
// used in API responses and logs. Persisting config must use the token, not the
// display string, or the daemon writes a value its own reader rejects.
var zoneStoreToConfigToken = map[ZoneStore]string{
	XfrZone: "xfr",
	MapZone: "map",
}

// zoneStoreConfigToken returns the canonical config token for s, defaulting to
// "map" for any unmapped value (matching parseZoneStore's default).
func zoneStoreConfigToken(s ZoneStore) string {
	if tok, ok := zoneStoreToConfigToken[s]; ok {
		return tok
	}
	return "map"
}

type ZoneType uint8

const (
	Primary ZoneType = iota + 1
	Secondary
)

var ZoneTypeToString = map[ZoneType]string{
	Primary:   "primary",
	Secondary: "secondary",
}

const (
	Sig0StateCreated       string = "created"
	Sig0StatePublished     string = "published"
	Sig0StateActive        string = "active"
	Sig0StateRetired       string = "retired"
	DnskeyStateCreated     string = "created"
	DnskeyStatePublished   string = "published"
	DnskeyStateDsPublished string = "ds-published"
	DnskeyStateStandby     string = "standby"
	DnskeyStateActive      string = "active"
	DnskeyStateRetired     string = "retired"
	DnskeyStateRemoved     string = "removed"
)

// MPdata caches multi-provider membership and signing state for a zone.
// nil means the zone is not confirmed as a multi-provider zone (either OptMultiProvider
// is not set, or the zone owner hasn't declared it via HSYNC3+HSYNCPARAM, or we are
// not a listed provider). Populated during zone refresh by populateMPdata().
//
// NOTE: This is an MP type that lives in tdns (not tdns-mp) because it is
// a field of ZoneMPExtension, which is a field of ZoneData.
/*
type MPdata struct {
       WeAreProvider bool                // At least one of our agent identities matches an HSYNC3 Identity
       OurLabel      string              // Our provider label from the matching HSYNC3 record
       WeAreSigner   bool                // Our label appears in HSYNCPARAM signers (or zone is unsigned)
       OtherSigners  int                 // Count of other signers in HSYNCPARAM
       ZoneSigned    bool                // HSYNCPARAM signers= is non-empty (zone uses multi-signer)
       Options       map[ZoneOption]bool // MP-specific options (future: migrate from zd.Options)
}
*/

// ZoneRefreshAnalysis carries analysis results from OnZonePreRefresh
// to OnZonePostRefresh. Set before the hard flip, consumed after.
type ZoneRefreshAnalysis struct {
	DelegationChanged bool
	DelegationStatus  DelegationSyncStatus
	//	HsyncChanged      bool
	//	HsyncStatus       *HsyncStatus
	DnskeyChanged bool
	DnskeyStatus  *DnskeyStatus
}

type ZoneData struct {
	mu sync.Mutex
	// policyApplyMu serializes a full DNSSEC-policy apply (rebind → re-sign →
	// persist → revert) for this zone. It is the OUTERMOST lock of that
	// operation and is distinct from mu: SignZone takes mu internally, so the
	// apply cannot hold mu across the sign; without a separate lock two
	// concurrent applies could interleave and a failed revert could clobber a
	// newer binding. Acquired by applyZonePolicyTransactional; policy-reset
	// holds it across its clear+re-sign via the *Locked variant. Never held
	// while mu is held, so there is no lock-order inversion with SignZone.
	policyApplyMu sync.Mutex
	// generation is bumped on every removal/replacement of this zone
	// (RemoveDynamicZone, ModifyDynamicZone, config-reload Zones.Remove). A
	// refresh goroutine snapshots it at dispatch; the pre-persist guard (B5b)
	// drops the persist if the live generation no longer matches — closing the
	// resurrection race where a mid-flight refresh re-writes a deleted zone.
	generation atomic.Uint64
	ZoneName   string
	ZoneStore  ZoneStore // 1 = "xfr", 2 = "map". An xfr zone only supports xfr related ops
	ZoneType   ZoneType
	ApexLen    int
	//	RRs            RRArray
	Data *core.NameMap[OwnerData]
	// 20260415 johani: MP    *ZoneMPExtension // Multi-provider state; nil for non-MP zones
	Ready bool // true if zd.Data has been populated (from file or upstream)
	// Status is the positive-lifecycle state (pending -> loading -> ready),
	// orthogonal to the error registry. Use SetStatus/GetStatus to mutate/read.
	// Surfaced to the API as ZoneConf.Provisioning. Added alongside Ready/
	// FirstZoneLoad without rewriting their consumers.
	Status ZoneStatus

	Logger *log.Logger
	// ZoneFile           string // TODO: Remove this
	IncomingSerial uint32 // SOA serial that we got from upstream
	CurrentSerial  uint32 // SOA serial after local bumping
	// OutboundSoaSerial is the PER-ZONE outbound serial mode (keep | unixtime
	// | persist), sourced from the zone's config (possibly via its template).
	// Empty means "inherit the server-global authengine.outbound-soa-serial".
	// Never read directly — call zd.EffectiveOutboundSoaSerial(), which
	// resolves the zone/global tiers.
	OutboundSoaSerial string
	// TransferSrc is the per-zone source address for OUTBOUND transfers, i.e.
	// what the upstream's allow-transfer ACL sees. Never read directly — call
	// zd.EffectiveTransferSrc(), which falls back to authengine.transfer-src.
	TransferSrc []string
	// TransferSrcTier records which tier TransferSrc was resolved FROM, and is
	// set only when TransferSrc was populated by resolution rather than by
	// configuration -- i.e. on the scratch zone an inbound AXFR is received
	// into, which is handed an already-resolved list. Empty on a normal zone,
	// where EffectiveTransferSrcWithSource derives the tier itself. Without it
	// a globally-configured source is reported as coming from the zone.
	TransferSrcTier string
	FirstZoneLoad   bool // true until first zone data has been loaded
	Verbose         bool
	Debug           bool
	IxfrChain       []Ixfr
	PrimariesConf   []PeerConf // as-written primaries; persisted; re-resolved each load (P3)
	Upstreams       []PeerConf // resolved addr:port tuples; runtime-only; used for transfer
	Notify          []PeerConf // downstream secondaries that we notify (addr + key)
	AllowNotify     []AclEntry // secondary: who may NOTIFY us; empty => accept from resolved primaries
	Downstreams     []AclEntry // primary: who may AXFR from us (provide-xfr ACL); empty => deny
	DownstreamAuth  []string   // acceptable transfer-auth mechanism classes (empty => unrestricted); see authorizeTransfer
	Zonefile        string
	// Template names the config template an API-provisioned zone was expanded
	// from (zone add --template). Persisted in the dynamic config entry so a
	// restart re-expands it; the update policy is deliberately NOT persisted —
	// it re-derives from the template at boot (one source of truth).
	Template          string
	DelegationSyncQ   chan DelegationSyncRequest
	Parent            string   // name of parentzone (if filled in)
	ParentNS          []string // names of parent nameservers
	ParentServers     []string // addresses of parent nameservers
	Children          map[string]*ChildDelegationData
	DelegationBackend DelegationBackend // parent-side: backend for storing child delegation data
	Options           map[ZoneOption]bool
	// SuppressedOptions records the origination options that were configured
	// for this zone but stripped by normalizeOptionsForRole (a tdns-auth
	// secondary may not originate content). Options above is the EFFECTIVE
	// set; Options ∪ SuppressedOptions is the AS-CONFIGURED set, which is what
	// must be re-serialized when a dynamic zone's config file is regenerated —
	// otherwise the operator's stated intent is silently deleted from their own
	// config. Use asConfiguredOptions(). nil when nothing was suppressed.
	SuppressedOptions map[ZoneOption]bool
	UpdatePolicy      UpdatePolicy
	DelegationPolicy  *DelegationPolicy
	DnssecPolicy      *DnssecPolicy
	DnssecPolicyName  string // name of currently-applied policy; used to detect config-reload-driven changes
	MultiSigner       *MultiSignerConf
	KeyDB             *KeyDB
	// proxySig0ParentBootstrapped is set after the parent accepted the
	// self-signed SIG(0) ceremony (rcode NOERROR) for the KEY currently
	// at the apex. Cleared when the KEY leaves the apex so a later
	// WAITING→READY transition runs the ceremony again.
	proxySig0ParentBootstrapped bool
	AppType                     AppType
	// Errors holds all active error conditions on this zone. Use SetError /
	// ClearError to mutate; HasError / ErrorList to inspect.
	// The fields below (Error, ErrorType, ErrorMsg) are derived from
	// Errors and kept in sync by SetError / ClearError. Existing call
	// sites that read those single-error fields continue to work; new
	// code can iterate ErrorList() for the full set.
	Errors      map[ErrorType]ZoneError
	Error       bool      // derived: len(Errors) > 0
	ErrorType   ErrorType // derived: highest-priority error type, see errorTypeReportOrder
	ErrorMsg    string    // derived: msg of the type reported in ErrorType
	LatestError time.Time // time of latest error
	// RefreshCount is NOT a have-data test, whatever its name suggests: it is
	// incremented only by initialLoadZone, so it reaches 1 at most once and
	// stays there however many refreshes follow -- and never leaves 0 at all
	// for a zone provisioned through the API in this process. The query and
	// UPDATE paths use zd.HasPublishedData() instead. Fix this to count
	// refreshes or retire it; see §6 of
	// docs/2026-08-28-secondary-serve-until-expire.md.
	RefreshCount  int       // times initialLoadZone loaded the zone (0 or 1), reported over the API
	LatestRefresh time.Time // when a usable SOA was last seen; what SOA EXPIRE is measured from
	// expireClampLoggedSerial is the serial the EXPIRE-clamp warning was last
	// emitted for, so a primary publishing a nonsensical EXPIRE is reported
	// once per copy rather than once per query. See effectiveExpire.
	expireClampLoggedSerial uint32
	SourceCatalog           string // if auto-configured, which catalog zone created this zone
	// ParentDSTTLObserved is the most recent TTL observed on the parent's
	// DS RRset (seconds). Refreshed by every successful QueryParentAgentDS
	// call. Zero means "not yet observed" — the E10 cache-flush invariant
	// check defers until either this value or DnssecPolicy.TTLS.ParentDS is set.
	ParentDSTTLObserved uint32

	// Zone snapshot publish path (Project B).
	snapshot atomic.Pointer[zoneSnapshot]
	// signingKeys is the per-zone copy-on-write active DNSSEC key set (G3).
	// Lock-free reads via SigningKeys() / ActiveDnssecKeys(); writers republish
	// post-commit via republishSigningKeys. Separate from the zone-data snapshot.
	signingKeys atomic.Pointer[signingKeysSnapshot]
	// signingKeysGen is bumped at the start of each republishSigningKeys call.
	// A build may Store only if it still owns the latest generation, so an
	// older overlapping republish cannot overwrite a newer snapshot.
	signingKeysGen atomic.Uint64
	workingSet     map[string]*OwnerData
	// wsSignalSynth stages the synthesized-transport-signal fallback map for the
	// next publish (see zoneSnapshot.signalSynth). Seeded from the published
	// snapshot in ensureWorkingSet so unrelated publishes preserve it.
	wsSignalSynth  map[string]*core.RRset
	publishCadence time.Duration
	publishQueued  bool
	publishUrgent  bool
	// ixfrDerived marks a transfer scratch zone whose contents were produced by
	// applying an inbound difference sequence to the copy we already served,
	// rather than by receiving a whole zone. Set on the scratch zone by the
	// IXFR apply and read once, by applyRefreshReplacementLocked, to decide
	// whether the replacement really is a new IXFR epoch. See §5 of
	// docs/2026-07-25-inbound-ixfr-plan.md.
	ixfrDerived bool

	// wsIxfrEpochReset marks the next publish as a new IXFR epoch (wholesale
	// zone replacement): updateIxfrChainLocked clears the delta history
	// instead of diffing. Set under zd.mu by applyRefreshReplacementLocked.
	wsIxfrEpochReset bool
	// wsPersistDelta marks the next publish as a real content change whose
	// delta belongs in the ZoneDelta table (Phase 2). Only the applier sets
	// it. Every other publish -- refresh, reload, signalSynth-only, and above
	// all the replay of persisted deltas during load -- leaves it clear. A
	// replay that re-persisted what it just replayed would double the stored
	// history on every restart.
	wsPersistDelta bool
	// fileSerial is the SOA serial of the zone FILE as last read from or
	// written to disk. It is NOT CurrentSerial: a zone that re-signs or
	// republishes during load advances CurrentSerial well past what the file
	// says, and the delta journal has to be anchored to the file, because the
	// file is what the next load starts from. Guarded by zd.mu.
	fileSerial uint32
	// deltasReplayed records that the persisted deltas have already been
	// applied on top of the zone file CURRENTLY loaded. Set by
	// ReplayPersistedDeltas on success and cleared by
	// applyRefreshReplacementLocked whenever the zone is re-read from file, so
	// a genuine reload replays again while a repeated completion attempt for
	// the same load does not. Guarded by zd.mu.
	deltasReplayed bool
	// fileDigest is the ZONEMD digest of the zone FILE as last read from or
	// written to disk, the companion to fileSerial. The serial says which
	// version the file claims to be; the digest says whether it is actually
	// that version -- a file can be regenerated, restored or reformatted
	// without the serial moving. Empty when the zone did not come from a file.
	// Guarded by zd.mu.
	fileDigest string
	// fileStatPath, fileModTime and fileSize are the stat of the zone file as
	// tdns last LOOKED at it -- the cheap gate in front of the digest, so a
	// refresh of an untouched file does not parse and digest a zone to learn
	// that nothing happened. In memory only and deliberately not persisted: a
	// zero value means "not looked at in this process", which is exactly right
	// for a first load, and a restart re-establishes them by parsing once.
	//
	// Unlike fileDigest, these are recorded whether or not the file was
	// ADOPTED, because they answer a different question -- "have we already
	// looked at this exact file?" rather than "which file is the zone
	// serving?". Guarded by zd.mu.
	fileStatPath string
	fileModTime  time.Time
	fileSize     int64
	// wsPersistErr carries a failed delta write from publishWorkingSetLocked
	// back to the applier. A publish whose delta could not be persisted is
	// refused outright -- serving a change that is certain to vanish at the
	// next restart is worse than not serving it -- and this is how the applier
	// learns to report that rather than claim success.
	wsPersistErr error
	// ixfrChainMaxBytes bounds the retained IXFR delta history (estimated
	// wire bytes). 0 => DefaultIxfrChainMaxBytes; negative => retention
	// disabled (IXFR queries are answered with full transfers). From zone
	// config ixfr-chain-max-bytes; written at parse time under zd.mu.
	ixfrChainMaxBytes int
	// zonemdAlgs and zonemdScheme are the resolved RFC 8976 parameters for
	// this zone's published ZONEMD, from the zone config's `zonemd` block.
	// Meaningful only when OptPublishZonemd is set. Written at parse time
	// under zd.mu, like ixfrChainMaxBytes above.
	zonemdAlgs   []uint8
	zonemdScheme uint8
	// zonemdOnVerifyFailure is the resolved ZonemdConf.OnVerifyFailure,
	// meaningful only when OptVerifyZonemd is set. Written at parse time under
	// zd.mu, like the two fields above.
	zonemdOnVerifyFailure string
	// zonemdWireCacheMaxBytes bounds the canonical-wire cache the publish path
	// keeps so it re-renders only what changed. 0/unset =>
	// DefaultZonemdWireCacheBytes; negative => caching disabled. Same sentinel
	// convention as ixfrChainMaxBytes above, deliberately.
	zonemdWireCacheMaxBytes int
	// zonemdCache holds one rendered block per owner name, tagged with the
	// *OwnerData it came from -- pointer identity is the validity check. Read
	// and written ONLY by the publish path under zd.mu; see zonemd_cache.go.
	zonemdCache      map[string]zonemdCacheEntry
	zonemdCacheStats ZonemdCacheStats
	// zonemdManaged records that the apex ZONEMD RRset now in this zone was
	// put there by us rather than by the operator. It is what makes turning
	// the option OFF remove our record while leaving a hand-authored one
	// alone. In memory only: after a restart with the option off, a ZONEMD in
	// the zone file is indistinguishable from operator data and is treated as
	// such. Guarded by zd.mu.
	zonemdManaged bool
	// zonemdDigests caches the digests computed by the last publish, keyed by
	// RFC 8976 hash algorithm, and zonemdDigestSerial is the serial they
	// describe.
	//
	// The point is the SHA-384 entry: ZoneDigest excludes the apex ZONEMD and
	// its RRSIG, so the value published in the ZONEMD RR is bit-for-bit the
	// value ZoneFileState wants, and a zone write can record its file identity
	// without digesting the whole zone a second time. Guarded by zd.mu.
	zonemdDigests      map[uint8]string
	zonemdDigestSerial uint32
	// zonemdLastErr is the last reason this zone could not publish a ZONEMD,
	// empty when it can. Held only so the failure is logged on transition
	// rather than on every publish. Guarded by zd.mu.
	zonemdLastErr   string
	lastPublish     time.Time
	publishWake     chan struct{}
	publisherOnce   sync.Once
	publishStop     chan struct{}
	publishStopOnce sync.Once
	// RemoteDNSKEYs holds DNSKEY RRs from other signers (multi-signer mode 4).
	// These are DNSKEYs found in the incoming zone that do not match keys in our
	// local keystore. They are preserved across resignings and merged into the
	// DNSKEY RRset during PublishDnskeyRRs().
	// RemoteDNSKEYs []dns.RR

	// OnFirstLoad holds one-shot callbacks executed after the zone's first successful load.
	// Apps register these before RefreshEngine starts, and RefreshEngine clears the slice
	// after executing them. Protected by zd.mu.
	OnFirstLoad []func(*ZoneData)

	// OnZonePreRefresh callbacks run BEFORE the hard flip in FetchFromFile/FetchFromUpstream.
	// They receive both old (zd, current, still served) and new (new_zd, incoming, not yet served)
	// zone data. Used for: analysis (compare old vs new for HSYNC/DNSKEY/delegation changes),
	// modification of new_zd (combiner contributions, signature TXT, MP data population),
	// and agent RFIs (RequestAndWaitForKeyInventory). Options map is shared between zd and new_zd.
	OnZonePreRefresh []func(zd, new_zd *ZoneData)

	// OnZonePostRefresh callbacks run AFTER the hard flip (and after RepopulateDynamicRRs).
	// They receive zd which now serves the new data. Used for: queue sends (SyncQ,
	// DelegationSyncQ) that need the live zone pointer, and any post-flip notifications.
	OnZonePostRefresh []func(zd *ZoneData)

	// ProxyRefreshAnalysis carries the delegation-sync-proxy change-detection
	// result from the PreRefresh hook (which sees old+new zone data) to the
	// PostRefresh hook (which acts). nil when no proxy analysis is pending.
	// Set/consumed only on the OnZonePreRefresh/PostRefresh path for zones with
	// OptDelSyncProxy; protected by zd.mu.
	ProxyRefreshAnalysis *ProxyDelegationAnalysis
}

// Lock and Unlock expose the mutex for code that moves to
// tdns-mp and can no longer access the unexported zd.mu.
func (zd *ZoneData) Lock()   { zd.mu.Lock() }
func (zd *ZoneData) Unlock() { zd.mu.Unlock() }

// NOKEY is the built-in sentinel key name meaning "no TSIG, unauthenticated".
// Every PeerConf carries a key name; NOKEY makes the no-TSIG choice explicit.
// It is a reserved name: a keys.tsig[] entry named NOKEY is rejected at parse.
const NOKEY = "NOKEY"

// PeerConf is a replication peer reference: an address plus a TSIG key name.
// Used for the upstream primary (secondary zones) and downstream notify peers
// (primary zones). Key is mandatory and explicit; NOKEY means unauthenticated.
// The Legacy field is set by stringToPeerConfHook when a bare-string value is
// found in config (pre-migration shape); a non-empty Legacy quarantines the
// zone to ERROR at validation rather than aborting the whole-file decode.
type PeerConf struct {
	Addr   string `yaml:"addr" mapstructure:"addr"`
	Key    string `yaml:"key" mapstructure:"key"`
	Legacy string `yaml:"-" mapstructure:"-"` // bare-string marker; not config

	// PeersRef holds the ids of a `- peers: [ id, ... ]` reference entry
	// (see the peers: block, v2/peers.go). Consumed (and cleared) by
	// expandPeerList at parse time; post-expansion lists never contain
	// reference entries.
	PeersRef []string `yaml:"peers" mapstructure:"peers"`

	// XoT (XFR-over-TLS, RFC 9103) fields. All optional; an empty Transport
	// means Do53 and preserves pre-XoT behavior exactly. TSIG (Key) remains
	// orthogonal: RFC 9103 allows TSIG and TLS together, so a peer may have
	// both a TLS auth mode and a TSIG key. Validated by validatePeerXoT.
	Transport string   `yaml:"transport" mapstructure:"transport"` // "" | do53 | dot
	TLSAuth   string   `yaml:"tls-auth" mapstructure:"tls-auth"`   // pin | dane | pkix (required for dot)
	TLSName   string   `yaml:"tls-name" mapstructure:"tls-name"`   // SNI + DANE base name; defaults to the Addr hostname
	Pins      []string `yaml:"pins" mapstructure:"pins"`           // base64 SPKI SHA-256 pins (tls-auth: pin)
	CAFile    string   `yaml:"ca-file" mapstructure:"ca-file"`     // PEM bundle (tls-auth: pkix); empty = system roots
}

// ZoneConf represents the external config for a zone; it contains no zone data
type ZoneConf struct {
	Name              string `validate:"required"`
	Zonefile          string
	Type              string     `validate:"required"`
	Store             string     // xfr | map | slice | reg (defaults to "map" if not specified)
	Primaries         []PeerConf `yaml:"primaries" mapstructure:"primaries"` // upstream set, for secondary zones
	Notify            []PeerConf
	AllowNotify       []AclEntry   `yaml:"allow-notify" mapstructure:"allow-notify"`       // secondary: who may NOTIFY us (ip-spec + key｜NOKEY｜BLOCKED)
	Downstreams       []AclEntry   `yaml:"downstreams" mapstructure:"downstreams"`         // primary: who may AXFR from us (provide-xfr ACL)
	DownstreamAuth    []string     `yaml:"downstream-auth" mapstructure:"downstream-auth"` // acceptable transfer-auth mechanisms: prefix|tsig|tls-pin|tls-pkix|tls-dane|any
	OptionsStrs       []string     `yaml:"options" mapstructure:"options"`
	Options           []ZoneOption `yaml:"-" mapstructure:"-"` // Ignore during both yaml and mapstructure decoding
	Frozen            bool         // true if zone is frozen; not a config param
	Dirty             bool         // true if zone has been modified; not a config param
	UpdatePolicy      UpdatePolicyConf
	DelegationBackend string `yaml:"delegationbackend" mapstructure:"delegationbackend"` // named backend for child delegation data
	DnssecPolicy      string `yaml:"dnssecpolicy" mapstructure:"dnssecpolicy"`
	DelegationPolicy  string `yaml:"delegationpolicy" mapstructure:"delegationpolicy"`
	// OutboundSoaSerial is the per-zone override of the server-global
	// authengine.outbound-soa-serial. Empty (the default) inherits the global.
	// Set it on a TEMPLATE to give a whole class of zones a serial policy —
	// that is the intended granularity; a zone that sets it explicitly wins
	// over its template (ExpandTemplate gap-fills only unset fields, and a
	// non-empty string counts as set, so an explicit "keep" beats a template
	// "persist").
	OutboundSoaSerial string `yaml:"outbound-soa-serial,omitempty" mapstructure:"outbound-soa-serial" validate:"omitempty,oneof=keep unixtime persist"`
	// TransferSrc is the per-zone override of the server-global
	// authengine.transfer-src: the local address to bind when dialling this
	// zone's upstreams, which is what the primary's allow-transfer ACL sees.
	// Empty (the default) inherits the global. Set it on a TEMPLATE to give a
	// whole class of zones one source address -- the same granularity argument
	// as OutboundSoaSerial above, and the reason a dynamically-provisioned
	// secondary can get a source address without the API having to carry one.
	TransferSrc []string `yaml:"transfer-src,omitempty" mapstructure:"transfer-src"`
	// EffectiveDnssecPolicy / DnssecPolicyOverridden / DnssecPolicyConfigBase
	// are display-only fields populated by the list-zones handler: the policy
	// actually bound to the running zone; whether it came from a dynamic
	// `set-policy` override (rather than the config base); and, when
	// overridden, the config-base policy it overrides. Not config; not
	// serialized to YAML.
	EffectiveDnssecPolicy  string `yaml:"-"`
	DnssecPolicyOverridden bool   `yaml:"-"`
	DnssecPolicyConfigBase string `yaml:"-"`
	// AppliedPolicy / AppliedSource / AppliedAt and PolicyDetail are display-only
	// fields populated ONLY by the single-zone `zone desc` path (list-zones scoped
	// to one zone): the last-applied DNSSEC-policy record from the keystore
	// (policy name; source config|command; the applied_at timestamp) and a
	// projection of the zone's currently-bound policy's algorithm/lifetime/
	// sig-validity detail. The bulk `list-zones` path (backing `zone list`) never
	// sets these, so its output is unchanged. Not config; not serialized to YAML.
	AppliedPolicy string `yaml:"-"`
	AppliedSource string `yaml:"-"`
	AppliedAt     string `yaml:"-"`
	// AppliedError is set (to the error text) when the keystore read for the
	// applied-policy record failed, so `zone desc` can distinguish a backend
	// failure from a genuinely absent record rather than showing both as
	// "(not recorded)".
	AppliedError string            `yaml:"-"`
	PolicyDetail *DnssecPolicyView `yaml:"-"`
	// Serial visibility (display-only; not config). CurrentSerial is what we
	// advertise to our downstreams, IncomingSerial what we last received from
	// upstream. Both are free to populate — they are already on ZoneData — and
	// `zone list -v` shows them side by side.
	//
	// UpstreamSerials is populated ONLY by the single-zone `zone desc` path: it
	// costs a live SOA probe per configured primary, which is fine for one zone
	// and not for a bulk listing. Per-primary rather than one aggregate value
	// is the point — "this master says 42, that one says 5000" is the direct
	// diagnostic for the split-brain that motivated the MUST-NOT-MODIFY work,
	// and there is currently no way to see it from tdns at all.
	CurrentSerial   uint32           `yaml:"-"`
	IncomingSerial  uint32           `yaml:"-"`
	UpstreamSerials []UpstreamSerial `yaml:"-"`
	// EffectiveOutboundSoaSerial is the resolved outbound serial mode and where
	// it came from ("zone", "global" or "default"), so an operator can see both
	// the value and why it applies.
	EffectiveOutboundSoaSerial string `yaml:"-"`
	OutboundSoaSerialSource    string `yaml:"-"`
	Template                   string `yaml:"template" mapstructure:"template"`
	// DynamicZones marks a TEMPLATE as instantiable via the dynamic-zones API
	// (zone add --type primary --template <name>). It is the per-template
	// opt-in gate: an API client can only pick among operator-blessed
	// configurations, never author one. Meaningful on templates only; never
	// copied to zones by ExpandTemplate.
	DynamicZones  bool      `yaml:"dynamiczones" mapstructure:"dynamiczones"`
	MultiSigner   string    `yaml:"multisigner" mapstructure:"multisigner"`
	Error         bool      // zone is broken and cannot be used
	ErrorType     ErrorType // "config" | "refresh" | "agent" | "DNSSEC"
	ErrorMsg      string    // reason for the error (if known)
	RefreshCount  int       // times initialLoadZone loaded the zone (0 or 1); NOT a have-data test, see ZoneData.RefreshCount
	SourceCatalog string    // if auto-configured, which catalog zone created this zone
	// ApiManaged marks a zone created/managed via the dynamic-zones API (zone
	// add/delete/modify). Persisted so OptApiManagedZone can be re-derived on
	// reload — a dedicated bool, not a SourceCatalog="api" sentinel.
	ApiManaged bool `yaml:"apimanaged" mapstructure:"apimanaged"`
	// PublishCadence is the minimum interval between coalesced snapshot publishes
	// for this zone (default 5s when unset). RFC 2136 urgent publishes bypass.
	PublishCadence string `yaml:"publish-cadence" mapstructure:"publish-cadence"`
	// IxfrChainMaxBytes bounds the retained outbound-IXFR delta history for
	// this zone (estimated wire bytes). 0/unset => 1 MiB default; negative =>
	// disable retention (IXFR clients always get a full transfer).
	IxfrChainMaxBytes int `yaml:"ixfr-chain-max-bytes" mapstructure:"ixfr-chain-max-bytes"`
	// Provisioning is a display-only derived lifecycle string
	// ("pending"|"loading"|"ready"|"error") populated by the list handlers from
	// ZoneStatus + the error registry. Not config; not serialized to YAML.
	Provisioning string `yaml:"-" mapstructure:"-"`
	// Zonemd parameterises the `publish-zonemd` option. Separate from the
	// option because Options is a map[ZoneOption]bool by construction and
	// cannot carry a value; separate from the DNSSEC policy because ZONEMD is
	// not DNSSEC — an unsigned zone may publish one, and binding the
	// parameters to a policy would make it need one first.
	Zonemd ZonemdConf `yaml:"zonemd" mapstructure:"zonemd"`
}

// ZonemdConf is the per-zone ZONEMD parameter block:
//
//	zones:
//	  example.com:
//	    options: [ publish-zonemd ]
//	    zonemd:
//	      algorithms: [ 1 ]   # 1 = SHA-384 (default), 2 = SHA-512
//	      scheme: 1           # SIMPLE; the only scheme RFC 8976 defines
//
// Both fields are optional; an empty block means SIMPLE/SHA-384. Ignored
// entirely unless the zone carries the publish-zonemd option, so a leftover
// block on a zone whose option was removed is inert rather than an error.
type ZonemdConf struct {
	// Algorithms are the RFC 8976 hash algorithm codepoints to publish, one
	// apex ZONEMD RR each. Empty => [1] (SHA-384), the mandatory-to-implement
	// algorithm and the one every published ZONEMD in the wild uses.
	Algorithms []uint8 `yaml:"algorithms" mapstructure:"algorithms"`
	// Scheme is the RFC 8976 collation scheme. 0 (unset) => 1 (SIMPLE). Only
	// SIMPLE is defined, so this exists to reject a config that asks for
	// something else rather than to offer a choice.
	Scheme uint8 `yaml:"scheme" mapstructure:"scheme"`
	// WireCacheMaxBytes bounds the canonical-wire cache that lets a publish
	// re-render only the owners it changed. 0/unset =>
	// DefaultZonemdWireCacheBytes (64 MiB); negative => caching disabled.
	//
	// The budget matters because the saving and the cost both scale with zone
	// size: the zones that gain most from the cache are the ones that can least
	// afford it, and on a PQ-signed zone an RRSIG's RDATA is kilobytes rather
	// than a hundred bytes. A byte budget is self-selecting -- a small zone
	// never reaches it -- and degrades in proportion rather than at a cliff.
	//
	// PER ZONE. A server with many large zones multiplies it; this does not
	// bound the host's memory across a fleet.
	WireCacheMaxBytes int `yaml:"wire-cache-max-bytes" mapstructure:"wire-cache-max-bytes"`
	// OnVerifyFailure decides what a failed `verify-zonemd` check does:
	// "refuse" (the default) declines the zone and keeps serving what the
	// server already had, "warn" adopts it and logs.
	//
	// Refuse is the default because the point of asking for verification is to
	// find out that a zone is not what its publisher says it is, and adopting
	// it anyway answers the question without acting on it. Warn exists for the
	// rollout, where the first thing an operator needs to know is whether
	// their own primaries would have passed.
	OnVerifyFailure string `yaml:"on-verify-failure" mapstructure:"on-verify-failure"`
}

// ZONEMD verification failure modes (ZonemdConf.OnVerifyFailure).
const (
	ZonemdOnFailureRefuse = "refuse"
	ZonemdOnFailureWarn   = "warn"
)

// DnssecPolicyView is a display-only projection of the DnssecPolicy bound to a
// zone, carried in ZoneConf.PolicyDetail and populated only by the `zone desc`
// path. It holds the operator-relevant algorithm/lifetime/sig-validity fields as
// raw values (algorithm numbers, lifetimes and sig-validity in seconds); the CLI
// renderer turns them into algorithm names and human durations. Error mirrors
// DnssecPolicy.Error: non-empty means the policy failed to parse and the other
// fields may be incomplete. Not config; not serialized to YAML.
type DnssecPolicyView struct {
	Name               string
	Error              string
	Mode               string // ksk-zsk | csk
	Algorithm          uint8  // default / CSK algorithm
	KSKAlgorithm       uint8
	ZSKAlgorithm       uint8
	KSKLifetime        uint32 // seconds
	ZSKLifetime        uint32 // seconds
	CSKLifetime        uint32 // seconds
	SigValidityDefault uint32 // seconds
	SigValidityDNSKEY  uint32 // seconds
	SigValidityDS      uint32 // seconds
}

type TemplateConf struct {
	Name           string `validate:"required"`
	Zonefile       string
	Type           string
	Store          string
	Primary        string // upstream, for secondary zones
	Notify         []string
	OptionsStrs    []string `yaml:"options" mapstructure:"options"`
	UpdatePolicy   UpdatePolicyConf
	DnssecPolicy   string `yaml:"dnssecpolicy" mapstructure:"dnssecpolicy"`
	MultiSigner    string `yaml:"multisigner" mapstructure:"multisigner"`
	PublishCadence string `yaml:"publish-cadence" mapstructure:"publish-cadence"`
}

type UpdatePolicyConf struct {
	Child struct {
		Type    string // selfsub | self | sub | none
		RRtypes []string
		TTL     uint32 `yaml:"ttl"`
	}
	Zone struct {
		Type    string // "selfsub" | "self" | "sub" | ...
		RRtypes []string
		TTL     uint32 `yaml:"ttl"`
	}
	Validate bool
}
type UpdatePolicy struct {
	Child    UpdatePolicyDetail
	Zone     UpdatePolicyDetail
	Validate bool
}

type UpdatePolicyDetail struct {
	Type    string // "selfsub" | "self"
	RRtypes map[uint16]bool
	TTL     uint32
}

// DnssecPolicyRolloverConf is the YAML `rollover:` subtree (KSK automated rollover; Phase 1+).
type DnssecPolicyRolloverConf struct {
	Method             string `yaml:"method" mapstructure:"method"`
	NumDS              int    `yaml:"num-ds" mapstructure:"num-ds"`
	ParentAgent        string `yaml:"parent-agent" mapstructure:"parent-agent"`
	ConfirmInitialWait string `yaml:"confirm-initial-wait" mapstructure:"confirm-initial-wait"`
	ConfirmPollMax     string `yaml:"confirm-poll-max" mapstructure:"confirm-poll-max"`
	ConfirmTimeout     string `yaml:"confirm-timeout" mapstructure:"confirm-timeout"`
	DsyncRequired      *bool  `yaml:"dsync-required" mapstructure:"dsync-required"`

	// Softfail state machine (rollover-overhaul). DsPublishDelay is
	// the primary new timing knob: parent's expected publication
	// cadence between "we sent UPDATE, got NOERROR" and "DS RRset
	// observable on the parent." Defaults derive from this for
	// healthy direct-publish parents (5m) up to batched registries
	// (1h, 24h). MaxAttemptsBeforeBackoff is the size of the initial
	// flurry; SoftfailDelay is the long-term-mode probe interval.
	DsPublishDelay           string `yaml:"ds-publish-delay" mapstructure:"ds-publish-delay"`
	MaxAttemptsBeforeBackoff int    `yaml:"max-attempts-before-backoff" mapstructure:"max-attempts-before-backoff"`
	SoftfailDelay            string `yaml:"softfail-delay" mapstructure:"softfail-delay"`

	// DsyncSchemePreference controls which DSYNC scheme(s) the rollover
	// engine attempts when pushing DS to the parent. Values:
	//   - "auto" (default): single advertised scheme is used; if the
	//     parent advertises both UPDATE and NOTIFY for CDS, both are
	//     dispatched in parallel and any wire-level NOERROR wins.
	//   - "prefer-update", "prefer-notify": single-scheme behavior on
	//     a both-advertising parent, falling through to the only
	//     advertised scheme on a one-advertising parent.
	//   - "force-update", "force-notify": only the named scheme is
	//     attempted; if the parent does not advertise it, the engine
	//     halts in child-config:waiting-for-parent until the parent
	//     starts advertising it.
	DsyncSchemePreference string `yaml:"dsync-scheme-preference" mapstructure:"dsync-scheme-preference"`

	// ParentCdsPollEstimate is an operator estimate of how long the
	// parent waits between "child published CDS at apex" and "parent's
	// DS RRset reflects the new CDS." Used by the E10 cache-flush
	// invariant check when NOTIFY is the only viable scheme: in that
	// case, parent_prop bundles a child-NOTIFY-to-parent-fetch hop on
	// top of the standard DS UPDATE timeline, so ds-publish-delay alone
	// understates the lead-time budget.
	//
	// Default 1m. Generalized NOTIFY exists to make parent CDS fetches
	// near-instant; parents that batch CDS polls should set a larger
	// value here.
	ParentCdsPollEstimate string `yaml:"parent-cds-poll-estimate" mapstructure:"parent-cds-poll-estimate"`

	// StandbyTime is the operator-configured pause between when a key
	// reaches the genuine "standby" state (propagation complete, ready
	// for AtomicRollover) and when the engine actually fires the
	// rollover. Default 1m. Production deployments may want 15m or
	// longer for operator observability — gives the operator a window
	// to abort the natural-cadence rollover if something looks wrong
	// post-publish.
	//
	// auto-rollover asap explicitly bypasses this pause: an operator
	// running asap is overriding the natural cadence, and the pause
	// is part of that natural cadence. asap fires AtomicRollover at
	// max(standby_at, now), not at standby_at + standby_time.
	StandbyTime string `yaml:"standby-time" mapstructure:"standby-time"`
}

// DnssecPolicyTtlsConf is the YAML `ttls:` subtree under a DNSSEC policy.
type DnssecPolicyTtlsConf struct {
	DNSKEY    string `yaml:"dnskey" mapstructure:"dnskey"`
	MaxServed string `yaml:"max-served" mapstructure:"max-served"`
	// ParentDS is an optional override for the parent's DS RRset TTL when
	// the engine cannot observe it (parent unreachable at zone init,
	// testbed determinism, registries that gate DS queries). Used by the
	// E10 cache-flush invariant check: (N − 1) × KSK.Lifetime ≥
	// retirement_period + parent_prop + DS_TTL. When unset, the engine
	// defers E10 validation until the first successful
	// QueryParentAgentDS observation supplies the live TTL.
	ParentDS string `yaml:"parent-ds" mapstructure:"parent-ds"`
	// DS is the fallback TTL for DS RRsets this zone publishes at its
	// children's secure delegations when the child has not expressed a
	// TTL (CDS / DNS UPDATE). Child-driven TTLs are never overridden.
	DS string `yaml:"ds" mapstructure:"ds"`
}

// DnssecPolicySigValidityConf is the YAML `sigvalidity:` subtree.
type DnssecPolicySigValidityConf struct {
	Default string `yaml:"default" mapstructure:"default"`
	Dnskey  string `yaml:"dnskey" mapstructure:"dnskey"`
	Ds      string `yaml:"ds" mapstructure:"ds"`
}

// DnssecPolicyClampingConf is the YAML `clamping:` subtree under a DNSSEC policy.
type DnssecPolicyClampingConf struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Margin  string `yaml:"margin" mapstructure:"margin"`
}

// DnssecPolicyConf should match the configuration
type DnssecPolicyConf struct {
	Name string
	// Template, if set, names an entry in dnssec.templates: whose fields are
	// deep-merged into this policy to fill any gaps (this policy's own values
	// win). Never copied from the template itself.
	Template  string `yaml:"template" mapstructure:"template"`
	Algorithm string
	Mode      string `yaml:"mode" mapstructure:"mode"`

	KSK struct {
		Lifetime  string
		Algorithm string `yaml:"algorithm" mapstructure:"algorithm"`
	}
	ZSK struct {
		Lifetime  string
		Algorithm string `yaml:"algorithm" mapstructure:"algorithm"`
	}
	CSK struct {
		Lifetime string
	}

	SigValidity DnssecPolicySigValidityConf `yaml:"sigvalidity" mapstructure:"sigvalidity"`

	Rollover DnssecPolicyRolloverConf `yaml:"rollover" mapstructure:"rollover"`
	Ttls     DnssecPolicyTtlsConf     `yaml:"ttls" mapstructure:"ttls"`
	Clamping DnssecPolicyClampingConf `yaml:"clamping" mapstructure:"clamping"`
}

type KeyLifetime struct {
	Lifetime uint32
}

// PolicySigValidity holds resolved RRSIG validity periods (seconds).
type PolicySigValidity struct {
	Default uint32
	DNSKEY  uint32
	DS      uint32
}

// DnssecPolicy is what is actually used; it is created from the corresponding DnssecPolicyConf
type DnssecPolicy struct {
	Name string

	// Error is empty for a healthy policy. When non-empty, the policy was
	// defined in config but rejected during parse (unknown algorithm, bad
	// lifetime, disallowed KSK/ZSK split, etc.) — the remaining fields may
	// be incomplete and the policy must not be used for signing. A broken
	// policy is still kept in Internal.DnssecPolicies (with Name + Error set)
	// so it is visible to the operator and so zones referencing it can be
	// quarantined with a clear reason.
	Error string

	Algorithm    uint8 // default / CSK algorithm
	KSKAlgorithm uint8
	ZSKAlgorithm uint8
	Mode         string

	KSK KeyLifetime
	ZSK KeyLifetime
	CSK KeyLifetime

	SigValidity PolicySigValidity

	Rollover RolloverPolicy
	TTLS     DnssecPolicyTTLS
	Clamping ClampingPolicy

	// suppressLoadWarnings is set by ParseDnssecPolicyConfQuiet so
	// CLI tools that re-parse a daemon's policy don't duplicate the
	// daemon's startup log lines. Internal flag — not serialized,
	// not part of the policy semantics.
	suppressLoadWarnings bool
}

// DnssecPolicyTTLS holds steady-state TTL hints from policy (seconds). Zero means unset.
type DnssecPolicyTTLS struct {
	DNSKEY uint32
	// MaxServed is a steady-state ceiling on the TTL of every RRset served
	// by this zone. When non-zero, SignRRset clamps Header().Ttl down to
	// min(operator_ttl, MaxServed) regardless of rollover proximity. Use
	// to enforce low TTLs on zones whose source data has high TTLs that
	// the operator can't directly edit (e.g. inbound zone transfers).
	// Zero means no ceiling. Validation: must be >= 60s when set.
	MaxServed uint32
	// ParentDS is the operator-provided override for the parent's DS RRset
	// TTL. Zero means "observe at runtime" — the engine queries the parent
	// agent and stores the observed TTL on zd.ParentDSTTLObserved. Used by
	// the E10 invariant check.
	ParentDS uint32
	// DS is the fallback TTL for child DS RRsets when the child has not
	// expressed a TTL. Zero means no fallback (TTL may remain 0 until set
	// elsewhere). Bounds sigvalidity.ds at config-load time.
	DS uint32
}

type Ixfr struct {
	FromSerial uint32
	ToSerial   uint32
	// FromSOA/ToSOA are the bracketing SOA RRs for this difference sequence,
	// stored as full RRs because SOA RDATA (timers/MNAME) may change between
	// serials — rewriting the current SOA's serial would not reproduce them.
	FromSOA *dns.SOA
	ToSOA   *dns.SOA
	Removed []core.RRset
	Added   []core.RRset
	// EstBytes is the estimated wire size of this link (RRs + bracket SOAs),
	// used for the byte-bounded chain trim.
	EstBytes int
}

type OwnerData struct {
	Name    string
	RRtypes *RRTypeStore

	// NSEC holds this owner's denial-of-existence record and its signature,
	// as a property rather than as an RRset inside RRtypes.
	//
	// It is derived data: the signer computes it from the shape of the zone,
	// and nothing outside the signer may author it. RRSIGs are already held
	// this way -- as a field on the RRset they cover -- and the placement is
	// what keeps two whole classes of bug unrepresentable:
	//
	//   - a name whose last real RRset is deleted has nothing left in RRtypes,
	//     so it stops existing, instead of lingering for ever with only its own
	//     NSEC to keep it alive and the chain asserting that it exists;
	//
	//   - the delta journal flattens rrset.RRs from the owner's RRtypes, so a
	//     regenerated NSEC cannot be recorded there as though an operator had
	//     written it, and cannot then be replayed or reported as a conflict
	//     against a zone file.
	//
	// It is emitted to the wire like any other record: zone file, AXFR, IXFR
	// and the ZONEMD digest all include it. See
	// docs/2026-08-22-nsec-chain-correctness.md §3.
	NSEC core.RRset
}

type ChildDelegationData struct {
	DelHasChanged    bool      // When returned from a scanner, this indicates that a change has been detected
	ParentSerial     uint32    // The parent serial that this data was correct for
	Timestamp        time.Time // Time at which this data was fetched
	ChildName        string
	RRsets           map[string]map[uint16]core.RRset // map[ownername]map[rrtype]RRset
	NS_rrs           []dns.RR
	A_glue           []dns.RR
	A_glue_rrsigs    []dns.RR
	AAAA_glue        []dns.RR
	AAAA_glue_rrsigs []dns.RR
	NS_rrset         *core.RRset
	DS_rrset         *core.RRset
	A_rrsets         []*core.RRset
	AAAA_rrsets      []*core.RRset
}

type DelegationSyncStatus struct {
	ZoneName      string
	Parent        string // use zd.Parent instead
	Time          time.Time
	InSync        bool
	Status        string
	Msg           string
	Rcode         uint8
	Adds          []dns.RR `json:"-"`
	Removes       []dns.RR `json:"-"`
	NsAdds        []dns.RR `json:"-"`
	NsRemoves     []dns.RR `json:"-"`
	AAdds         []dns.RR `json:"-"`
	ARemoves      []dns.RR `json:"-"`
	AAAAAdds      []dns.RR `json:"-"`
	AAAARemoves   []dns.RR `json:"-"`
	DNSKEYAdds    []dns.RR `json:"-"`
	DNSKEYRemoves []dns.RR `json:"-"`
	DSAdds        []dns.RR `json:"-"`
	DSRemoves     []dns.RR `json:"-"`
	// NewDSKnown reports whether NewDS is an answer. An empty NewDS means
	// "withdraw the DS" when this is set and "no opinion about DS" when it is
	// not; the two are opposite instructions that look identical as a nil
	// slice, so the flag travels with the field and must be read first.
	NewDSKnown   bool `json:"-"`
	Error        bool
	ErrorMsg     string
	UpdateResult UpdateResult // Experimental
	// Complete new delegation data for replace mode
	NewNS   []dns.RR `json:"-"`
	NewA    []dns.RR `json:"-"`
	NewAAAA []dns.RR `json:"-"`
	NewDS   []dns.RR `json:"-"`
	// String representations for JSON serialization (populated by ToStrings())
	NsAddsStr      []string `json:"NsAdds,omitempty"`
	NsRemovesStr   []string `json:"NsRemoves,omitempty"`
	AAddsStr       []string `json:"AAdds,omitempty"`
	ARemovesStr    []string `json:"ARemoves,omitempty"`
	AAAAAddsStr    []string `json:"AAAAAdds,omitempty"`
	AAAARemovesStr []string `json:"AAAARemoves,omitempty"`
	DSAddsStr      []string `json:"DSAdds,omitempty"`
	DSRemovesStr   []string `json:"DSRemoves,omitempty"`
}

func (dss *DelegationSyncStatus) ToStrings() {
	dss.NsAddsStr = rrsToStrings(dss.NsAdds)
	dss.NsRemovesStr = rrsToStrings(dss.NsRemoves)
	dss.AAddsStr = rrsToStrings(dss.AAdds)
	dss.ARemovesStr = rrsToStrings(dss.ARemoves)
	dss.AAAAAddsStr = rrsToStrings(dss.AAAAAdds)
	dss.AAAARemovesStr = rrsToStrings(dss.AAAARemoves)
	dss.DSAddsStr = rrsToStrings(dss.DSAdds)
	dss.DSRemovesStr = rrsToStrings(dss.DSRemoves)
}

func rrsToStrings(rrs []dns.RR) []string {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]string, len(rrs))
	for i, rr := range rrs {
		out[i] = rr.String()
	}
	return out
}

// UpstreamSerial is one primary's answer to a live SOA probe, for `zone desc`.
// Err carries the probe failure (unreachable, REFUSED, TSIG mismatch, ...) so a
// primary that cannot be reached is shown as such rather than silently omitted
// — an unreachable master is itself diagnostic.
type UpstreamSerial struct {
	Addr   string
	Serial uint32
	Err    string
}

type ZoneRefresher struct {
	Name           string
	ZoneType       ZoneType   // primary | secondary
	PrimariesConf  []PeerConf // as-written; copied to zd.PrimariesConf on merge
	Primaries      []PeerConf // resolved; copied to zd.Upstreams on merge
	Notify         []PeerConf
	AllowNotify    []AclEntry // copied to zd.AllowNotify on merge
	Downstreams    []AclEntry // copied to zd.Downstreams on merge
	DownstreamAuth []string   // copied to zd.DownstreamAuth on merge (config-bearing only)
	// ConfigUpdate marks a config-bearing refresher (from ParseZones /
	// LoadDynamicZoneFiles) as opposed to a NOTIFY/refresh-only trigger. On reload
	// it lets the merge assign Notify/AllowNotify/Downstreams even when they are
	// nil/empty, so a config that REMOVES an ACL actually clears it (empty
	// downstreams => deny, empty allow-notify => primaries) instead of keeping
	// stale permissions.
	ConfigUpdate bool
	ZoneStore    ZoneStore // 1=xfr, 2=map
	Zonefile     string
	// Template propagates the config-template name of a dynamic zone to the
	// ZoneData built by the RefreshEngine (copied to zd.Template), so a later
	// persist re-serializes it. Empty for template-less zones.
	Template string
	// PublishCadence, when non-zero, sets the zone's minimum snapshot publish
	// interval (zd.publishCadence). Carried parsed so the RefreshEngine does
	// not re-parse; zero means "leave the zone's default".
	PublishCadence   time.Duration
	Options          map[ZoneOption]bool
	Edns0Options     *edns0.MsgOptions
	UpdatePolicy     UpdatePolicy
	DelegationPolicy *DelegationPolicy
	DnssecPolicy     string
	// OutboundSoaSerial carries the per-zone outbound serial mode to the
	// RefreshEngine (copied to zd.OutboundSoaSerial on merge). Empty means
	// "inherit the server-global setting" and is a valid, self-consistent
	// value, so it is always copied — no "only if non-empty" guard.
	OutboundSoaSerial string
	// TransferSrc carries the per-zone outbound-transfer source to the
	// RefreshEngine (copied to zd.TransferSrc on merge). Empty inherits.
	TransferSrc []string
	MultiSigner string
	Force       bool // force refresh, ignoring SOA serial
	Wait        bool // wait for refresh to complete before responding
	Response    chan RefresherResponse
}

type RefresherResponse struct {
	Time     time.Time
	Zone     string
	Msg      string
	Error    bool
	ErrorMsg string
}

type ValidatorRequest struct {
	Qname    string
	RRset    *core.RRset
	Response chan ValidatorResponse
}

type ValidatorResponse struct {
	Validated bool
	Msg       string
}

type Sig0StoreT struct {
	Map *core.ConcurrentMap[string, Sig0Key]
}

type Sig0Key struct {
	Name            string
	State           string
	Keyid           uint16
	Algorithm       string
	Creator         string
	Validated       bool   // has this key been validated
	PublishedInDNS  bool   // is this key published in DNS (as a KEY RR)
	DnssecValidated bool   // has this key been DNSSEC validated
	Trusted         bool   // is this key trusted
	Source          string // "dns" | "file" | "keystore" | "child-update"
	PrivateKey      string //
	Key             dns.KEY
	Keystr          string
	// ValidationFailed: the parent's automatic verification of this child key
	// ran out of attempts (TriggerChildKeyVerification). Distinct from
	// !Validated, which also covers "verification in progress". Reported as
	// KEY_VALIDATION_FAILED(8) / EDE KEY-VALIDATION-FAILED; ValidationError
	// carries the last reason for the operator and the KeyState EXTRA-TEXT.
	ValidationFailed bool
	ValidationError  string
}

type DnssecKey struct {
	Name                   string
	State                  string
	Keyid                  uint16
	Flags                  uint16
	Algorithm              string
	Creator                string
	PrivateKey             string //
	Key                    dns.DNSKEY
	Keystr                 string
	PropagationConfirmed   bool      // True when all remote providers confirmed this key
	PropagationConfirmedAt time.Time // When propagation was confirmed (zero if not confirmed)
}

type DelegationSyncRequest struct {
	Command      string
	ZoneName     string
	ZoneData     *ZoneData
	SyncStatus   DelegationSyncStatus
	OldDnskeys   *core.RRset
	NewDnskeys   *core.RRset
	MsignerGroup *core.RRset
	Response     chan DelegationSyncStatus // used for API-based requests
	// Attempt counts re-enqueues of a DELEGATION-SYNC-SETUP whose SIG(0)
	// bootstrap was deferred because the parent's SVCB advertisement could not
	// be looked up (errBootstrapAdvertisementLookup). Zero on the first try.
	Attempt int
	// ProxyAnalysis is set for the PROXY-NOTIFY command: the changed-dimension
	// set the proxy NOTIFY action keys on (delegation-sync-proxy).
	ProxyAnalysis *ProxyDelegationAnalysis
}

type BumperData struct {
	Zone   string
	Result chan BumperResponse
}

type BumperResponse struct {
	Time      time.Time
	Zone      string
	Msg       string
	OldSerial uint32
	NewSerial uint32
	Error     bool
	ErrorMsg  string
	Status    bool
}

// A Signer is a struct where we keep track of the signer name and keyid
// for a DNS UPDATE message.
type Sig0UpdateSigner struct {
	Name  string // from the SIG
	KeyId uint16 // from the SIG
	// Sig is the specific *dns.SIG RR this signer was discovered
	// from. Verification must use this signature, not whatever was
	// last parsed in the outer loop — multi-signature UPDATEs would
	// otherwise classify against the wrong SIG.
	Sig       *dns.SIG
	Sig0Key   *Sig0Key // a key that matches the signer name and keyid
	Validated bool     // true if this key validated the update
}

// The UpdateStatus is used to track the evolving status of
// a received DNS UPDATE as it passes through the validation
// and approval processes.

type UpdateStatus struct {
	Zone                  string             // zone that the update applies to
	ChildZone             string             // zone that the update applies to
	Type                  string             // auth | child
	Data                  string             // auth | delegation | key
	ValidatorKey          *Sig0Key           // key that validated the update
	Signers               []Sig0UpdateSigner // possible validators
	SignerName            string             // name of the key that signed the update
	SignatureType         string             // by-trusted | by-known | self-signed
	ValidationRcode       uint8              // Rcode from the validation process
	Validated             bool               // true if the update has passed validation
	ValidatedByTrustedKey bool               // true if the update has passed validation by a trusted key
	SafetyChecked         bool               // true if the update has been safety checked
	PolicyChecked         bool               // true if the update has been policy checked
	Approved              bool               // true if the update has been approved
	// RejectionEDE is the specific EDE code that describes why the
	// update was rejected, set by ApproveUpdate (or by ValidateUpdate
	// for the validation-failure paths). The responder reads this
	// when constructing the wire response and attaches the EDE so the
	// child operator can diagnose without parent-side log access.
	// Zero means "no specific reason recorded."
	RejectionEDE uint16
	Msg          string
	Error        bool
	ErrorMsg     string
	Status       bool
}

type NotifyStatus struct {
	Zone          string // zone that the update applies to
	ChildZone     string // zone that the update applies to
	Type          uint16 // CDS | CSYNC | DNSKEY | DELEG
	ScanStatus    string // "ok" | "changed" | "failed"
	SafetyChecked bool   // true if the update has been safety checked
	PolicyChecked bool   // true if the update has been policy checked
	Approved      bool   // true if the update has been approved
	Msg           string
	Error         bool
	ErrorMsg      string
	Status        bool
}

// Migrating all DB access to own interface to be able to have local receiver functions.
type PrivateKeyCache struct {
	// K, CS and RR are interfaces and MUST NOT cross the API boundary.
	//
	// json.Marshal writes an ed25519.PrivateKey (a []byte) as a base64
	// string; on the way back in, that string decodes happily into the
	// empty interface crypto.PrivateKey but FAILS against the non-empty
	// crypto.Signer, aborting the decode partway through. The server used
	// to log that error and carry on, leaving K holding a plain string —
	// which then reached x509.MarshalPKCS8PrivateKey and produced the
	// misleading "pkcs8: codec does not support this key/OID".
	//
	// The wire form carries PrivateKey (base64) + DnskeyRR/KeyRR, which is
	// everything the server needs to rebuild the key locally.
	K crypto.PrivateKey `json:"-"`
	// PrivateKey is the BIND single-field base64. Kept for existing callers,
	// but do NOT rely on it across the API: it is empty for RSA, whose BIND
	// format has eight fields and no "PrivateKey:" line. Use PrivateKeyPEM.
	PrivateKey string
	// PrivateKeyPEM is the PKCS#8 PEM encoding and is what the server rebuilds
	// the key from. Algorithm-agnostic: works for RSA, ECDSA, Ed25519 and the
	// registered PQ algorithms alike.
	PrivateKeyPEM string
	CS            crypto.Signer `json:"-"`
	RR            dns.RR        `json:"-"`
	KeyType       uint16
	Algorithm     uint8
	KeyId         uint16
	KeyRR         dns.KEY
	DnskeyRR      dns.DNSKEY
}

type Sig0ActiveKeys struct {
	Keys []*PrivateKeyCache
}

type DnssecKeys struct {
	KSKs []*PrivateKeyCache
	ZSKs []*PrivateKeyCache
}

type KeyDB struct {
	DB     *sql.DB
	DBFile string // sqlite file path, recorded by NewKeyDB
	mu     sync.Mutex
	// Sig0Cache   map[string]*Sig0KeyCache
	KeystoreSig0Cache   map[string]*Sig0ActiveKeys
	TruststoreSig0Cache *Sig0StoreT // was *Sig0StoreT
	Ctx                 string
	UpdateQ             chan UpdateRequest
	// options holds the parsed DnsEngine auth options. It is read on the hot
	// query path (QueryResponder, per request) and replaced wholesale on config
	// reload, so it is stored behind an atomic.Pointer for lock-free reads and a
	// race-free swap. Access via AuthOption()/SetOptions(), never directly.
	options atomic.Pointer[map[AuthOption]string]
	// outboundSoaSerial is the resolved mode for outbound SOA serials:
	// OutboundSoaSerialKeep / OutboundSoaSerialUnixtime / OutboundSoaSerialPersist.
	// Sourced from DnsEngineConf.OutboundSoaSerial at parse, defaulted to
	// OutboundSoaSerialKeep if unset.
	//
	// Behind an atomic.Pointer for the same reason as options above: written
	// wholesale by config reload, read from zone-serving goroutines. Access via
	// OutboundSoaSerialMode()/SetOutboundSoaSerial(), never directly.
	outboundSoaSerial atomic.Pointer[string]
	// transferSrc is the server-global source address list for outbound zone
	// transfers (authengine.transfer-src). Per-zone ZoneData.TransferSrc wins;
	// see zd.EffectiveTransferSrc(). Same reload-vs-read exposure as the two
	// above; access via TransferSrcList()/SetTransferSrc().
	transferSrc atomic.Pointer[[]string]
}

// SetOutboundSoaSerial replaces the server-global outbound serial mode. Called
// at parse and on every config reload.
func (kdb *KeyDB) SetOutboundSoaSerial(mode string) {
	m := mode
	kdb.outboundSoaSerial.Store(&m)
}

// OutboundSoaSerialMode returns the server-global outbound serial mode, or ""
// if none has been set.
func (kdb *KeyDB) OutboundSoaSerialMode() string {
	if m := kdb.outboundSoaSerial.Load(); m != nil {
		return *m
	}
	return ""
}

// SetTransferSrc replaces the server-global outbound-transfer source list.
// Stores a copy, so a caller that later mutates the slice it passed cannot
// change what serving goroutines observe.
func (kdb *KeyDB) SetTransferSrc(srcs []string) {
	cp := append([]string(nil), srcs...)
	kdb.transferSrc.Store(&cp)
}

// TransferSrcList returns the server-global outbound-transfer source list.
// Returns a copy: the caller receives a stable snapshot that a concurrent
// reload cannot mutate underneath it.
func (kdb *KeyDB) TransferSrcList() []string {
	s := kdb.transferSrc.Load()
	if s == nil || len(*s) == 0 {
		return nil
	}
	return append([]string(nil), (*s)...)
}

// Lock and Unlock expose the mutex for code that moves to
// tdns-mp and can no longer access the unexported kdb.mu.
func (kdb *KeyDB) Lock()   { kdb.mu.Lock() }
func (kdb *KeyDB) Unlock() { kdb.mu.Unlock() }

// SetOptions replaces the auth-option map atomically (config reload). It stores
// a private COPY of opts, not the caller's map, so the stored map can never be
// mutated out from under a concurrent lock-free reader even if the caller later
// changes its own map. A nil map yields an empty one so readers never observe a
// nil dereference.
func (kdb *KeyDB) SetOptions(opts map[AuthOption]string) {
	cp := make(map[AuthOption]string, len(opts))
	for k, v := range opts {
		cp[k] = v
	}
	kdb.options.Store(&cp)
}

// AuthOption returns the value for an auth option and whether it is set, reading
// the current option map without a lock.
func (kdb *KeyDB) AuthOption(key AuthOption) (string, bool) {
	m := kdb.options.Load()
	if m == nil {
		return "", false
	}
	v, ok := (*m)[key]
	return v, ok
}

type Tx struct {
	*sql.Tx
	KeyDB   *KeyDB
	context string
}

// String-based versions of RRset for JSON marshaling
type RRsetString struct {
	Name   string   `json:"name"`
	RRtype uint16   `json:"rrtype"`
	RRs    []string `json:"rrs"`
	RRSIGs []string `json:"rrsigs,omitempty"`
}

type KeyConf struct {
	Tsig []TsigDetails `yaml:"tsig" mapstructure:"tsig"`
}
type TsigDetails struct {
	Name      string `validate:"required" yaml:"name"`
	Algorithm string `validate:"required" yaml:"algorithm"`
	Secret    string `validate:"required" yaml:"secret"`
	Owner     string `yaml:"owner,omitempty"`
}

type ZoneName string

type AgentId string

func (id AgentId) String() string {
	return string(id)
}

// AgentMgmt{Post,Response} are used in the mgmt API
type AgentMgmtPost struct {
	Command    string   `json:"command"`
	Zone       ZoneName `json:"zone"`
	AgentId    AgentId  `json:"agent_id"`
	RRType     uint16
	RR         string
	RRs        []string
	AddedRRs   []string // for update-local-zonedata
	RemovedRRs []string // for update-local-zonedata
	Upstream   AgentId
	Downstream AgentId
	Data       map[string]interface{} `json:"data,omitempty"` // Generic data field for custom parameters
	Response   chan *AgentMgmtResponse
}

type AgentMgmtResponse struct {
	Identity AgentId
	Status   string
	Time     time.Time
	Msg      string
	Error    bool
	ErrorMsg string
	Data     interface{} `json:"data,omitempty"` // Generic data field for custom responses
}

// ImrMgmtPost is a management request to a daemon's /imr endpoint (tdns-imr, or
// an agent/auth hosting an in-process IMR). Dedicated to the IMR mgmt API — it
// deliberately does NOT reuse AgentMgmtPost, whose agent/RR fields are unrelated
// to IMR operations and whose overloading here would be a future footgun.
type ImrMgmtPost struct {
	Command  string                 `json:"command"`
	Zone     ZoneName               `json:"zone,omitempty"`
	Id       string                 `json:"id,omitempty"`   // e.g. imr-show: cache identity to show
	Data     map[string]interface{} `json:"data,omitempty"` // command-specific parameters
	Response chan *ImrMgmtResponse  `json:"-"`
}

// ImrMgmtResponse is the response from a daemon's /imr endpoint.
type ImrMgmtResponse struct {
	Status   string
	Time     time.Time
	Msg      string
	Error    bool
	ErrorMsg string
	Data     interface{} `json:"data,omitempty"` // command-specific response payload
}

// DnskeyStatus holds the result of DNSKEY change detection (local keys only).
// 20260415 johani: somewhat unclear if we still need this.
type DnskeyStatus struct {
	Time             time.Time
	ZoneName         string
	LocalAdds        []dns.RR // Local DNSKEYs added since last check
	LocalRemoves     []dns.RR // Local DNSKEYs removed since last check
	CurrentLocalKeys []dns.RR // Complete current set of local DNSKEYs (for replace operations)
}
