/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strings"
	"sync/atomic"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The childsync: and parentsync: blocks, typed, plus the fold that still
// accepts the retired `delegationsync:` wrapper they were hoisted out of.
//
// childsync: is what a PARENT offers its children -- the DSYNC RRset, the
// schemes behind it, the UPDATE receiver's key, and the named delegation
// policies. parentsync: is what a CHILD does towards its parent. Each is named
// for the zone option that switches it on.
//
// These were read with viper.GetString/GetStringSlice from a dozen call sites.
// They are now modelled in full and these structs are the ONLY reader, with one
// deliberate exception: the parentsync keygen MODE is still read from viper in
// sig0_utils.go and is intentionally NOT modelled here -- the sample config says
// "`algorithm` and `generator` are read on the child side; `mode` is not", and
// modelling it would turn a setting that has never had any effect into a live one.
//
// Why it was unwound: viper splits keys on ".". Any config shape with a dotted
// key silently arrives empty, the setting reads back as its zero value, and
// nothing logs a thing. Zone names are dotted, so a per-zone setting under these
// blocks was unreadable through viper and gave no sign of it.
//
// Keep them complete. A subtree modelled here while its readers still call viper
// is worse than one that is honestly absent, because the field looks
// authoritative and returns a zero value; add the fields and move the readers
// in the same change.
// DeprecatedDelegationSyncConf is the retired `delegationsync:` block.
//
// It wrapped three things -- `parent:`, `child:` and `policies:` -- under a
// level that said nothing the members did not. Worse, `parent:` and `child:`
// were each named after the FAR END of the relationship they configure:
// `delegationsync.parent` is what a CHILDSYNC zone publishes to its children.
// The two blocks are now top-level `childsync:` and `parentsync:`, matching the
// zone options, and the policies live at `childsync.policies:` because every
// consumer of a bound policy is childsync-side.
//
// Pointers so "absent" and "present but empty" stay distinguishable: folding an
// empty block over a populated canonical one would silently erase it.
// foldDeprecatedKeys moves them into place and clears the block, so nothing
// downstream ever sees a non-nil one. Remove this type, the Config field, the
// fold and the hasContent helpers together when the deprecation cycle ends.
type DeprecatedDelegationSyncConf struct {
	Parent   *ChildSyncConf                  `yaml:"parent" mapstructure:"parent"`
	Child    *ParentSyncConf                 `yaml:"child" mapstructure:"child"`
	Policies map[string]DelegationPolicyConf `yaml:"policies" mapstructure:"policies"`
}

// foldDeprecatedDelegationSync moves a `delegationsync:` block onto the
// top-level childsync:/parentsync: fields and clears it, so every reader sees
// one shape and a second call is a no-op.
//
// Setting a member in both places is an ERROR, not a precedence rule. It means
// a half-finished migration, and picking a winner silently would leave the
// operator reading one block while the server obeys the other -- the exact
// failure mode the rename exists to end. Moving the blocks but not yet the
// policies is NOT that: it is a coherent half-step, so it folds with a warning.
//
// Returns the deprecation warnings for the caller to log: a config-parsing
// helper has no business choosing a logger.
func (conf *Config) foldDeprecatedDelegationSync() ([]string, error) {
	ds := conf.DeprecatedDelegationSync
	if ds == nil {
		return nil, nil
	}
	var warnings []string
	if ds.Parent != nil {
		if conf.ChildSync.hasContent() {
			return nil, fmt.Errorf("both the top-level `childsync:` and the deprecated `delegationsync.parent:` are set; keep only `childsync:`")
		}
		conf.ChildSync = *ds.Parent
		warnings = append(warnings, "delegationsync.parent: is deprecated, move it to the top-level childsync: (it configures what a childsync zone offers its children)")
	}
	if ds.Child != nil {
		if conf.ParentSync.hasContent() {
			return nil, fmt.Errorf("both the top-level `parentsync:` and the deprecated `delegationsync.child:` are set; keep only `parentsync:`")
		}
		conf.ParentSync = *ds.Child
		warnings = append(warnings, "delegationsync.child: is deprecated, move it to the top-level parentsync: (it configures what a parentsync zone does towards its parent)")
	}
	if len(ds.Policies) > 0 {
		if len(conf.ChildSync.Policies) > 0 {
			return nil, fmt.Errorf("both `childsync.policies:` and the deprecated `delegationsync.policies:` are set; keep only `childsync.policies:`")
		}
		conf.ChildSync.Policies = ds.Policies
		warnings = append(warnings, "delegationsync.policies: is deprecated, move it to childsync.policies: (a delegation policy governs what a childsync zone advertises and accepts)")
	}
	conf.DeprecatedDelegationSync = nil
	return warnings, nil
}

// FoldDeprecatedDelegationSync folds the retired `delegationsync:` block and
// logs the warnings. Every config-decode path calls this; the fold is
// idempotent, so a path reached twice costs nothing.
func (conf *Config) FoldDeprecatedDelegationSync() error {
	warnings, err := conf.foldDeprecatedDelegationSync()
	if err != nil {
		return err
	}
	for _, w := range warnings {
		lgConfig.Warn(w)
	}
	return nil
}

// hasContent reports whether an operator wrote anything into the block. Used
// only to catch a config that sets both the canonical and the deprecated
// spelling; a zero block is indistinguishable from an absent one, which is
// exactly the case where folding is safe.
func (c ChildSyncConf) hasContent() bool {
	return len(c.Schemes) > 0 ||
		c.Notify.Target != "" || c.Notify.Port != 0 || len(c.Notify.Types) > 0 || len(c.Notify.Addresses) > 0 ||
		c.Update.Target != "" || c.Update.Port != 0 || len(c.Update.Types) > 0 || len(c.Update.Addresses) > 0 ||
		c.Update.Keygen != DsyncKeygenConf{} ||
		c.Api.Target != "" || c.Api.Port != 0 || len(c.Api.Listen) > 0 ||
		len(c.Policies) > 0
}

func (c ParentSyncConf) hasContent() bool {
	return len(c.Schemes) > 0 ||
		len(c.Update.Bootstrap.Methods) > 0 || c.Update.Keygen != DsyncKeygenConf{} || c.Update.AllowInsecure ||
		len(c.Api.Credentials) > 0 || c.Api.AllowInsecure
}

type ChildSyncConf struct {
	// Schemes we are willing to offer children, and therefore publish DSYNC
	// records for: notify, update, api.
	Schemes []string           `yaml:"schemes" mapstructure:"schemes"`
	Notify  DsyncDnsSchemeConf `yaml:"notify" mapstructure:"notify"`
	// Update is the UPDATE scheme's DSYNC keys plus the keygen subtree that
	// hangs off the same YAML node, which is why it is not a plain
	// DsyncDnsSchemeConf like Notify. Embedding keeps Parent.Update.Target and
	// friends reading exactly as before. Bootstrap policy is not here: it lives
	// in named childsync.policies.* and is referenced per-zone.
	Update DsyncUpdateSchemeConf `yaml:"update" mapstructure:"update"`
	Api    DsyncApiSchemeConf    `yaml:"api" mapstructure:"api"`

	// Policies are the named delegation policies, referenced per-zone with
	// `delegationpolicy: <name>`. They live here, not at the top level,
	// because every consumer of a bound policy is childsync-side: the SVCB
	// bootstrap advertisement a childsync zone publishes, and what it accepts
	// from a child (ApproveChildUpdate, ApproveTrustUpdate, SIG(0) validation).
	// A child that needs its parent's policy reads it off the parent zone.
	Policies map[string]DelegationPolicyConf `yaml:"policies" mapstructure:"policies"`
	// CompiledPolicies is derived, never decoded: SetDelegationSyncConfig fills
	// it from Policies.
	CompiledPolicies map[string]DelegationPolicy `yaml:"-" mapstructure:"-"`
}

type ParentSyncConf struct {
	// Schemes we are willing to use against a parent, in preference order.
	Schemes []string             `yaml:"schemes" mapstructure:"schemes"`
	Api     ParentSyncApiConf    `yaml:"api" mapstructure:"api"`
	Update  ParentSyncUpdateConf `yaml:"update" mapstructure:"update"`

	// CompiledMethods is derived from Update.Bootstrap.Methods, never decoded.
	CompiledMethods []string `yaml:"-" mapstructure:"-"`
}

// ParentSyncUpdateConf is the child side of the UPDATE scheme: keygen, plus
// bootstrap.methods (intersected with the parent SVCB advertisement at
// bootstrap time). The DSYNC keys themselves are the parent's to publish.
type ParentSyncUpdateConf struct {
	Keygen    DsyncKeygenConf `yaml:"keygen" mapstructure:"keygen"`
	Bootstrap struct {
		Methods []string `yaml:"methods" mapstructure:"methods"`
	} `yaml:"bootstrap" mapstructure:"bootstrap"`

	// AllowInsecure permits acting on parent-derived input that cannot be
	// authenticated: a KeyState response that is unsigned or signed with a
	// receiver KEY that is neither DNSSEC-validated (together with the DSYNC
	// lookup that named it) nor manually trusted in the truststore, and an
	// SVCB bootstrap advertisement discovered without DNSSEC validation. It
	// is the draft's "subject to local policy" escape for an unsigned parent
	// zone with no manually bootstrapped receiver key (ddns-02 §"Authenticating
	// Responses"), and mirrors ParentSyncApiConf.AllowInsecure: one switch,
	// because the two inputs are the same protection seen from two sides.
	//
	// It does NOT make a wrong signature acceptable: a response whose SIG(0)
	// is present but fails to verify is rejected regardless. A lab
	// convenience. Never a production setting.
	AllowInsecure bool `yaml:"allow-insecure" mapstructure:"allow-insecure"`
}

// DsyncUpdateSchemeConf is the parent's UPDATE scheme: the DSYNC record keys
// plus the keygen settings. How an uploaded SIG(0) key is verified is the
// zone's bound delegationpolicy, not a sibling of this block.
type DsyncUpdateSchemeConf struct {
	// Squash, spelled in the YAML tag because the decoder runs with
	// TagName: "yaml" -- so mapstructure reads THIS tag, and `yaml:",inline"`
	// (the yaml package's spelling) means nothing to it and silently drops
	// every embedded field. The mapstructure tag is kept for any decoder that
	// uses the conventional tag name.
	DsyncDnsSchemeConf `yaml:",squash" mapstructure:",squash"`

	Keygen DsyncKeygenConf `yaml:"keygen" mapstructure:"keygen"`
}

// DsyncKeygenConf: how a SIG(0) keypair is produced for delegation sync.
type DsyncKeygenConf struct {
	Algorithm string `yaml:"algorithm" mapstructure:"algorithm"`
	Generator string `yaml:"generator" mapstructure:"generator"`
}

// ParentSyncApiConf is what a child needs to use the API scheme against its
// parents: one credential per parent, obtained out of band.
type ParentSyncApiConf struct {
	// A LIST, not a map keyed by parent name. viper splits keys on ".", so a
	// map keyed "example." would arrive keyed "example" with every setting
	// beneath it somewhere the struct cannot see -- and the credential would
	// read back empty with nothing logged anywhere. Same reason the labstuff
	// parentupdater config is a list.
	Credentials []ParentSyncApiCredentialConf `yaml:"credentials" mapstructure:"credentials"`

	// CaFile is an additional CA bundle to trust for DSYNC API endpoints, on
	// top of the system roots.
	//
	// This is NOT a way to weaken verification: certificates are still fully
	// validated, against a larger set of roots. It exists because the natural
	// deployment is a private trust domain -- `tdns-cli cert ca` mints exactly
	// such a CA -- and the alternative would be installing that CA into the
	// host's system trust store, which grants it authority over every TLS
	// connection the host makes rather than just these.
	CaFile string `yaml:"cafile" mapstructure:"cafile"`

	// AllowInsecure permits a plain-http endpoint AND an endpoint discovered
	// without DNSSEC validation. Deliberately one switch for both: they are
	// the same protection seen from two sides, and an operator who turns off
	// one while believing the other still holds has no protection at all.
	//
	// It does NOT disable certificate validation -- use CaFile for a private
	// CA. There is no switch for turning verification off, because a
	// credential sent to an unverified endpoint is a credential given away.
	// A lab convenience. Never a production setting.
	AllowInsecure bool `yaml:"allow-insecure" mapstructure:"allow-insecure"`
}

type ParentSyncApiCredentialConf struct {
	Parent string `yaml:"parent" mapstructure:"parent"`

	// Child names the child zone this credential is for. OPTIONAL, and empty
	// in every config written before delegation-sync-proxy existed.
	//
	// A tdns-auth child is itself the child zone, so the parent alone
	// identifies the relationship and this stays empty. A tdns-agent running
	// delegation-sync-proxy can be secondary for SEVERAL child zones under one
	// parent, each with its own username and key at that parent -- and parent
	// alone can no longer say which. Naming the child here is how the second
	// and subsequent ones are expressed.
	//
	// An entry naming a child matches only that child. An entry with no child
	// matches any child under that parent, which is what keeps existing
	// single-child configs working untouched.
	Child string `yaml:"child" mapstructure:"child"`

	Username string          `yaml:"username" mapstructure:"username"`
	Key      SensitiveString `yaml:"key" mapstructure:"key"`

	// TLS is the client-certificate alternative to Username/Key. A pointer so
	// that "the operator wrote no tls block" and "the operator wrote an empty
	// one" are distinguishable -- the second is a config error worth naming,
	// the first is every config written before this existed.
	TLS *ParentSyncApiTLSConf `yaml:"tls" mapstructure:"tls"`
}

// ParentSyncApiTLSConf is one client keypair. Both paths, no secrets: the
// private key stays in its file and is never read into the config.
type ParentSyncApiTLSConf struct {
	CertFile string `yaml:"cert" mapstructure:"cert"`
	KeyFile  string `yaml:"key" mapstructure:"key"`
}

// Validate rejects a half-written block early, where the error can name the
// field, rather than at first use where it surfaces as a TLS handshake failure
// against the parent.
func (t *ParentSyncApiTLSConf) Validate() error {
	if t == nil {
		return nil
	}
	if strings.TrimSpace(t.CertFile) == "" || strings.TrimSpace(t.KeyFile) == "" {
		return fmt.Errorf("parentsync.api.credentials[].tls needs both cert and key")
	}
	return nil
}

// Validate rejects a credential entry that cannot authenticate: both a bearer
// pair and a tls block (ambiguous; the Authorization header would win and the
// certificate would be ignored), or a tls block that is only half written.
func (cc ParentSyncApiCredentialConf) Validate() error {
	if err := cc.TLS.Validate(); err != nil {
		return err
	}
	if cc.TLS != nil && (strings.TrimSpace(cc.Username) != "" || cc.Key.Value() != "") {
		return fmt.Errorf("parentsync.api.credentials[] cannot carry both a bearer credential and a tls block")
	}
	return nil
}

// ValidateCredentials checks every child credential entry.
func (c ParentSyncApiConf) ValidateCredentials() error {
	for i, cc := range c.Credentials {
		if err := cc.Validate(); err != nil {
			return fmt.Errorf("parentsync.api.credentials[%d]: %v", i, err)
		}
	}
	return nil
}

// CredentialFor returns the credential for a parent zone, matching as FQDNs so
// a config written with or without the trailing dot works either way.
//
// Kept for callers that have no child to offer. Prefer CredentialForChild:
// this one cannot see a child-specific entry, so on a host that proxies
// several children under one parent it returns whichever generic entry exists
// -- or nothing, if every entry names a child.
func (c ParentSyncApiConf) CredentialFor(parent string) (DsyncApiClientCredential, bool) {
	return c.CredentialForChild(parent, "")
}

// CredentialForChild returns the credential for a (parent, child) pair.
//
// Most specific wins: an entry naming this child is preferred over a generic
// entry for the parent. The generic entry is the fallback rather than an
// error, because it is what every pre-existing config looks like and the
// single-child case has no ambiguity to resolve.
//
// The alternative -- matching on username == child -- was rejected: §6.2 keeps
// principal and username deliberately distinct, so the parent does not require
// them to be equal and neither should this.
func (c ParentSyncApiConf) CredentialForChild(parent, child string) (DsyncApiClientCredential, bool) {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		if s == "" {
			return ""
		}
		return core.CanonicalizeName(dns.Fqdn(s))
	}
	wantParent, wantChild := norm(parent), norm(child)

	build := func(cc ParentSyncApiCredentialConf) DsyncApiClientCredential {
		out := DsyncApiClientCredential{
			Parent:   wantParent,
			Username: strings.TrimSpace(cc.Username),
			Key:      cc.Key.Value(),
		}
		if cc.TLS != nil {
			out.CertFile = strings.TrimSpace(cc.TLS.CertFile)
			out.KeyFile = strings.TrimSpace(cc.TLS.KeyFile)
		}
		return out
	}

	var generic *ParentSyncApiCredentialConf
	for i, cc := range c.Credentials {
		if norm(cc.Parent) != wantParent {
			continue
		}
		ccChild := norm(cc.Child)
		if ccChild == "" {
			if generic == nil {
				generic = &c.Credentials[i]
			}
			continue
		}
		if wantChild != "" && ccChild == wantChild {
			return build(cc), true
		}
	}
	if generic != nil {
		return build(*generic), true
	}
	return DsyncApiClientCredential{}, false
}

// DsyncDnsSchemeConf configures a scheme whose DSYNC target is a host that
// receives DNS messages: NOTIFY and UPDATE. Addresses are published as A/AAAA
// at the target, because a child has to be able to reach it by name.
type DsyncDnsSchemeConf struct {
	Types     []string `yaml:"types" mapstructure:"types"`
	Port      uint16   `yaml:"port" mapstructure:"port"`
	Target    string   `yaml:"target" mapstructure:"target"`
	Addresses []string `yaml:"addresses" mapstructure:"addresses"`
}

// DsyncApiSchemeConf configures the API scheme
// (docs/2026-08-11-dsync-api-scheme.md).
//
// The DSYNC target here is a service description point, not a host to send DNS
// to: the URI record published at it carries the actual endpoint, and that
// URI's authority resolves by ordinary means. Addresses are therefore optional,
// unlike the two DNS schemes above — set them only when the target is a name
// this zone is itself authoritative for and nothing else would publish them.
type DsyncApiSchemeConf struct {
	Types  []string `yaml:"types" mapstructure:"types"`
	Target string   `yaml:"target" mapstructure:"target"`
	// BaseUrl is a template: it must contain both {TARGET} and {PORT}, which
	// is what PublishUriRR requires of any URI it publishes.
	BaseUrl   string   `yaml:"baseurl" mapstructure:"baseurl"`
	Port      uint16   `yaml:"port" mapstructure:"port"`
	Dialect   string   `yaml:"dialect" mapstructure:"dialect"`
	Addresses []string `yaml:"addresses" mapstructure:"addresses"`

	// The listener. Not read by the publication path; the DSYNC-API server
	// (a later PR) reads it. Present here because it belongs to this block.
	Listen   []string `yaml:"listen" mapstructure:"listen"`
	CertFile string   `yaml:"cert" mapstructure:"cert"`
	KeyFile  string   `yaml:"key" mapstructure:"key"`

	// ClientAuth is the optional client-certificate path on this listener.
	// Absent (nil) means the feature is off: no CertificateRequest, and the
	// middleware never looks at a presented certificate.
	//
	// The handshake is fixed when the listener starts. Reload updates the
	// middleware from the live block, but does not send (or stop sending) a
	// CertificateRequest; a change here needs a restart.
	ClientAuth *DsyncApiClientAuthConf `yaml:"client-auth" mapstructure:"client-auth"`
}

// DsyncApiClientAuthConf is the parent-side client-certificate configuration.
// Mechanisms are tried in list order; tls-pin before tls-pkix is the sensible
// order (exact lookup, no chain building).
type DsyncApiClientAuthConf struct {
	Mechanisms []string `yaml:"mechanisms" mapstructure:"mechanisms"`
	CAFile     string   `yaml:"ca-file" mapstructure:"ca-file"`
}

// Enabled reports whether the listener should request client certificates.
func (c *DsyncApiClientAuthConf) Enabled() bool {
	return c != nil && len(c.Mechanisms) > 0
}

// Validate normalises mechanism names and refuses unknown ones. tls-pkix
// without ca-file is unsatisfiable and is warned at load, not refused, matching
// crossCheckDownstreamAuth.
func (c *DsyncApiClientAuthConf) Validate() error {
	if c == nil {
		return nil
	}
	if len(c.Mechanisms) == 0 {
		return fmt.Errorf("childsync.api.client-auth has no mechanisms")
	}
	var hasPkix bool
	for i, m := range c.Mechanisms {
		m = strings.ToLower(strings.TrimSpace(m))
		c.Mechanisms[i] = m
		if !validDsyncApiCertMech(m) {
			return fmt.Errorf("unknown DSYNC API client-auth mechanism %q (supported: tls-pin, tls-pkix)", m)
		}
		if m == DsyncApiAuthTLSPkix {
			hasPkix = true
		}
	}
	if hasPkix && strings.TrimSpace(c.CAFile) == "" {
		lgConfig.Warn("childsync.api.client-auth lists tls-pkix but ca-file is empty; tls-pkix will be unsatisfiable")
	}
	return nil
}

// Validate checks the childsync:/parentsync: blocks beyond what
// DsyncApiSchemeConf.Validate already does for publication: client-auth
// mechanisms on the childsync side, credential shape on the parentsync side.
func (c ChildSyncConf) Validate() error {
	return c.Api.ClientAuth.Validate()
}

func (c ParentSyncConf) Validate() error {
	return c.Api.ValidateCredentials()
}

// DsyncApiDialectV1 is the dialect identifier published in the TXT record at
// the API scheme's target, and the only one this implementation speaks.
//
// Protocol and version in one opaque token, matched literally by the child. A
// child that does not recognise the token does not use the endpoint, and
// crucially does not send its credential there — so the match has to happen
// before any parsing that could go subtly wrong on a future version.
const DsyncApiDialectV1 = "tdns-child-api-v1.0"

const (
	DefaultDsyncApiTarget  = "dsync-api.{ZONENAME}"
	DefaultDsyncApiBaseUrl = "https://{TARGET}:{PORT}/dsync/v1"
	DefaultDsyncApiPort    = 443
)

// WithDefaults returns the API scheme config with unset fields filled in. The
// defaults are all names and paths, never credentials or trust decisions, so
// defaulting them costs nothing an operator would want to be asked about.
func (c DsyncApiSchemeConf) WithDefaults() DsyncApiSchemeConf {
	if c.Target == "" {
		c.Target = DefaultDsyncApiTarget
	}
	if c.BaseUrl == "" {
		c.BaseUrl = DefaultDsyncApiBaseUrl
	}
	if c.Port == 0 {
		c.Port = DefaultDsyncApiPort
	}
	if c.Dialect == "" {
		c.Dialect = DsyncApiDialectV1
	}
	if len(c.Types) == 0 {
		c.Types = []string{"CDS", "CSYNC"}
	}
	return c
}

// Validate checks what can be checked without a zone name in hand. Called at
// publication time rather than at parse time because the block is only
// meaningful for a zone that actually offers the scheme.
func (c DsyncApiSchemeConf) Validate() error {
	if !strings.Contains(c.BaseUrl, "{TARGET}") || !strings.Contains(c.BaseUrl, "{PORT}") {
		return fmt.Errorf("childsync.api.baseurl %q must contain both {TARGET} and {PORT}", c.BaseUrl)
	}
	if c.Dialect == "" {
		return fmt.Errorf("childsync.api.dialect is empty")
	}
	if strings.ContainsAny(c.Dialect, " \t") {
		// The first whitespace-separated token of the TXT is the dialect;
		// anything after it is a parameter. A dialect containing whitespace
		// would publish as a dialect plus a garbage parameter.
		return fmt.Errorf("childsync.api.dialect %q must not contain whitespace", c.Dialect)
	}
	return nil
}

// delegationSyncConf holds the parsed delegationsync: block.
//
// Same shape and the same reasoning as KeyDB.options: it is read from code
// that has no *Config in hand (PublishDsyncRRs is a method on ZoneData, called
// from four places, none of which carry the config), and it is replaced
// wholesale on config reload. An atomic.Pointer gives lock-free reads and a
// race-free swap. Access via DelegationSyncConfig()/SetDelegationSyncConfig(),
// never directly.
// delegationSyncRuntime is the installed pair. It is NOT a config-file shape --
// childsync: and parentsync: are separate top-level blocks -- it exists so one
// atomic swap replaces both, since compiling the policies and rebinding the
// live zones has to happen once, for both halves, or not at all.
type delegationSyncRuntime struct {
	ChildSync  ChildSyncConf
	ParentSync ParentSyncConf
}

var delegationSyncConf atomic.Pointer[delegationSyncRuntime]

// SetDelegationSyncConfig installs the freshly-parsed childsync:/parentsync:
// blocks. Called from ParseConfig on both first start and reload. On error the
// previous pair stays installed.
func SetDelegationSyncConfig(cs ChildSyncConf, ps ParentSyncConf) error {
	compiled, err := compileDelegationPolicies(cs.Policies)
	if err != nil {
		return err
	}
	methods, err := compileChildBootstrapMethods(ps.Update.Bootstrap.Methods)
	if err != nil {
		return err
	}
	cs.CompiledPolicies = compiled
	ps.CompiledMethods = methods
	delegationSyncConf.Store(&delegationSyncRuntime{ChildSync: cs, ParentSync: ps})
	rebindLiveDelegationPolicies()
	return nil
}

// ChildSyncConfig returns the installed childsync: block. Never nil: a daemon
// that has not parsed a config yet, or one whose config has no childsync: block
// at all, gets the zero value — no schemes, which publishes nothing.
func ChildSyncConfig() *ChildSyncConf {
	if c := delegationSyncConf.Load(); c != nil {
		return &c.ChildSync
	}
	return &ChildSyncConf{}
}

// ParentSyncConfig returns the installed parentsync: block. Never nil, for the
// same reason as ChildSyncConfig.
func ParentSyncConfig() *ParentSyncConf {
	if c := delegationSyncConf.Load(); c != nil {
		return &c.ParentSync
	}
	return &ParentSyncConf{}
}
