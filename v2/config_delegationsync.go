/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// The delegationsync: block, typed.
//
// This block has been read with viper.GetString/GetStringSlice since it was
// written, from a dozen call sites across the tree. That is being unwound one
// file at a time rather than all at once, so THIS STRUCT IS NOT YET THE WHOLE
// BLOCK: it models the keys the DSYNC publication path reads, and nothing
// else. The keygen and key-verification subtrees under parent.update and
// child.update are still read via viper by sig0_utils.go, ops_key.go,
// delegation_sync.go and truststore_verify.go, and are deliberately absent
// here so this struct does not claim an authority it does not have.
//
// mapstructure ignores keys it has no field for, so the two views coexist
// without either losing data.
//
// Why unwind it at all: viper splits keys on ".". Any config shape with a
// dotted key silently arrives empty, the setting reads back as its zero value,
// and nothing logs a thing. Zone names are dotted, and the labstuff
// parentupdater work walked into exactly this trap in the same week this was
// written. New code reads the struct.
type DelegationSyncConf struct {
	Parent DelegationSyncParentConf `yaml:"parent" mapstructure:"parent"`
	Child  DelegationSyncChildConf  `yaml:"child" mapstructure:"child"`
}

type DelegationSyncParentConf struct {
	// Schemes we are willing to offer children, and therefore publish DSYNC
	// records for: notify, update, api.
	Schemes []string           `yaml:"schemes" mapstructure:"schemes"`
	Notify  DsyncDnsSchemeConf `yaml:"notify" mapstructure:"notify"`
	Update  DsyncDnsSchemeConf `yaml:"update" mapstructure:"update"`
	Api     DsyncApiSchemeConf `yaml:"api" mapstructure:"api"`

	Bootstrap struct {
		Methods string `yaml:"methods" mapstructure:"methods"`
	} `yaml:"bootstrap" mapstructure:"bootstrap"`
}

type DelegationSyncChildConf struct {
	// Schemes we are willing to use against a parent, in preference order.
	Schemes []string          `yaml:"schemes" mapstructure:"schemes"`
	Api     DsyncApiChildConf `yaml:"api" mapstructure:"api"`
}

// DsyncApiChildConf is what a child needs to use the API scheme against its
// parents: one credential per parent, obtained out of band.
type DsyncApiChildConf struct {
	// A LIST, not a map keyed by parent name. viper splits keys on ".", so a
	// map keyed "example." would arrive keyed "example" with every setting
	// beneath it somewhere the struct cannot see -- and the credential would
	// read back empty with nothing logged anywhere. Same reason the labstuff
	// parentupdater config is a list.
	Credentials []DsyncApiChildCredentialConf `yaml:"credentials" mapstructure:"credentials"`

	// AllowInsecure permits a plain-http endpoint AND an endpoint discovered
	// without DNSSEC validation. Deliberately one switch for both: they are
	// the same protection seen from two sides, and an operator who turns off
	// one while believing the other still holds has no protection at all.
	// A lab convenience. Never a production setting.
	AllowInsecure bool `yaml:"allow-insecure" mapstructure:"allow-insecure"`
}

type DsyncApiChildCredentialConf struct {
	Parent   string          `yaml:"parent" mapstructure:"parent"`
	Username string          `yaml:"username" mapstructure:"username"`
	Key      SensitiveString `yaml:"key" mapstructure:"key"`
}

// CredentialFor returns the credential for a parent zone, matching as FQDNs so
// a config written with or without the trailing dot works either way.
func (c DsyncApiChildConf) CredentialFor(parent string) (DsyncApiClientCredential, bool) {
	want := strings.ToLower(dns.Fqdn(strings.TrimSpace(parent)))
	for _, cc := range c.Credentials {
		if strings.ToLower(dns.Fqdn(strings.TrimSpace(cc.Parent))) == want {
			return DsyncApiClientCredential{
				Parent:   want,
				Username: strings.TrimSpace(cc.Username),
				Key:      cc.Key.Value(),
			}, true
		}
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
		return fmt.Errorf("delegationsync.parent.api.baseurl %q must contain both {TARGET} and {PORT}", c.BaseUrl)
	}
	if c.Dialect == "" {
		return fmt.Errorf("delegationsync.parent.api.dialect is empty")
	}
	if strings.ContainsAny(c.Dialect, " \t") {
		// The first whitespace-separated token of the TXT is the dialect;
		// anything after it is a parameter. A dialect containing whitespace
		// would publish as a dialect plus a garbage parameter.
		return fmt.Errorf("delegationsync.parent.api.dialect %q must not contain whitespace", c.Dialect)
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
var delegationSyncConf atomic.Pointer[DelegationSyncConf]

// SetDelegationSyncConfig installs the freshly-parsed block. Called from
// ParseConfig on both first start and reload.
func SetDelegationSyncConfig(dsc DelegationSyncConf) {
	delegationSyncConf.Store(&dsc)
}

// DelegationSyncConfig returns the current block. Never nil: a daemon that has
// not parsed a config yet, or one whose config has no delegationsync: block at
// all, gets the zero value — no schemes, which publishes nothing.
func DelegationSyncConfig() *DelegationSyncConf {
	if dsc := delegationSyncConf.Load(); dsc != nil {
		return dsc
	}
	return &DelegationSyncConf{}
}
