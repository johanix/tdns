/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func TestDsyncApiDefaults(t *testing.T) {
	c := DsyncApiSchemeConf{}.WithDefaults()

	if c.Target != DefaultDsyncApiTarget {
		t.Errorf("target = %q, want %q", c.Target, DefaultDsyncApiTarget)
	}
	if c.Port != DefaultDsyncApiPort {
		t.Errorf("port = %d, want %d", c.Port, DefaultDsyncApiPort)
	}
	if c.Dialect != DsyncApiDialectV1 {
		t.Errorf("dialect = %q, want %q", c.Dialect, DsyncApiDialectV1)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the defaults do not validate: %v", err)
	}

	// Defaults must not overwrite what an operator set.
	set := DsyncApiSchemeConf{Target: "api.{ZONENAME}", Port: 8443, Dialect: "x-1.0"}.WithDefaults()
	if set.Target != "api.{ZONENAME}" || set.Port != 8443 || set.Dialect != "x-1.0" {
		t.Errorf("defaults overwrote configured values: %+v", set)
	}
}

func TestDsyncApiValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf DsyncApiSchemeConf
		ok   bool
	}{
		{"defaults", DsyncApiSchemeConf{}.WithDefaults(), true},
		{"baseurl without {TARGET}", DsyncApiSchemeConf{
			BaseUrl: "https://fixed.example:{PORT}/dsync/v1", Dialect: DsyncApiDialectV1}, false},
		{"baseurl without {PORT}", DsyncApiSchemeConf{
			BaseUrl: "https://{TARGET}/dsync/v1", Dialect: DsyncApiDialectV1}, false},
		{"empty dialect", DsyncApiSchemeConf{
			BaseUrl: DefaultDsyncApiBaseUrl, Dialect: ""}, false},
		// A dialect with a space would publish as a dialect plus a garbage
		// parameter, and the child would match on the first token only --
		// silently talking a protocol nobody configured.
		{"dialect with whitespace", DsyncApiSchemeConf{
			BaseUrl: DefaultDsyncApiBaseUrl, Dialect: "tdns-child-api v1.0"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.conf.Validate()
			if tc.ok && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Error("Validate() = nil, want an error")
			}
		})
	}
}

// The URL host must not carry the trailing dot the RR owner name does. Go's
// TLS stack strips it for SNI and certificate matching, but the endpoint is
// consumed by whatever HTTP client a registrant happens to run, and a
// certificate mismatch fails the one operation the scheme exists for.
func TestDsyncApiEndpointUrlStripsTrailingDot(t *testing.T) {
	c := DsyncApiSchemeConf{}.WithDefaults()

	url, err := DsyncApiEndpointUrl("dsync-api.example.", c)
	if err != nil {
		t.Fatalf("DsyncApiEndpointUrl: %v", err)
	}
	want := "https://dsync-api.example:443/dsync/v1"
	if url != want {
		t.Errorf("url = %q, want %q", url, want)
	}

	// A target written without the dot must produce the same URL.
	url2, err := DsyncApiEndpointUrl("dsync-api.example", c)
	if err != nil {
		t.Fatalf("DsyncApiEndpointUrl: %v", err)
	}
	if url2 != want {
		t.Errorf("url (no trailing dot) = %q, want %q", url2, want)
	}
}

func TestDsyncApiEndpointUrlRejectsBadTemplate(t *testing.T) {
	c := DsyncApiSchemeConf{BaseUrl: "https://{TARGET}/dsync/v1", Port: 443}
	if _, err := DsyncApiEndpointUrl("dsync-api.example.", c); err == nil {
		t.Error("a baseurl with no {PORT} was accepted")
	}
}

func TestDsyncApiRecords(t *testing.T) {
	c := DsyncApiSchemeConf{}.WithDefaults()
	target := "dsync-api.example."

	uri, err := dsyncApiUriRR(target, c, 7200)
	if err != nil {
		t.Fatalf("dsyncApiUriRR: %v", err)
	}
	if uri.Hdr.Name != target {
		t.Errorf("URI owner = %q, want %q", uri.Hdr.Name, target)
	}
	if uri.Hdr.Rrtype != dns.TypeURI || uri.Hdr.Ttl != 7200 {
		t.Errorf("URI header wrong: %+v", uri.Hdr)
	}
	if uri.Target != "https://dsync-api.example:443/dsync/v1" {
		t.Errorf("URI target = %q", uri.Target)
	}

	txt := dsyncApiTxtRR(target, c, 7200)
	if txt.Hdr.Name != target || txt.Hdr.Rrtype != dns.TypeTXT {
		t.Errorf("TXT header wrong: %+v", txt.Hdr)
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != DsyncApiDialectV1 {
		t.Errorf("TXT = %v, want exactly [%q]", txt.Txt, DsyncApiDialectV1)
	}

	// Both must survive a presentation-format round trip: they are written to
	// a zone file and read back on the next load.
	for _, rr := range []dns.RR{uri, txt} {
		reparsed, err := dns.NewRR(rr.String())
		if err != nil {
			t.Errorf("cannot reparse %q: %v", rr.String(), err)
			continue
		}
		if reparsed.String() != rr.String() {
			t.Errorf("round trip changed the record:\n  before %q\n  after  %q", rr.String(), reparsed.String())
		}
	}
}

func TestDsyncApiTargetName(t *testing.T) {
	t.Cleanup(func() { SetDelegationSyncConfig(DelegationSyncConf{}) })

	// Not configured for the API scheme: no target, so UnpublishDsyncRRs does
	// not try to delete records that were never published.
	SetDelegationSyncConfig(DelegationSyncConf{
		Parent: DelegationSyncParentConf{Schemes: []string{"notify", "update"}},
	})
	if got := DsyncApiTargetName("example."); got != "" {
		t.Errorf("target for a zone not offering the API scheme = %q, want empty", got)
	}

	SetDelegationSyncConfig(DelegationSyncConf{
		Parent: DelegationSyncParentConf{Schemes: []string{"notify", "update", "api"}},
	})
	if got, want := DsyncApiTargetName("example."), "dsync-api.example."; got != want {
		t.Errorf("target = %q, want %q", got, want)
	}
	// The root zone would expand to "dsync-api.." — the same "root" spelling
	// the other two schemes use.
	if got, want := DsyncApiTargetName("."), "dsync-api.root."; got != want {
		t.Errorf("root target = %q, want %q", got, want)
	}
}

// DelegationSyncConfig must be usable before any config is parsed: it is
// reached from zone setup paths that run in tests and in tools that never call
// ParseConfig. The zero value publishes nothing, which is the safe answer.
func TestDelegationSyncConfigNeverNil(t *testing.T) {
	t.Cleanup(func() { SetDelegationSyncConfig(DelegationSyncConf{}) })

	delegationSyncConf.Store(nil)
	dsc := DelegationSyncConfig()
	if dsc == nil {
		t.Fatal("DelegationSyncConfig() returned nil")
	}
	if len(dsc.Parent.Schemes) != 0 {
		t.Errorf("the zero value offers schemes: %v", dsc.Parent.Schemes)
	}
}

// The reason this block is typed at all. viper splits keys on ".", so a config
// read with viper.GetString survives only as long as no key contains a dot.
// This asserts the struct view sees everything the YAML says, which is what
// new code is required to read.
func TestDelegationSyncConfigRoundTripsThroughViper(t *testing.T) {
	const y = `
delegationsync:
   parent:
      schemes: [ notify, update, api ]
      notify:
         types:     [ CDS, CSYNC ]
         port:      5354
         target:    notifications.{ZONENAME}
         addresses: [ 127.0.0.1, '::1' ]
      update:
         types:     [ ANY ]
         port:      5354
         target:    updates.{ZONENAME}
         addresses: [ 127.0.0.1 ]
      api:
         types:   [ CDS, CSYNC ]
         target:  dsync-api.{ZONENAME}
         baseurl: "https://{TARGET}:{PORT}/dsync/v1"
         port:    8443
         dialect: tdns-child-api-v1.0
         listen:  [ "0.0.0.0:8443" ]
         cert:    /etc/tdns/dsync-api.crt
         key:     /etc/tdns/dsync-api.key
   child:
      schemes: [ update, notify, api ]
`
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(y)); err != nil {
		t.Fatalf("read: %v", err)
	}

	var conf Config
	if err := v.Unmarshal(&conf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	dsc := conf.DelegationSync
	if len(dsc.Parent.Schemes) != 3 {
		t.Fatalf("parent schemes = %v", dsc.Parent.Schemes)
	}
	if len(dsc.Child.Schemes) != 3 {
		t.Errorf("child schemes = %v", dsc.Child.Schemes)
	}

	// The two pre-existing schemes must decode exactly as their viper reads
	// did, or converting PublishDsyncRRs changed behaviour.
	if dsc.Parent.Notify.Port != 5354 || dsc.Parent.Notify.Target != "notifications.{ZONENAME}" {
		t.Errorf("notify decoded wrong: %+v", dsc.Parent.Notify)
	}
	if len(dsc.Parent.Notify.Addresses) != 2 {
		t.Errorf("notify addresses = %v", dsc.Parent.Notify.Addresses)
	}
	if dsc.Parent.Update.Port != 5354 || dsc.Parent.Update.Target != "updates.{ZONENAME}" {
		t.Errorf("update decoded wrong: %+v", dsc.Parent.Update)
	}
	if len(dsc.Parent.Update.Types) != 1 || dsc.Parent.Update.Types[0] != "ANY" {
		t.Errorf("update types = %v", dsc.Parent.Update.Types)
	}

	api := dsc.Parent.Api
	if api.Port != 8443 || api.Target != "dsync-api.{ZONENAME}" || api.Dialect != DsyncApiDialectV1 {
		t.Errorf("api decoded wrong: %+v", api)
	}
	if api.BaseUrl != "https://{TARGET}:{PORT}/dsync/v1" {
		t.Errorf("api baseurl = %q", api.BaseUrl)
	}
	// cert/key use yaml keys that differ from the field names; a silent miss
	// here would surface much later as a listener that cannot start.
	if api.CertFile != "/etc/tdns/dsync-api.crt" || api.KeyFile != "/etc/tdns/dsync-api.key" {
		t.Errorf("api cert/key decoded wrong: cert=%q key=%q", api.CertFile, api.KeyFile)
	}
	if len(api.Listen) != 1 || api.Listen[0] != "0.0.0.0:8443" {
		t.Errorf("api listen = %v", api.Listen)
	}
}
