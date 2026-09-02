/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// The two records that describe a DSYNC API endpoint, per
// docs/2026-08-11-dsync-api-scheme.md §3-4:
//
//	dsync-api.example.  URI  1 1 "https://dsync-api.example:443/dsync/v1"
//	dsync-api.example.  TXT  "tdns-child-api-v1.0"
//
// Built here rather than published through PublishUriRR so that they can go
// into the same UpdateRequest as the DSYNC record that points at them.

// DsyncApiEndpointUrl expands the baseurl template for a target.
//
// The trailing dot is stripped from the target before it goes into the URL.
// The RR owner name stays a proper FQDN; the URL host does not, because a host
// with a trailing dot is at best unusual and at worst mishandled — Go's TLS
// stack strips it for SNI and certificate matching, but nothing guarantees the
// same of whatever HTTP client a registrant's provisioning system uses, and a
// certificate mismatch here fails closed on the one operation this scheme
// exists to perform.
func DsyncApiEndpointUrl(target string, c DsyncApiSchemeConf) (string, error) {
	if !strings.Contains(c.BaseUrl, "{TARGET}") || !strings.Contains(c.BaseUrl, "{PORT}") {
		return "", fmt.Errorf("baseurl %q must contain both {TARGET} and {PORT}", c.BaseUrl)
	}
	host := strings.TrimSuffix(dns.Fqdn(target), ".")
	if host == "" {
		return "", fmt.Errorf("empty DSYNC api target")
	}
	url := strings.Replace(c.BaseUrl, "{TARGET}", host, 1)
	url = strings.Replace(url, "{PORT}", fmt.Sprintf("%d", c.Port), 1)
	return url, nil
}

// dsyncApiUriRR builds the URI record carrying the endpoint.
//
// Priority and weight are both 1. The RRset is expected to hold exactly one
// record; if a deployment ever publishes several, the values are there to be
// given meaning then rather than now.
func dsyncApiUriRR(target string, c DsyncApiSchemeConf, ttl uint32) (*dns.URI, error) {
	endpoint, err := DsyncApiEndpointUrl(target, c)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		// Published anyway: a conforming child refuses it (the credential is
		// a bearer token and plaintext hands it away), and a lab that wants
		// this sets delegationsync.child.api.allow-insecure on the child. But
		// it is never what a production parent meant to configure.
		lg.Warn("DSYNC API endpoint is not https; conforming children will refuse it",
			"target", target, "endpoint", endpoint)
	}
	return &dns.URI{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(target),
			Rrtype: dns.TypeURI,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Priority: 1,
		Weight:   1,
		Target:   endpoint,
	}, nil
}

// dsyncApiTxtRR builds the TXT record carrying the dialect identifier.
//
// One character-string holding one token. The format allows trailing
// key=value parameters (§4), none are defined in v1.0, and publishing none is
// how a v1.0 parent says so.
func dsyncApiTxtRR(target string, c DsyncApiSchemeConf, ttl uint32) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(target),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Txt: []string{c.Dialect},
	}
}

// DsyncApiTargetName computes the DSYNC API target name for a parent zone from
// the global config. Returns empty string if the scheme is not configured.
func DsyncApiTargetName(zonename string) string {
	dsc := DelegationSyncConfig().Parent
	if !dsyncSchemeConfigured(dsc.Schemes, "api") {
		return ""
	}
	tpl := dsc.Api.WithDefaults().Target
	return expandDsyncTemplate(tpl, zonename)
}

func dsyncSchemeConfigured(schemes []string, want string) bool {
	for _, s := range schemes {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}
