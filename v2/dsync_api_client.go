/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The child side of the DSYNC API scheme (docs/2026-08-11-dsync-api-scheme.md
// §8, §11).
//
// This scheme has one exposure the UPDATE scheme does not, and everything
// defensive here follows from it: the credential is a BEARER token. A child
// fooled into sending a SIG(0)-signed update to the wrong server leaks
// nothing -- the message is signed, the wrong server cannot use it, and the
// change simply does not happen. A child fooled into POSTing here hands an
// attacker a working credential.
//
// So the endpoint is only ever derived from DNSSEC-validated records, only
// ever https, and the credential is never sent anywhere the discovery did not
// name.

// DsyncApiEndpoint is a validated, usable endpoint.
type DsyncApiEndpoint struct {
	Target  string // the DSYNC target, where URI and TXT were found
	Url     string // from the URI record
	Dialect string // from the TXT record
}

// dsyncApiSupportedDialects are the dialects this implementation speaks, in
// preference order. A parent may advertise several; the first match wins.
var dsyncApiSupportedDialects = []string{DsyncApiDialectV1}

// DiscoverDsyncApiEndpoint resolves the service description at a DSYNC API
// target: the URI carrying the endpoint and the TXT carrying the dialect.
//
// Both lookups MUST validate. This is a hard prerequisite, not a
// recommendation: an unvalidated URI is an attacker's URL, and the next thing
// that happens is a credential being sent to it. It also means this scheme
// requires a signed parent zone -- a real constraint, and the reason it is a
// fallback rather than a default.
//
// requireDnssec is the escape hatch, and it is the same switch as
// allowInsecure: a lab that has turned off one has turned off the other, and
// pretending they are separate protections invites turning off the wrong one.
func DiscoverDsyncApiEndpoint(ctx context.Context, imr *Imr, target string, requireDnssec bool) (*DsyncApiEndpoint, error) {
	if imr == nil {
		return nil, fmt.Errorf("no IMR available to resolve the DSYNC API endpoint")
	}
	target = dns.Fqdn(strings.TrimSpace(target))

	uriResp, err := imr.ImrQuery(ctx, target, dns.TypeURI, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("looking up URI at %s: %v", target, err)
	}
	if uriResp == nil || uriResp.RRset == nil || len(uriResp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no URI record at %s; the parent advertises the API scheme but publishes no endpoint", target)
	}
	if requireDnssec && !uriResp.Validated {
		return nil, fmt.Errorf(
			"the URI record at %s did not DNSSEC-validate; refusing to send credentials to an unauthenticated endpoint", target)
	}

	txtResp, err := imr.ImrQuery(ctx, target, dns.TypeTXT, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("looking up TXT at %s: %v", target, err)
	}
	if txtResp == nil || txtResp.RRset == nil || len(txtResp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no TXT record at %s; nothing says what dialect the endpoint speaks", target)
	}
	if requireDnssec && !txtResp.Validated {
		return nil, fmt.Errorf("the TXT record at %s did not DNSSEC-validate", target)
	}

	dialect, err := pickDsyncApiDialect(txtResp.RRset.RRs)
	if err != nil {
		return nil, err
	}

	endpoint, err := pickDsyncApiUrl(uriResp.RRset.RRs)
	if err != nil {
		return nil, err
	}

	return &DsyncApiEndpoint{Target: target, Url: endpoint, Dialect: dialect}, nil
}

// pickDsyncApiDialect finds the first advertised dialect this implementation
// speaks. Several TXT records at the name is how a parent advertises more than
// one, which is the version-migration story.
func pickDsyncApiDialect(rrs []dns.RR) (string, error) {
	var advertised []string
	for _, rr := range rrs {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		// Character-strings inside one TXT are concatenated with no
		// separator, as SPF and DKIM do.
		joined := strings.Join(txt.Txt, "")
		fields := strings.Fields(joined)
		if len(fields) == 0 {
			continue
		}
		// The first token is the dialect; anything after it is a parameter,
		// and unknown parameters are ignored by design.
		advertised = append(advertised, fields[0])
	}

	for _, want := range dsyncApiSupportedDialects {
		for _, got := range advertised {
			if got == want {
				return got, nil
			}
		}
	}
	// Fail closed. Not guessing, not defaulting, and above all not sending a
	// credential to something whose protocol we do not know.
	return "", fmt.Errorf("no supported dialect advertised (parent offers %v, this implementation speaks %v)",
		advertised, dsyncApiSupportedDialects)
}

func pickDsyncApiUrl(rrs []dns.RR) (string, error) {
	for _, rr := range rrs {
		uri, ok := rr.(*dns.URI)
		if !ok {
			continue
		}
		if strings.TrimSpace(uri.Target) != "" {
			return strings.TrimSpace(uri.Target), nil
		}
	}
	return "", fmt.Errorf("no usable URI target")
}

// DsyncApiClientCredential is what a child holds for one parent.
type DsyncApiClientCredential struct {
	Parent   string
	Username string
	Key      string
}

// DsyncApiPostDelegationRequest sends a declared delegation to a parent.
//
// allowInsecure permits a plain-http endpoint. Off by default and named so it
// reads like what it is: with it on, the credential goes over the wire in
// clear to anyone on the path.
func DsyncApiPostDelegationRequest(ctx context.Context, endpoint *DsyncApiEndpoint,
	cred DsyncApiClientCredential, child string, rrsets []DsyncApiRRset,
	allowInsecure bool, caFile string) (*DsyncApiDelegation, error) {

	if endpoint == nil || endpoint.Url == "" {
		return nil, fmt.Errorf("no endpoint")
	}
	u, err := url.Parse(endpoint.Url)
	if err != nil {
		return nil, fmt.Errorf("the published endpoint %q is not a URL: %v", endpoint.Url, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		if !allowInsecure {
			return nil, fmt.Errorf(
				"the published endpoint %q is not https; refusing to send a bearer credential in clear"+
					" (set delegationsync.child.api.allow-insecure to override, in a lab only)", endpoint.Url)
		}
		lgDns.Warn("DSYNC API: sending a credential over a non-https endpoint because allow-insecure is set",
			"endpoint", endpoint.Url)
	}

	body, err := json.Marshal(DsyncApiDelegation{Child: dns.Fqdn(child), RRsets: rrsets})
	if err != nil {
		return nil, fmt.Errorf("encoding the delegation: %v", err)
	}

	reqUrl := strings.TrimSuffix(endpoint.Url, "/") + "/delegation/" + url.PathEscape(dns.Fqdn(child))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqUrl, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cred.Username, cred.Key)

	client, err := dsyncApiHttpClient(caFile)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting the delegation to %s: %v", reqUrl, err)
	}
	defer resp.Body.Close()

	// Bounded: an endpoint that answers with a gigabyte is not one to read
	// into memory on the strength of it having a certificate.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the parent refused the delegation update: %s: %s",
			resp.Status, strings.TrimSpace(string(respBody)))
	}

	var out DsyncApiDelegation
	if err := json.Unmarshal(respBody, &out); err != nil {
		// The change was made -- 200 is the parent's promise that it was
		// applied, persisted and published -- and only the read-back is
		// unreadable. Saying "failed" here would invite a retry of something
		// that already succeeded.
		lgDns.Warn("DSYNC API: the parent's response body could not be parsed, but the update was accepted",
			"err", err)
		return nil, nil
	}
	return &out, nil
}

// dsyncApiHttpClient builds the client used for every DSYNC API request.
//
// Two deliberate choices, both about the credential:
//
//   - Certificate validation is on. DNSSEC establishes which endpoint was
//     meant; TLS establishes that this is it. Disabling either makes the other
//     pointless, so there is no knob for this.
//   - Redirects are refused outright. Go strips Authorization across hosts,
//     which turns a redirect into a silent auth failure rather than a leak,
//     but a same-host redirect still carries the credential -- and a redirect
//     on this endpoint means something is wrong either way.
func dsyncApiHttpClient(caFile string) (*http.Client, error) {
	tlsconf := &tls.Config{MinVersion: tls.VersionTLS12}

	// An extra CA on top of the system roots, for the private trust domain
	// `tdns-cli cert ca` mints. Additive: everything is still verified, just
	// against a larger set of roots. A CA file that is named but unreadable is
	// an error rather than a silent fallback to the system roots -- the
	// operator asked for that CA, and quietly not using it would mean every
	// request failing later with a confusing certificate error.
	if strings.TrimSpace(caFile) != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading delegationsync.child.api.cafile %q: %v", caFile, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %q", caFile)
		}
		tlsconf.RootCAs = pool
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("the endpoint redirected to %s; refusing to follow it with a credential attached",
				req.URL.Redacted())
		},
		Transport: &http.Transport{
			TLSClientConfig: tlsconf,
		},
	}, nil
}

// DsyncApiRRsetsFromSyncStatus renders the child's desired delegation as the
// declarative form the endpoint takes.
//
// Replace semantics throughout: the child states what its delegation should
// be, not what changed. That is what makes a retry safe, and it is the same
// shape UpdateModeReplace produces on the UPDATE path.
//
// Only what the child actually manages is listed. An RRset absent from the
// request is left alone by the parent, so a child that has no opinion about
// its DS must not send an empty DS entry -- that would remove it.
func DsyncApiRRsetsFromSyncStatus(child string, syncstate DelegationSyncStatus) []DsyncApiRRset {
	child = dns.Fqdn(child)
	var out []DsyncApiRRset

	add := func(owner string, rrtype uint16, rrs []dns.RR) {
		strs := make([]string, 0, len(rrs))
		for _, rr := range rrs {
			strs = append(strs, rr.String())
		}
		out = append(out, DsyncApiRRset{
			Owner: dns.Fqdn(owner), Type: dns.TypeToString[rrtype], RRs: strs,
		})
	}

	if len(syncstate.NewNS) > 0 {
		add(child, dns.TypeNS, syncstate.NewNS)
	}
	// Glue is grouped by owner: one entry per nameserver name per address
	// family, because each is its own RRset and the endpoint addresses RRsets.
	for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		var src []dns.RR
		switch rrtype {
		case dns.TypeA:
			src = syncstate.NewA
		case dns.TypeAAAA:
			src = syncstate.NewAAAA
		}
		byOwner := map[string][]dns.RR{}
		var order []string
		for _, rr := range src {
			owner := rr.Header().Name
			if _, seen := byOwner[owner]; !seen {
				order = append(order, owner)
			}
			byOwner[owner] = append(byOwner[owner], rr)
		}
		for _, owner := range order {
			add(owner, rrtype, byOwner[owner])
		}
	}
	if len(syncstate.NewDS) > 0 {
		add(child, dns.TypeDS, syncstate.NewDS)
	}

	return out
}
