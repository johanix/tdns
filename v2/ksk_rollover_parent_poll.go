package tdns

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type dsCanon struct {
	keyTag     uint16
	algorithm  uint8
	digestType uint8
	digest     []byte
}

func dsCanonical(d *dns.DS) dsCanon {
	return dsCanon{
		keyTag:     d.KeyTag,
		algorithm:  d.Algorithm,
		digestType: d.DigestType,
		digest:     append([]byte(nil), d.Digest...),
	}
}

func canonEqual(a, b dsCanon) bool {
	return a.keyTag == b.keyTag && a.algorithm == b.algorithm && a.digestType == b.digestType && bytes.Equal(a.digest, b.digest)
}

func canonInList(c dsCanon, list []dsCanon) bool {
	for _, x := range list {
		if canonEqual(c, x) {
			return true
		}
	}
	return false
}

// ObservedDSSetMatchesExpected implements the match rule in design §7.5 (normative).
func ObservedDSSetMatchesExpected(observed, expected []dns.RR) bool {
	var expDS, obsDS []*dns.DS
	for _, rr := range expected {
		d, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		if d.Hdr.Class != dns.ClassINET {
			return false
		}
		expDS = append(expDS, d)
	}
	for _, rr := range observed {
		d, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		if d.Hdr.Class != dns.ClassINET {
			return false
		}
		obsDS = append(obsDS, d)
	}
	if len(expDS) == 0 {
		return false
	}
	expCanon := make([]dsCanon, len(expDS))
	for i, d := range expDS {
		expCanon[i] = dsCanonical(d)
	}
	obsCanon := make([]dsCanon, len(obsDS))
	for i, d := range obsDS {
		obsCanon[i] = dsCanonical(d)
	}
	keytagsManaged := make(map[uint16]struct{})
	for _, d := range expDS {
		keytagsManaged[d.KeyTag] = struct{}{}
	}
	for _, ec := range expCanon {
		if !canonInList(ec, obsCanon) {
			return false
		}
	}
	for _, o := range obsDS {
		if _, ok := keytagsManaged[o.KeyTag]; !ok {
			continue
		}
		if !canonInList(dsCanonical(o), expCanon) {
			return false
		}
	}
	return true
}

// QueryParentAgentDS asks the configured parent-agent (addr:port) for child DS over TCP.
func QueryParentAgentDS(ctx context.Context, childZone, agentAddr string) ([]dns.RR, error) {
	q := dns.Fqdn(childZone)
	m := new(dns.Msg)
	m.SetQuestion(q, dns.TypeDS)
	m.SetEdns0(4096, true)

	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = 10 * time.Second

	res, _, err := c.ExchangeContext(ctx, m, agentAddr)
	if err != nil {
		return nil, err
	}
	if res.Truncated {
		return nil, fmt.Errorf("QueryParentAgentDS: unexpected TC on TCP response")
	}
	if res.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("QueryParentAgentDS: rcode %s", dns.RcodeToString[res.Rcode])
	}
	if err := checkParentAgentAnswer(res, q, agentAddr); err != nil {
		return nil, err
	}
	return res.Answer, nil
}

// checkParentAgentAnswer refuses an answer that cannot have come from the
// parent's authoritative view of the child's DS. The engine reads an empty
// answer as "the parent holds no DS" -- for an insecure roll that is what
// lets the old KSK go -- so a misconfigured parent-agent must show up as a
// failed poll, not as an insecure parent:
//   - no AA bit: not authoritative (a resolver, a referral);
//   - an empty answer whose SOA is not a proper ancestor of the child:
//     typically the child's own server, which says "no DS" for every query
//     because DS lives in the parent.
func checkParentAgentAnswer(res *dns.Msg, child, agentAddr string) error {
	if !res.Authoritative {
		return fmt.Errorf("QueryParentAgentDS: %s did not answer authoritatively for the DS of %s; rollover.parent-agent must be the parent's authoritative server", agentAddr, child)
	}
	for _, rr := range res.Answer {
		if rr.Header().Rrtype == dns.TypeDS {
			return nil
		}
	}
	soaOwner := ""
	for _, rr := range res.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			soaOwner = soa.Hdr.Name
			break
		}
	}
	if soaOwner == "" {
		return fmt.Errorf("QueryParentAgentDS: %s answered no DS for %s without an SOA, so it does not say which zone answered", agentAddr, child)
	}
	if strings.EqualFold(dns.Fqdn(soaOwner), dns.Fqdn(child)) || !dns.IsSubDomain(soaOwner, child) {
		return fmt.Errorf("QueryParentAgentDS: %s answered no DS for %s from zone %s, not from its parent; rollover.parent-agent must be the parent's authoritative server", agentAddr, child, soaOwner)
	}
	return nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// PollParentDSUntilMatch queries the parent-agent until the answer matches expected (§7.2, §7.5)
// or confirmTimeout elapses. Backoff between attempts: next = min(2*previous, pollMax), with the
// first pre-query wait equal to initialWait.
func PollParentDSUntilMatch(ctx context.Context, childZone string, expected []dns.RR, agentAddr string, initialWait, pollMax, confirmTimeout time.Duration) (matched bool, err error) {
	if len(expected) == 0 {
		return false, fmt.Errorf("PollParentDSUntilMatch: empty expected DS set")
	}
	if initialWait <= 0 {
		initialWait = defaultConfirmInitialWait
	}
	if pollMax <= 0 {
		pollMax = defaultConfirmPollMax
	}
	if confirmTimeout <= 0 {
		confirmTimeout = defaultConfirmTimeout
	}
	deadline := time.Now().Add(confirmTimeout)
	nextSleep := initialWait
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		now := time.Now()
		if !now.Before(deadline) {
			return false, fmt.Errorf("PollParentDSUntilMatch: elapsed >= confirm-timeout (%v)", confirmTimeout)
		}
		wait := minDuration(nextSleep, time.Until(deadline))
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return false, ctx.Err()
			case <-t.C:
			}
		}
		if !time.Now().Before(deadline) {
			return false, fmt.Errorf("PollParentDSUntilMatch: elapsed >= confirm-timeout (%v)", confirmTimeout)
		}
		obs, qerr := QueryParentAgentDS(ctx, childZone, agentAddr)
		if qerr == nil && ObservedDSSetMatchesExpected(obs, expected) {
			return true, nil
		}
		nextSleep = minDuration(2*nextSleep, pollMax)
	}
}
