/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// LookupChildKeyAtApex queries the child zone apex for KEY records via the
// IMR engine. Returns the KEY RRs found, whether the response was DNSSEC-
// validated, and any error.
func LookupChildKeyAtApex(ctx context.Context, childZone string, imr *Imr) ([]dns.RR, bool, error) {
	resp, err := imr.ImrQuery(ctx, dns.Fqdn(childZone), dns.TypeKEY, dns.ClassINET, nil)
	if err != nil {
		return nil, false, fmt.Errorf("IMR query for %s KEY failed: %v", childZone, err)
	}
	if resp.Error {
		return nil, false, fmt.Errorf("IMR query for %s KEY returned error: %s", childZone, resp.ErrorMsg)
	}
	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, false, fmt.Errorf("no KEY records found at apex of %s", childZone)
	}

	return resp.RRset.RRs, resp.Validated, nil
}

// LookupChildKeyAtSignal queries _sig0key.<childzone>._signal.<ns>. for KEY
// records for each NS serving the child zone. Returns the union of KEY RRs
// found, whether all responses were DNSSEC-validated, and any error.
func LookupChildKeyAtSignal(ctx context.Context, childZone string, imr *Imr) ([]dns.RR, bool, error) {
	// First, look up the child zone's NS records.
	nsResp, err := imr.ImrQuery(ctx, dns.Fqdn(childZone), dns.TypeNS, dns.ClassINET, nil)
	if err != nil {
		return nil, false, fmt.Errorf("IMR query for %s NS failed: %v", childZone, err)
	}
	if nsResp.Error || nsResp.RRset == nil || len(nsResp.RRset.RRs) == 0 {
		return nil, false, fmt.Errorf("no NS records found for %s", childZone)
	}

	var allKeys []dns.RR
	allValidated := true
	found := false

	for _, rr := range nsResp.RRset.RRs {
		nsRR, ok := rr.(*dns.NS)
		if !ok {
			continue
		}

		// _sig0key.<childzone>._signal.<ns>.
		signalName := fmt.Sprintf("_sig0key.%s_signal.%s", dns.Fqdn(childZone), dns.Fqdn(nsRR.Ns))
		lgSigner.Debug("LookupChildKeyAtSignal: querying", "name", signalName)

		keyResp, err := imr.ImrQuery(ctx, signalName, dns.TypeKEY, dns.ClassINET, nil)
		if err != nil {
			lgSigner.Debug("LookupChildKeyAtSignal: query failed", "name", signalName, "err", err)
			continue
		}
		if keyResp.Error || keyResp.RRset == nil || len(keyResp.RRset.RRs) == 0 {
			continue
		}

		found = true
		allKeys = append(allKeys, keyResp.RRset.RRs...)
		if !keyResp.Validated {
			allValidated = false
		}
	}

	if !found {
		return nil, false, fmt.Errorf("no KEY records found at _signal names for %s", childZone)
	}

	return allKeys, allValidated, nil
}

// VerifyChildKey checks whether a child's KEY (identified by keyRR string) can
// be found via the configured verification mechanisms (at-apex, at-ns). Returns
// true if any mechanism succeeds (key found + optionally DNSSEC-validated).
func VerifyChildKey(ctx context.Context, childZone string, keyRR string, imr *Imr) (verified bool, dnssecValidated bool) {
	mechanisms := DelegationSyncConfig().Parent.Update.KeyVerification.Mechanisms
	if len(mechanisms) == 0 {
		mechanisms = []string{"at-apex", "at-ns"}
	}

	// Try each mechanism in order. Stop as soon as we have a DNSSEC-validated
	// match. If a mechanism finds the key without DNSSEC validation, remember
	// that but keep trying — a later mechanism may provide validation.
	foundUnvalidated := false

	for _, mech := range mechanisms {
		switch mech {
		case "at-apex":
			keys, validated, err := LookupChildKeyAtApex(ctx, childZone, imr)
			if err != nil {
				lgSigner.Debug("VerifyChildKey: at-apex failed", "zone", childZone, "err", err)
				continue
			}
			if matchKeyRR(keys, keyRR) {
				lgSigner.Info("VerifyChildKey: key found via at-apex", "zone", childZone, "dnssec", validated)
				if validated {
					return true, true
				}
				foundUnvalidated = true
			} else {
				lgSigner.Debug("VerifyChildKey: key not found in at-apex results", "zone", childZone)
			}

		case "at-ns":
			keys, validated, err := LookupChildKeyAtSignal(ctx, childZone, imr)
			if err != nil {
				lgSigner.Debug("VerifyChildKey: at-ns failed", "zone", childZone, "err", err)
				continue
			}
			if matchKeyRR(keys, keyRR) {
				lgSigner.Info("VerifyChildKey: key found via at-ns (_signal)", "zone", childZone, "dnssec", validated)
				if validated {
					return true, true
				}
				foundUnvalidated = true
			} else {
				lgSigner.Debug("VerifyChildKey: key not found in at-ns results", "zone", childZone)
			}
		}
	}

	return foundUnvalidated, false
}

// matchKeyRR checks if any of the RRs match the given keyRR string.
func matchKeyRR(rrs []dns.RR, keyRR string) bool {
	for _, rr := range rrs {
		if rr.String() == keyRR {
			return true
		}
	}
	return false
}

// TriggerChildKeyVerification starts an async verification of a child KEY
// that was just stored in the TrustStore. It uses the KeyBootstrapper's
// retry pattern: verify via DNS lookup, retry with backoff, then trust.
func (kdb *KeyDB) TriggerChildKeyVerification(childZone string, keyid uint16, keyRR string) {
	go func() {
		maxAttempts := DelegationSyncConfig().Parent.Update.KeyVerification.MaxAttempts
		if maxAttempts == 0 {
			maxAttempts = 5
		}
		retryInterval := DelegationSyncConfig().Parent.Update.KeyVerification.RetryInterval
		if retryInterval == 0 {
			retryInterval = 10 * time.Second
		}

		ctx := context.Background()

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			imr := Globals.ImrEngine
			if imr == nil {
				lgSigner.Warn("TriggerChildKeyVerification: IMR engine not yet available, will retry",
					"zone", childZone, "keyid", keyid, "attempt", attempt)
				if attempt < maxAttempts {
					time.Sleep(retryInterval)
					retryInterval *= 2
				}
				continue
			}

			lgSigner.Info("verifying child key via DNS",
				"zone", childZone, "keyid", keyid, "attempt", attempt, "max", maxAttempts)

			verified, dnssecValidated := VerifyChildKey(ctx, childZone, keyRR, imr)

			// Default true; only an explicit false turns it off. The pointer
			// preserves the distinction the viper reader made with its
			// nil-check: absent and false are different answers here, and
			// collapsing them would silently downgrade key verification on
			// every config that does not mention the key.
			requireDnssec := true
			if rd := DelegationSyncConfig().Parent.Update.KeyVerification.RequireDnssec; rd != nil {
				requireDnssec = *rd
			}

			accepted := verified && (!requireDnssec || dnssecValidated)

			if verified && !accepted {
				lgSigner.Info("child key found but not DNSSEC-validated, require-dnssec is true, will retry",
					"zone", childZone, "keyid", keyid, "attempt", attempt)
			}

			if accepted {
				// Update TrustStore: mark as validated + trusted.
				tx, err := kdb.Begin("VerifyChildKey")
				if err != nil {
					lgSigner.Error("TriggerChildKeyVerification: failed to begin tx", "err", err)
					return
				}

				tppost := TruststorePost{
					SubCommand:      "verify",
					Keyname:         childZone,
					Keyid:           int(keyid),
					DnssecValidated: dnssecValidated,
				}
				_, err = kdb.Sig0TrustMgmt(tx, tppost)
				if err != nil {
					lgSigner.Error("TriggerChildKeyVerification: failed to update TrustStore", "err", err)
					tx.Rollback()
					return
				}
				if err := tx.Commit(); err != nil {
					lgSigner.Error("TriggerChildKeyVerification: failed to commit", "err", err)
					return
				}

				lgSigner.Info("child key verified and trusted",
					"zone", childZone, "keyid", keyid, "dnssec", dnssecValidated)
				return
			}

			if attempt < maxAttempts {
				lgSigner.Info("child key not yet verifiable, will retry",
					"zone", childZone, "keyid", keyid, "delay", retryInterval)
				time.Sleep(retryInterval)
				retryInterval *= 2 // exponential backoff
			}
		}

		lgSigner.Warn("child key verification exhausted all attempts",
			"zone", childZone, "keyid", keyid)
	}()
}
