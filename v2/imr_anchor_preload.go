/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

// loadConfiguredTrustAnchors puts the configured trust anchors into the DNSKEY
// cache without touching the network: DNSKEY anchors directly, DS anchors as a
// seeded DS RRset. InitImrEngine calls it before priming, so the root that
// priming fetches is validated against the anchor instead of against nothing.
//
// initializeImrTrustAnchors, which runs once the cache is primed, loads the same
// anchors again (harmless: both writes are idempotent) before fetching and
// validating the anchored zones' DNSKEY RRsets.
func (imr *Imr) loadConfiguredTrustAnchors(conf *Config) {
	if imr == nil || imr.Cache == nil || conf == nil {
		return
	}
	dsByName, dnskeysByName, err := imr.parseTrustAnchorsFromConfig(conf)
	if err != nil {
		// initializeImrTrustAnchors fails on the same error and reports it.
		lgImr.Debug("trust anchors not loaded before priming", "err", err)
		return
	}
	imr.addDirectDNSKEYTrustAnchors(dnskeysByName)
	for name, dslist := range dsByName {
		if len(dslist) > 0 {
			imr.seedDSRRsetFromTrustAnchors(name, dslist)
		}
	}
}
