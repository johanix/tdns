/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// authenticateDsyncApiClientCert resolves a presented client certificate to a
// DsyncApiCredential using the identity walk in the implementation plan (D2).
//
// Failure is undifferentiated: unknown identity, disabled, expired, and failed
// chain verification all return the same error. The caller answers 401.
func authenticateDsyncApiClientCert(kdb *KeyDB, zone string, r *http.Request, ca *DsyncApiClientAuthConf) (*DsyncApiCredential, error) {
	if ca == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("authentication failed")
	}
	leaf := r.TLS.PeerCertificates[0]
	presented := r.TLS.PeerCertificates[1:]

	for _, mech := range ca.Mechanisms {
		cred, err := authenticateDsyncApiClientCertMech(kdb, zone, mech, leaf, presented, ca.CAFile)
		if err != nil {
			return nil, err
		}
		if cred != nil {
			return cred, nil
		}
	}
	return nil, fmt.Errorf("authentication failed")
}

func authenticateDsyncApiClientCertMech(kdb *KeyDB, zone, mech string, leaf *x509.Certificate, presented []*x509.Certificate, caFile string) (*DsyncApiCredential, error) {
	switch mech {
	case DsyncApiAuthTLSPin:
		row, err := kdb.LookupDsyncApiCertCredential(zone, mech, SPKISHA256(leaf))
		if err != nil {
			return nil, err
		}
		if row == nil {
			return nil, nil
		}
		if !row.Usable(time.Now()) {
			lgDsyncApi.Warn("DSYNC API certificate credential refused",
				"zone", zone, "mech", mech, "identity", row.Identity,
				"disabled", row.Disabled, "expired", row.Expired(time.Now()))
			return nil, fmt.Errorf("authentication failed")
		}
		cred := row.asDsyncApiCredential()
		return &cred, nil

	case DsyncApiAuthTLSPkix:
		for _, name := range leaf.DNSNames {
			identity := core.CanonicalizeName(dns.Fqdn(name))
			row, err := kdb.LookupDsyncApiCertCredential(zone, mech, identity)
			if err != nil {
				return nil, err
			}
			if row == nil {
				continue
			}
			if err := verifyClientCertPKIX(leaf, presented, caFile, identity); err != nil {
				lgDsyncApi.Warn("DSYNC API tls-pkix verification failed",
					"zone", zone, "identity", identity, "err", err)
				continue
			}
			if !row.Usable(time.Now()) {
				lgDsyncApi.Warn("DSYNC API certificate credential refused",
					"zone", zone, "mech", mech, "identity", row.Identity,
					"disabled", row.Disabled, "expired", row.Expired(time.Now()))
				return nil, fmt.Errorf("authentication failed")
			}
			cred := row.asDsyncApiCredential()
			return &cred, nil
		}
		return nil, nil

	default:
		// Unknown names are a config error and are refused at load.
		return nil, nil
	}
}
