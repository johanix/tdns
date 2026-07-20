/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * XoT (XFR-over-TLS, RFC 9103) support: SPKI pinning helpers and the
 * client-side verifying TLS configuration builder.
 */
package tdns

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// SPKISHA256 returns the base64 (standard encoding) SHA-256 digest of the
// certificate's SubjectPublicKeyInfo. This is the value used for static
// certificate pinning (tls-auth: pin) and matches the digest carried in a
// TLSA 3-1-1 record (which encodes the same bytes in hex).
func SPKISHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
