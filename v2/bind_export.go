/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Rendering keystore private keys as bind9 `Private-key-format: v1.3` text,
 * for `keystore <class> export --format bind` and the bulk equivalent.
 *
 * This is the missing half of a conversion that was one-way: `import` and
 * `bulk-convert` bring bind key files in, but everything on the way out was
 * written as the PKCS#8 PEM the keystore column holds. An export directory
 * therefore LOOKED like a bind key directory -- K<name>+<alg>+<tag> filenames,
 * a .key half in zone-file presentation format -- right up until something
 * opened the .private.
 *
 * This lives daemon-side, and must. (*dns.DNSKEY).PrivateKeyString renders
 * RSA, ECDSA and ED25519 from explicit type cases, but every other algorithm
 * goes through the process-wide algorithm registry -- and tdns-cli
 * deliberately registers NO implementations (see cmdv2/cli/algs.list: it is a
 * management tool, and an empty list keeps it pure Go, with no liboqs, SQIsign
 * or QR-UOV). Rendering in the CLI would therefore have worked for the
 * classical algorithms and failed for all sixteen PQ ones. The daemon links
 * the implementations it can sign with, so it is the only component that can
 * serialize their private keys.
 */
package tdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Accepted values for KeystorePost.KeyFormat.
const (
	KeyFormatPEM  = "pem"
	KeyFormatBind = "bind"
)

// ValidateKeyFormat rejects an unknown format before any key is read, so a
// typo cannot produce a half-written export directory.
func ValidateKeyFormat(f string) error {
	switch f {
	case "", KeyFormatPEM, KeyFormatBind:
		return nil
	default:
		return fmt.Errorf("unknown key format %q (want %q or %q)", f, KeyFormatPEM, KeyFormatBind)
	}
}

// BindPrivateKeyText renders one stored PKCS#8 PEM private key as bind's
// Private-key-format text.
//
// The algorithm comes from the public RR, not from the private key's Go type.
// The PEM carries no DNSSEC algorithm number, and the type does not determine
// one either: ECDSAP256SHA256 and ECDSAP384SHA384 are both *ecdsa.PrivateKey,
// and PrivateKeyString needs the number to pick the right integer width.
func BindPrivateKeyText(keyRR, privPEM string) (string, error) {
	rr, err := dns.NewRR(strings.TrimSpace(keyRR))
	if err != nil {
		return "", fmt.Errorf("unparsable public key RR: %v", err)
	}
	var k *dns.DNSKEY
	switch t := rr.(type) {
	case *dns.DNSKEY:
		k = t
	case *dns.KEY:
		k = &t.DNSKEY
	default:
		return "", fmt.Errorf("public key RR is %T, want DNSKEY or KEY", rr)
	}

	priv, err := PEMToPrivateKey(privPEM)
	if err != nil {
		return "", fmt.Errorf("unusable stored private key: %v", err)
	}

	out := k.PrivateKeyString(priv)
	if out == "" {
		// PrivateKeyString signals every failure the same way, by returning
		// the empty string: an algorithm with no registered implementation in
		// this binary, one whose implementation cannot marshal its private
		// key, and a key of the wrong type for the algorithm all look alike
		// here. Whichever it is, writing that empty string out is the one
		// thing we must not do -- an empty .private parses as nothing and
		// fails at signing time, far from the export that produced it.
		// bulk-import refuses the mirror image of this on the way in.
		return "", fmt.Errorf("algorithm %d (%s) has no bind private-key representation "+
			"in this daemon: it is either not registered here, or unable to marshal its private key",
			k.Algorithm, dns.AlgorithmToString[k.Algorithm])
	}
	return out, nil
}

// BindTimingTags renders the keystore's per-key timestamps as bind's timing
// tags, to be appended to the Private-key-format body.
//
// Only the three the keystore actually records are emitted. An absent
// timestamp produces no tag at all: bind reads a missing tag as "not
// recorded", which is true, whereas any value we invented would assert an
// event that never happened. ParseBindKeyTimes treats the two the same way on
// the way in.
//
// Created and Delete have no keystore column, and Revoke, DSPublish and
// SyncPublish describe events tdns does not track per key. They are omitted
// rather than approximated.
func BindTimingTags(publishedAt, activeAt, retiredAt string) (string, error) {
	var b strings.Builder
	for _, tag := range []struct{ name, value string }{
		{"Publish", publishedAt},
		{"Activate", activeAt},
		// bind's Inactive is "no longer signing", which is what the keystore
		// calls retired.
		{"Inactive", retiredAt},
	} {
		if strings.TrimSpace(tag.value) == "" {
			continue
		}
		bt, err := RFC3339ToBindTime(tag.value)
		if err != nil {
			return "", fmt.Errorf("%s: %v", tag.name, err)
		}
		fmt.Fprintf(&b, "%s: %s\n", tag.name, bt)
	}
	return b.String(), nil
}

// PrivateKeyForExport returns the bytes to put in a .private file in the
// requested format. Timestamps are optional and ignored for PEM; an empty
// format means PEM, so a caller that has not been taught about formats keeps
// its existing behaviour.
func PrivateKeyForExport(format, keyRR, privPEM, publishedAt, activeAt, retiredAt string) (string, error) {
	if format != KeyFormatBind {
		return privPEM, nil
	}
	body, err := BindPrivateKeyText(keyRR, privPEM)
	if err != nil {
		return "", err
	}
	times, err := BindTimingTags(publishedAt, activeAt, retiredAt)
	if err != nil {
		return "", err
	}
	return body + times, nil
}
