/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// storedKeyPair produces a key pair the way the keystore holds it: a DNSKEY RR
// for the public half, PKCS#8 PEM for the private one.
func storedKeyPair(t *testing.T, alg uint8, bits int) (keyRR, privPEM string, priv any) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: alg,
	}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	return k.String(), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), priv
}

// A key exported in bind format must parse back to the key that went in.
// Without this the two directions can drift apart silently: the export
// produces a file that looks right, and the failure surfaces only when
// something tries to sign with it.
func TestBindPrivateKeyTextRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  uint8
		bits int
	}{
		{"ED25519", dns.ED25519, 256},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, 256},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384, 384},
		{"RSASHA256", dns.RSASHA256, 2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyRR, privPEM, orig := storedKeyPair(t, tc.alg, tc.bits)

			out, err := BindPrivateKeyText(keyRR, privPEM)
			if err != nil {
				t.Fatalf("BindPrivateKeyText: %v", err)
			}
			if !strings.HasPrefix(out, "Private-key-format: v1.3") {
				t.Errorf("output does not start with the bind format header:\n%s", out)
			}

			rr, err := dns.NewRR(keyRR)
			if err != nil {
				t.Fatalf("NewRR: %v", err)
			}
			back, err := rr.(*dns.DNSKEY).NewPrivateKey(out)
			if err != nil {
				t.Fatalf("re-parsing the exported key: %v", err)
			}

			switch o := orig.(type) {
			case ed25519.PrivateKey:
				b, ok := back.(ed25519.PrivateKey)
				if !ok || !o.Equal(b) {
					t.Error("ed25519 key changed across the round trip")
				}
			case *ecdsa.PrivateKey:
				b, ok := back.(*ecdsa.PrivateKey)
				if !ok || o.D.Cmp(b.D) != 0 {
					t.Error("ecdsa key changed across the round trip")
				}
			case *rsa.PrivateKey:
				b, ok := back.(*rsa.PrivateKey)
				if !ok || o.D.Cmp(b.D) != 0 {
					t.Error("rsa key changed across the round trip")
				}
			default:
				t.Fatalf("unexpected key type %T", orig)
			}
		})
	}
}

// A timestamp the keystore does not hold must produce no tag at all. bind reads
// a missing tag as "not recorded"; a fabricated one asserts an event.
func TestBindTimingTags(t *testing.T) {
	got, err := BindTimingTags("2026-01-02T03:04:05Z", "", "2026-03-04T05:06:07Z")
	if err != nil {
		t.Fatalf("BindTimingTags: %v", err)
	}
	if !strings.Contains(got, "Publish: 20260102030405\n") {
		t.Errorf("Publish tag missing or malformed:\n%s", got)
	}
	if strings.Contains(got, "Activate:") {
		t.Errorf("empty timestamp produced a tag:\n%s", got)
	}
	if !strings.Contains(got, "Inactive: 20260304050607\n") {
		t.Errorf("Inactive tag missing or malformed:\n%s", got)
	}

	if _, err := BindTimingTags("not a timestamp", "", ""); err == nil {
		t.Error("an unparsable timestamp was accepted")
	}
}

// RFC3339ToBindTime and BindTimeToRFC3339 must agree, including on the empty
// value: "not recorded" is a distinct fact from any particular time.
func TestBindTimeRoundTrips(t *testing.T) {
	const bindT = "20260102030405"
	rfc, err := BindTimeToRFC3339(bindT)
	if err != nil {
		t.Fatalf("BindTimeToRFC3339: %v", err)
	}
	back, err := RFC3339ToBindTime(rfc)
	if err != nil {
		t.Fatalf("RFC3339ToBindTime: %v", err)
	}
	if back != bindT {
		t.Errorf("round trip changed %q to %q", bindT, back)
	}
	if got, err := RFC3339ToBindTime(""); err != nil || got != "" {
		t.Errorf(`empty became %q (err %v); it must stay empty`, got, err)
	}
}

// Every failure must be an error, never a shorter file. An empty or truncated
// .private parses as nothing and fails later, at signing time, far from the
// export that produced it.
func TestBindExportFailsRatherThanWritingNothing(t *testing.T) {
	_, privPEM, _ := storedKeyPair(t, dns.ED25519, 256)

	for _, tc := range []struct{ name, keyRR, pem string }{
		{"unparsable RR", "this is not a resource record", privPEM},
		{"wrong RR type", "example. 3600 IN A 192.0.2.1", privPEM},
		{"unusable PEM", "example. 3600 IN DNSKEY 257 3 15 " +
			"aIufB25wu/A9nLOZOm7ZlAxkdQyeCqAQcH7wMCg8DVo=",
			"-----BEGIN PRIVATE KEY-----\nbroken\n-----END PRIVATE KEY-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := BindPrivateKeyText(tc.keyRR, tc.pem)
			if err == nil {
				t.Fatalf("accepted bad input, returning %q", out)
			}
			if out != "" {
				t.Errorf("returned content alongside an error: %q", out)
			}
		})
	}
}

// NOTE on the empty-string guard in BindPrivateKeyText: it is not reachable
// from this package's test binary, and the attempt to reach it is instructive.
// PrivateKeyString dispatches on the key's Go TYPE before consulting the
// registry, so an ed25519 key renders happily under any algorithm number. A
// genuine PQ key cannot be built here either: with no codec registered,
// PEMToPrivateKey rejects its PKCS#8 before the guard is reached. The guard
// covers the daemon case where the codec parses but the implementation cannot
// render -- exercised in production, not here.

// The default format must hand back exactly what the keystore holds, so the
// existing export/bulk-import round trip is untouched by this change. An empty
// format means the same thing, for callers not yet taught about formats.
func TestPrivateKeyForExportPEMIsVerbatim(t *testing.T) {
	keyRR, privPEM, _ := storedKeyPair(t, dns.ED25519, 256)

	for _, format := range []string{KeyFormatPEM, ""} {
		got, err := PrivateKeyForExport(format, keyRR, privPEM, "2026-01-02T03:04:05Z", "", "")
		if err != nil {
			t.Fatalf("PrivateKeyForExport(%q): %v", format, err)
		}
		if got != privPEM {
			t.Errorf("format %q altered the stored key", format)
		}
	}

	bindOut, err := PrivateKeyForExport(KeyFormatBind, keyRR, privPEM, "2026-01-02T03:04:05Z", "", "")
	if err != nil {
		t.Fatalf("PrivateKeyForExport(bind): %v", err)
	}
	if !strings.Contains(bindOut, "Publish: 20260102030405") {
		t.Errorf("bind format dropped the timing tag:\n%s", bindOut)
	}
}

func TestValidateKeyFormat(t *testing.T) {
	for _, ok := range []string{KeyFormatPEM, KeyFormatBind, ""} {
		if err := ValidateKeyFormat(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	if err := ValidateKeyFormat("bind9"); err == nil {
		t.Error("a typo in the format was accepted; it would surface as a half-written export")
	}
}
