/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// A PEM private key that is not unencrypted PKCS#8 must be refused by its
// block type. Each of these used to fall through to the bind parser and come
// back as "dns: no private key seen", which says nothing about what to do.
func TestPrepareKeyCacheRefusesNonPKCS8PEM(t *testing.T) {
	rsaRR, rsaPKCS8 := genDnskey(t, "example.", 257, dns.RSASHA256)
	ecRR, ecPKCS8 := genDnskey(t, "example.", 257, dns.ECDSAP256SHA256)

	rsaPriv, err := PEMToPrivateKey(rsaPKCS8)
	if err != nil {
		t.Fatalf("parse RSA PKCS#8: %v", err)
	}
	ecPriv, err := PEMToPrivateKey(ecPKCS8)
	if err != nil {
		t.Fatalf("parse EC PKCS#8: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecPriv.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("marshal SEC1: %v", err)
	}
	ecBlock, _ := pem.Decode([]byte(ecPKCS8))

	cases := []struct {
		blockType string
		der       []byte
		rr        *dns.DNSKEY
	}{
		{"RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaPriv.(*rsa.PrivateKey)), rsaRR},
		{"EC PRIVATE KEY", sec1, ecRR},
		// The refusal is on the block type, so the body need not really be
		// encrypted.
		{"ENCRYPTED PRIVATE KEY", ecBlock.Bytes, ecRR},
	}
	for _, c := range cases {
		t.Run(c.blockType, func(t *testing.T) {
			privkey := string(pem.EncodeToMemory(&pem.Block{Type: c.blockType, Bytes: c.der}))
			_, err := PrepareKeyCache(privkey, c.rr.String())
			if err == nil {
				t.Fatalf("a %s block was accepted", c.blockType)
			}
			msg := err.Error()
			if !strings.Contains(msg, strconv.Quote(c.blockType)) || !strings.Contains(msg, "PKCS#8") {
				t.Fatalf("error must name the block type and PKCS#8: %v", err)
			}
		})
	}

	// The same keys as PKCS#8 still go through.
	for _, k := range []struct {
		pem string
		rr  *dns.DNSKEY
	}{{rsaPKCS8, rsaRR}, {ecPKCS8, ecRR}} {
		if _, err := PrepareKeyCache(k.pem, k.rr.String()); err != nil {
			t.Fatalf("PKCS#8 key refused: %v", err)
		}
	}
}
