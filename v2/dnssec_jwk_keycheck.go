/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Rule 5 of draft-schlyter-dnsop-dnssec-jwk (a private key must match its
 * public key) for the key types core cannot check with the standard
 * library: Ed448 and ML-DSA. core stays free of CIRCL so that the modules
 * importing it (tdns-mp, tdns-transport, v2/cache, v2/edns0) do not gain
 * the dependency; this package links CIRCL already for signing, so every
 * tdns daemon and CLI gets the checks from here.
 */

package tdns

import (
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	core "github.com/johanix/tdns/v2/core"
)

func jwkSeed32(alg string, priv []byte) (*[32]byte, error) {
	var s [32]byte
	if len(priv) != len(s) {
		return nil, fmt.Errorf("%s seed is %d octets, want %d", alg, len(priv), len(s))
	}
	copy(s[:], priv)
	return &s, nil
}

func init() {
	core.RegisterJWKKeyPairCheck(core.JWKKtyOKP, core.JWKCrvEd448, func(priv []byte) ([]byte, error) {
		if len(priv) != ed448.SeedSize {
			return nil, fmt.Errorf("Ed448 private key is %d octets, want %d", len(priv), ed448.SeedSize)
		}
		return ed448.NewKeyFromSeed(priv).Public().(ed448.PublicKey), nil
	})
	core.RegisterJWKKeyPairCheck(core.JWKKtyAKP, core.JWKAlgMLDSA44, func(priv []byte) ([]byte, error) {
		s, err := jwkSeed32(core.JWKAlgMLDSA44, priv)
		if err != nil {
			return nil, err
		}
		pk, _ := mldsa44.NewKeyFromSeed(s)
		return pk.Bytes(), nil
	})
	core.RegisterJWKKeyPairCheck(core.JWKKtyAKP, core.JWKAlgMLDSA65, func(priv []byte) ([]byte, error) {
		s, err := jwkSeed32(core.JWKAlgMLDSA65, priv)
		if err != nil {
			return nil, err
		}
		pk, _ := mldsa65.NewKeyFromSeed(s)
		return pk.Bytes(), nil
	})
	core.RegisterJWKKeyPairCheck(core.JWKKtyAKP, core.JWKAlgMLDSA87, func(priv []byte) ([]byte, error) {
		s, err := jwkSeed32(core.JWKAlgMLDSA87, priv)
		if err != nil {
			return nil, err
		}
		pk, _ := mldsa87.NewKeyFromSeed(s)
		return pk.Bytes(), nil
	})
}
