/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The "sig0key" JWK parameter: a SIG(0) key as a JWK.
 *
 * A SIG(0) key is a KEY RR, not a DNSKEY. tdns makes its KEY RRs with
 * flags 256 and protocol 3, so a JWK carrying them in "dnskey" would import
 * into any DNSSEC signer as a ZSK. "sig0key" carries the same members as
 * "dnskey" (the KEY RR has the same RDATA layout) under a name a DNSSEC
 * consumer does not know: it ignores the member, finds no "dnskey", and
 * rejects the key (draft section 2.6, rule 1). That is the fail-safe this
 * parameter exists for. A JWK carries exactly one of the two.
 *
 * The name is tdns's proposal to the draft's author; it is not in the
 * draft (yet) and needs its own IANA registration.
 */

package core

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

var (
	ErrSig0KeyParamMissing = errors.New("dnssec jwk: no \"sig0key\" parameter")
	ErrBothKeyParams       = errors.New("dnssec jwk: both \"dnskey\" and \"sig0key\"")
	ErrNoKeyParam          = errors.New("dnssec jwk: neither \"dnskey\" nor \"sig0key\"")
)

// parseKeyParams reads whichever of "dnskey" and "sig0key" data has, and
// the key material. Both present is an error.
func parseKeyParams(data []byte) (*DNSSECJWK, error) {
	m, err := parseJWKMembers(data)
	if err != nil {
		return nil, err
	}
	rawDK, hasDK := m["dnskey"]
	rawS0, hasS0 := m["sig0key"]
	if hasDK && hasS0 {
		return nil, ErrBothKeyParams
	}
	d := &DNSSECJWK{Key: new(JSONWebKey)}
	if hasDK {
		if d.DNSKEY, err = parseDNSKEYParam(rawDK, "dnskey"); err != nil {
			return nil, err
		}
	}
	if hasS0 {
		if d.Sig0Key, err = parseDNSKEYParam(rawS0, "sig0key"); err != nil {
			return nil, err
		}
	}
	if err := d.Key.fromMembers(m); err != nil {
		return nil, err
	}
	return d, nil
}

// ParseSIG0JWK parses a SIG(0) JWK and applies the draft's five import
// rules to its "sig0key" parameter, returning the KEY RR. A JWK with
// "dnskey" (alone or beside "sig0key") is refused.
func ParseSIG0JWK(data []byte) (*DNSSECJWK, *dns.KEY, error) {
	d, err := parseKeyParams(data)
	if err != nil {
		return nil, nil, err
	}
	if d.Sig0Key == nil {
		if d.DNSKEY != nil {
			return nil, nil, fmt.Errorf("%w: the JWK is a DNSSEC key (\"dnskey\")", ErrSig0KeyParamMissing)
		}
		return nil, nil, ErrSig0KeyParamMissing
	}
	rr, err := d.ToKEY()
	if err != nil {
		return nil, nil, err
	}
	return d, rr, nil
}

// ParseKeyJWK parses a JWK that carries either "dnskey" or "sig0key" and
// returns a *dns.DNSKEY or a *dns.KEY accordingly. Neither or both is an
// error.
func ParseKeyJWK(data []byte) (*DNSSECJWK, dns.RR, error) {
	d, err := parseKeyParams(data)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case d.DNSKEY != nil:
		rr, err := d.ToDNSKEY()
		if err != nil {
			return nil, nil, err
		}
		return d, rr, nil
	case d.Sig0Key != nil:
		rr, err := d.ToKEY()
		if err != nil {
			return nil, nil, err
		}
		return d, rr, nil
	}
	return nil, nil, ErrNoKeyParam
}

// ToKEY applies rules 2 to 5 to a SIG(0) JWK and returns its KEY RR.
func (d *DNSSECJWK) ToKEY() (*dns.KEY, error) {
	if d.DNSKEY != nil && d.Sig0Key != nil {
		return nil, ErrBothKeyParams
	}
	if d.Sig0Key == nil {
		return nil, ErrSig0KeyParamMissing
	}
	if err := d.Sig0Key.check(); err != nil {
		return nil, err
	}
	rr, err := buildKeyRR(d.Key, d.Sig0Key, dns.TypeKEY)
	if err != nil {
		return nil, err
	}
	return &dns.KEY{DNSKEY: *rr}, nil
}

// NewSIG0JWK builds a SIG(0) JWK from a KEY RR, flags kept as stored. With
// priv nil it is the public key; otherwise priv is the private JWK, as for
// NewDNSSECJWK. kid and keytag are always set.
func NewSIG0JWK(rr *dns.KEY, priv *JSONWebKey) (*DNSSECJWK, error) {
	if rr == nil {
		return nil, fmt.Errorf("%w: nil RR", ErrDNSKEYPublicKey)
	}
	if t := rr.Hdr.Rrtype; t != 0 && t != dns.TypeKEY {
		return nil, fmt.Errorf("%w: RR type %s is not KEY", ErrDNSKEYParamMalformed, dns.TypeToString[t])
	}
	p, pub, err := paramFromKeyRR(&rr.DNSKEY)
	if err != nil {
		return nil, err
	}
	k, err := withPrivate(pub, priv)
	if err != nil {
		return nil, err
	}
	return &DNSSECJWK{Key: k, Sig0Key: p}, nil
}
