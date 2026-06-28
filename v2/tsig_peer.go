/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// tsigFudge is the TSIG time-window slack, in seconds (RFC 8945 default 300).
const tsigFudge = 300

// tsigKeyProvider adapts the live TsigKeyStore to the dns.TsigProvider interface,
// so signing and verifying always consult the current keystore (including keys
// upserted by the dynamic-zone API) rather than a static snapshot. It mirrors the
// vendored library's built-in HMAC provider, parameterised by the secret looked
// up via the TSIG RR's key name; matching the library byte-for-byte is what makes
// it interoperate with BIND/NSD peers.
type tsigKeyProvider struct{ store *TsigKeyStore }

func (p tsigKeyProvider) hmac(t *dns.TSIG) (hash.Hash, error) {
	d, ok := p.store.Get(t.Hdr.Name) // Get canonicalises the wire name
	if !ok {
		return nil, dns.ErrSecret
	}
	rawsecret, err := base64.StdEncoding.DecodeString(d.Secret)
	if err != nil {
		return nil, err
	}
	switch dns.CanonicalName(t.Algorithm) {
	case dns.HmacSHA1:
		return hmac.New(sha1.New, rawsecret), nil
	case dns.HmacSHA224:
		return hmac.New(sha256.New224, rawsecret), nil
	case dns.HmacSHA256:
		return hmac.New(sha256.New, rawsecret), nil
	case dns.HmacSHA384:
		return hmac.New(sha512.New384, rawsecret), nil
	case dns.HmacSHA512:
		return hmac.New(sha512.New, rawsecret), nil
	default:
		return nil, dns.ErrKeyAlg
	}
}

func (p tsigKeyProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	h, err := p.hmac(t)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

func (p tsigKeyProvider) Verify(msg []byte, t *dns.TSIG) error {
	b, err := p.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(b, mac) {
		return dns.ErrSig
	}
	return nil
}

// tsigProvider returns a dns.TsigProvider backed by this server's TSIG key store.
// Set it on dns.Client / dns.Transfer (outbound) and dns.Server (inbound verify).
func (conf *Config) tsigProvider() dns.TsigProvider {
	return tsigKeyProvider{conf.Internal.TsigKeyStore}
}

// SignForPeer prepares msg for TSIG signing under keyName and returns the
// provider to set on the dns.Client / dns.Transfer. keyName == NOKEY (or the
// empty string) is a no-op: it returns (nil, nil) and the caller signs nothing.
// An unknown key name is an error (it should have been caught at config
// validation). The key's algorithm comes from the keystore; the wire name and
// algorithm are canonicalised (lowercase FQDN) per RFC 8945.
func SignForPeer(msg *dns.Msg, keyName string, conf *Config) (dns.TsigProvider, error) {
	if keyName == "" || keyName == NOKEY {
		return nil, nil
	}
	d, ok := conf.Internal.TsigKeyStore.Get(keyName)
	if !ok {
		return nil, fmt.Errorf("TSIG key %q not found in keys store", keyName)
	}
	msg.SetTsig(dns.CanonicalName(keyName), dns.CanonicalName(d.Algorithm), tsigFudge, time.Now().Unix())
	return conf.tsigProvider(), nil
}

// peerIP reduces a "host:port" (or bare "host") address to its IP for ACL
// matching. The inbound RemoteAddr()'s ephemeral source port is irrelevant, so it
// is dropped. Returns (zero, false) if no valid IP can be parsed.
func peerIP(addr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(addr); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}
