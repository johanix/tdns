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

// notifyKeyFor returns the TSIG key name to sign an outbound NOTIFY to target,
// found by matching target's IP against the zone's notify peers (IP-only — the
// configured and actual ports may differ). NOKEY when no peer matches (e.g. a
// parent NOTIFY for CSYNC/CDS, which has no notify: entry).
func (zd *ZoneData) notifyKeyFor(target string) string {
	tip, ok := peerIP(target)
	if !ok {
		return NOKEY
	}
	for _, p := range zd.Notify {
		if pip, ok := peerIP(p.Addr); ok && pip == tip {
			return p.Key
		}
	}
	return NOKEY
}

// checkInboundTSIG verifies that an inbound request — already ACL-allowed — carries
// the TSIG the ACL requires. requiredKey == NOKEY (or "") accepts the request as
// is, signed or not. For a named key, the request must carry a TSIG RR naming that
// key (canonical compare) and the server's TsigProvider must have validated the
// MAC, which the library records in w.TsigStatus(). Returns nil on success, else a
// reason error for the caller to log. The provider must be set on the dns.Server
// (conf.tsigProvider()) or w.TsigStatus() is meaningless.
func checkInboundTSIG(w dns.ResponseWriter, r *dns.Msg, requiredKey string) error {
	if requiredKey == "" || requiredKey == NOKEY {
		return nil
	}
	ts := r.IsTsig()
	if ts == nil {
		return fmt.Errorf("TSIG required (key %q) but request is unsigned", requiredKey)
	}
	if status := w.TsigStatus(); status != nil {
		return fmt.Errorf("TSIG verification failed: %w", status)
	}
	if dns.CanonicalName(ts.Hdr.Name) != dns.CanonicalName(requiredKey) {
		return fmt.Errorf("TSIG signed with key %q but ACL requires %q", ts.Hdr.Name, requiredKey)
	}
	return nil
}

// signResponseLikeRequest mirrors a verified request's TSIG onto a single-message
// response so the server's WriteMsg fills in the response MAC (RFC 8945: a signed
// request gets a signed response). It is a no-op when the request was unsigned or
// its TSIG failed verification (w.TsigStatus() != nil) — matching the library's own
// Transfer.Out gate. Multi-message AXFR responses are handled by Transfer.Out
// directly and must NOT call this. The server must have a TsigProvider set for the
// MAC to actually be written.
func signResponseLikeRequest(w dns.ResponseWriter, req, resp *dns.Msg) {
	if ts := req.IsTsig(); ts != nil && w.TsigStatus() == nil {
		resp.SetTsig(ts.Hdr.Name, ts.Algorithm, ts.Fudge, time.Now().Unix())
	}
}

// allowNotifyDecision resolves the allow-notify ACL for an inbound NOTIFY's source
// IP. An empty ACL accepts (unsigned) from any configured primary's IP — so
// operators needn't restate the primary list — and ignores everything else. A
// non-empty ACL is matched verbatim (matchACL: BLOCKED/no-match => deny).
func (zd *ZoneData) allowNotifyDecision(src netip.Addr) (allowed bool, requiredKey string) {
	if len(zd.AllowNotify) == 0 {
		for _, p := range zd.Upstreams { // resolved primaries
			if pip, ok := peerIP(p.Addr); ok && pip == src {
				return true, NOKEY
			}
		}
		return false, ""
	}
	return matchACL(zd.AllowNotify, src)
}

// downstreamsDecision resolves the downstreams (provide-xfr) ACL for an inbound
// AXFR/IXFR's source IP. An empty ACL DENIES — a hard cutover that closes the
// legacy open-AXFR default (matchACL already returns (false,"") for an empty ACL).
func (zd *ZoneData) downstreamsDecision(src netip.Addr) (allowed bool, requiredKey string) {
	return matchACL(zd.Downstreams, src)
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
