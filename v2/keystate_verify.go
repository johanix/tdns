/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Child-side half of mutual authentication for the KeyState inquiry channel
// (draft-ietf-dnsop-delegation-mgmt-via-ddns-02 §"Mutual Authentication",
// §"Acquiring and Validating the UPDATE Receiver's Key", §"Authenticating
// Responses"; draft-berra-dnsop-keystate-03 §"KeyStates Set By The UPDATE
// Receiver").
//
// The parent's UPDATE Receiver signs every KeyState response with the SIG(0)
// key it publishes as a KEY RR at the DSYNC UPDATE target
// (keyStateResponseWriter, keystate.go). Without the checks here the child
// took whatever KEY-STATE code arrived over plain UDP at face value, so anyone
// able to inject a response could report the child's key as unknown and
// trigger a needless re-bootstrap, or as trusted and suppress a needed one.
//
// A response is AUTHENTICATED when its SIG(0) verifies with a receiver KEY the
// child has reason to trust, which is one of:
//
//   - a KEY for the receiver name in the child's truststore marked trusted
//     (manual bootstrap: `tdns-cli truststore sig0 add --child <target>
//     --src <keyfile>` followed by `... trust --keyid <id>`), or
//   - the KEY RRset published at the receiver name, when BOTH that lookup and
//     the DSYNC lookup that named the receiver were DNSSEC-validated. The
//     second half is not optional: the DSYNC target IS the receiver's
//     identity, so an unvalidated DSYNC would let a forged target pick which
//     (perfectly validly signed) zone's KEY the child ends up trusting.
//
// A response whose signature is present but FAILS -- wrong bytes, wrong
// signer name, outside its validity window -- is rejected unconditionally. So
// is one whose receiver KEY, or whose DSYNC target, came back DNSSEC-BOGUS: a
// chain that exists and fails is an attack signal, not an unsigned zone. A
// response that merely CANNOT be authenticated (unsigned, or signed with a key
// the child has no authenticated copy of, or an unsigned parent zone) is
// rejected by default and accepted, with a warning, only under
// delegationsync.child.update.allow-insecure, which is the draft's "subject
// to local policy" escape for unsigned parent zones -- and only for those.

// receiverKeyFetcher returns the KEY RRset published at the UPDATE Receiver's
// name (the DSYNC UPDATE target) and the DNSSEC verdict on that answer: Secure
// authenticates, Bogus refuses, anything else is "cannot authenticate".
// Injected so the verification logic can be tested without an IMR; the
// production fetcher is imrReceiverKeyFetcher.
type receiverKeyFetcher func(ctx context.Context, name string) (keys []dns.RR, state cache.ValidationState, err error)

// imrReceiverKeyFetcher looks the receiver KEY up through the IMR engine. The
// IMR caches the RRset with its validation state, so repeated inquiries do not
// re-query; a receiver key rollover becomes visible when the cached RRset
// expires.
func imrReceiverKeyFetcher(imr *Imr) receiverKeyFetcher {
	return func(ctx context.Context, name string) ([]dns.RR, cache.ValidationState, error) {
		if imr == nil {
			return nil, 0, errors.New("no IMR engine available")
		}
		resp, err := imr.ImrQuery(ctx, dns.Fqdn(name), dns.TypeKEY, dns.ClassINET, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("IMR query for %s KEY failed: %v", name, err)
		}
		if resp == nil || resp.Error {
			msg := "nil response"
			if resp != nil {
				msg = resp.ErrorMsg
			}
			return nil, 0, fmt.Errorf("IMR query for %s KEY returned error: %s", name, msg)
		}
		if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
			return nil, 0, fmt.Errorf("no KEY RRset published at %s", name)
		}
		return resp.RRset.RRs, resp.ValidationState, nil
	}
}

// receiverKeyTrust returns the child's manually trusted KEY for the receiver
// (name, keyid), if there is one. Injected for the same reason as
// receiverKeyFetcher; the production lookup is KeyDB.receiverKeyTrust.
type receiverKeyTrust func(name string, keyid uint16) (*dns.KEY, bool)

// receiverKeyTrust consults the truststore. Only a key explicitly marked
// trusted counts: `truststore sig0 add --src <file>` stores a key untrusted, and
// the operator's `trust` is the manual-bootstrap decision the draft describes.
func (kdb *KeyDB) receiverKeyTrust() receiverKeyTrust {
	return func(name string, keyid uint16) (*dns.KEY, bool) {
		if kdb == nil {
			return nil, false
		}
		sk, err := kdb.FindSig0TrustedKey(dns.Fqdn(name), keyid)
		if err != nil || sk == nil || !sk.Trusted {
			return nil, false
		}
		key := sk.Key
		return &key, true
	}
}

// keyStateSig0 returns the SIG(0) on r. RFC 2931 §3.1: the SIG(0) is the last
// RR of the additional section; miekg's SIG.Verify locates it there too, so a
// SIG anywhere else is not one this message can be verified with.
func keyStateSig0(r *dns.Msg) *dns.SIG {
	if r == nil || len(r.Extra) == 0 {
		return nil
	}
	sig, ok := r.Extra[len(r.Extra)-1].(*dns.SIG)
	if !ok || sig.TypeCovered != 0 {
		return nil
	}
	return sig
}

// matchingReceiverKey picks the KEY in rrs that sig was made with: same owner
// as the receiver, same key tag, same algorithm.
func matchingReceiverKey(rrs []dns.RR, receiver string, sig *dns.SIG) *dns.KEY {
	for _, rr := range rrs {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		if !core.EqualNames(key.Hdr.Name, receiver) {
			continue
		}
		if key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm {
			continue
		}
		return key
	}
	return nil
}

func receiverSigFailure(receiver string, sig *dns.SIG, err error) error {
	if errors.Is(err, dns.ErrTime) {
		return fmt.Errorf("KeyState response from %s: SIG(0) by keyid %d is outside its validity window (inception %s, expiration %s; clock skew?)",
			receiver, sig.KeyTag, dns.TimeToString(sig.Inception), dns.TimeToString(sig.Expiration))
	}
	return fmt.Errorf("KeyState response from %s: SIG(0) by keyid %d does not verify: %v", receiver, sig.KeyTag, err)
}

const allowInsecureKnob = "delegationsync.child.update.allow-insecure"

// verifyKeyStateResponse authenticates a KeyState response. wire is the
// response exactly as received (SIG(0) verification runs over the bytes the
// signer hashed, not over a re-pack), r its unpacked form, and target the
// DSYNC UPDATE target the inquiry was sent to: its Name is the receiver
// identity, its Validated / Bogus what the DSYNC lookup said about DNSSEC.
//
// It returns authenticated=true only when the signature verified with a
// trusted receiver key (see the file comment). With allowInsecure a response
// that cannot be authenticated is accepted (authenticated=false, err=nil) and
// logged; a response whose signature is present but wrong, or whose chain of
// trust is bogus, is rejected regardless of policy.
func verifyKeyStateResponse(ctx context.Context, wire []byte, r *dns.Msg, target *DsyncTarget,
	trust receiverKeyTrust, fetch receiverKeyFetcher, allowInsecure bool) (bool, error) {

	if target == nil {
		return false, errors.New("KeyState response: no DSYNC target to verify against")
	}
	receiver := dns.Fqdn(target.Name)

	sig := keyStateSig0(r)
	if sig == nil {
		if allowInsecure {
			lgDns.Warn("KeyState response is not SIG(0)-signed; acting on it because "+allowInsecureKnob+" is set",
				"receiver", receiver)
			return false, nil
		}
		return false, fmt.Errorf("KeyState response from %s is not SIG(0)-signed; the UPDATE Receiver MUST sign inquiry responses (set %s to act on unauthenticated responses)",
			receiver, allowInsecureKnob)
	}

	if !core.EqualNames(sig.SignerName, receiver) {
		return false, fmt.Errorf("KeyState response signed by %q, but the UPDATE Receiver is %q", sig.SignerName, receiver)
	}

	// 1. A manually trusted receiver key authenticates on its own: the
	// operator bound this exact (name, keyid) to the parent out of band, so
	// how the target name was discovered no longer matters.
	if trust != nil {
		if key, ok := trust(receiver, sig.KeyTag); ok {
			if err := sig0Verify(sig, key, wire); err != nil {
				return false, receiverSigFailure(receiver, sig, err)
			}
			lgDns.Debug("KeyState response authenticated by manually trusted receiver key",
				"receiver", receiver, "keyid", sig.KeyTag)
			return true, nil
		}
	}

	// 2. The KEY the receiver publishes at its own name. A bogus verdict --
	// on the KEY, or on the DSYNC that named the receiver -- is a chain of
	// trust that exists and failed. That is what an attacker substituting
	// either record looks like, and no lab knob waives it.
	if target.Bogus {
		return false, fmt.Errorf("the DSYNC lookup that named the UPDATE Receiver %s failed DNSSEC validation (bogus); refusing regardless of %s",
			receiver, allowInsecureKnob)
	}
	var key *dns.KEY
	keyValidated := false
	if fetch != nil {
		keys, state, err := fetch(ctx, receiver)
		switch {
		case err != nil:
			lgDns.Debug("KeyState response: receiver KEY lookup failed", "receiver", receiver, "err", err)
		case state == cache.ValidationStateBogus:
			return false, fmt.Errorf("the KEY RRset at the UPDATE Receiver %s failed DNSSEC validation (bogus); refusing regardless of %s",
				receiver, allowInsecureKnob)
		default:
			key = matchingReceiverKey(keys, receiver, sig)
			keyValidated = state == cache.ValidationStateSecure
		}
	}
	if key == nil {
		if allowInsecure {
			lgDns.Warn("KeyState response: no KEY with the signing keyid found for the receiver, signature cannot be checked; acting on it because "+allowInsecureKnob+" is set",
				"receiver", receiver, "keyid", sig.KeyTag)
			return false, nil
		}
		return false, fmt.Errorf("cannot verify KeyState response from %s: no KEY with keyid %d in the truststore or published at that name (set %s to act on unauthenticated responses)",
			receiver, sig.KeyTag, allowInsecureKnob)
	}

	if err := sig0Verify(sig, key, wire); err != nil {
		return false, receiverSigFailure(receiver, sig, err)
	}

	if keyValidated && target.Validated {
		lgDns.Debug("KeyState response authenticated by DNSSEC-validated receiver key",
			"receiver", receiver, "keyid", sig.KeyTag)
		return true, nil
	}

	if allowInsecure {
		lgDns.Warn("KeyState response signature verified, but the receiver key is not authenticated; acting on it because "+allowInsecureKnob+" is set",
			"receiver", receiver, "keyid", sig.KeyTag, "dsyncValidated", target.Validated, "keyValidated", keyValidated)
		return false, nil
	}
	return false, fmt.Errorf("KeyState response from %s verified against a receiver KEY that is not authenticated (DSYNC DNSSEC-validated: %v, KEY DNSSEC-validated: %v, keyid %d not trusted in the truststore); set %s to act on unauthenticated responses",
		receiver, target.Validated, keyValidated, sig.KeyTag, allowInsecureKnob)
}

// exchangeRawCancellable is exchangeCancellable (childsync_utils.go) for a
// caller that must also have the response as it arrived on the wire. SIG(0)
// verification hashes the received bytes; a re-pack of the parsed message is
// only usually identical, and "usually" is not a property to hang
// authentication on.
func exchangeRawCancellable(ctx context.Context, client *dns.Client, msg *dns.Msg, dst string) (*dns.Msg, []byte, error) {
	conn, err := client.DialContext(ctx, dst)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-finished:
		}
	}()

	if opt := msg.IsEdns0(); opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		conn.UDPSize = opt.UDPSize()
	}
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}

	if err := conn.WriteMsg(msg); err != nil {
		return nil, nil, err
	}
	_, isPacket := conn.Conn.(net.PacketConn)
	for {
		wire, err := conn.ReadMsgHeader(nil)
		if err != nil {
			return nil, nil, err
		}
		r := new(dns.Msg)
		if err := r.Unpack(wire); err != nil {
			return nil, nil, err
		}
		if r.Id != msg.Id {
			if isPacket {
				continue // a late answer to an earlier query
			}
			return nil, nil, dns.ErrId
		}
		return r, wire, nil
	}
}

// queryKeyState sends the SIG(0)-signed KeyState inquiry for (keyName, keyid)
// to the UPDATE Receiver at target and returns the authenticated KeyState
// option. It is QueryParentKeyState minus the DSYNC discovery, so it can be
// driven against a local responder in tests.
//
// The inquiry goes over TCP, like the delegation UPDATEs themselves (D-2a): the
// reply is signed and may carry a large (post-quantum) SIG(0), and the Do53
// mux truncates oversized UDP replies AFTER keyStateResponseWriter has signed
// them, which would drop the very SIG this function exists to check.
func queryKeyState(ctx context.Context, kdb *KeyDB, keyName string, keyid uint16, target *DsyncTarget,
	trust receiverKeyTrust, fetch receiverKeyFetcher, allowInsecure bool) (*edns0.KeyStateOption, bool, error) {

	if target == nil || len(target.Addresses) == 0 {
		return nil, false, fmt.Errorf("DSYNC UPDATE target has no addresses for %s", keyName)
	}

	sak, err := kdb.GetSig0Keys(keyName, Sig0StateActive)
	if err != nil || sak == nil || len(sak.Keys) == 0 {
		return nil, false, fmt.Errorf("no active SIG(0) key for %s", keyName)
	}
	signedMsg, err := SignMsg(*newKeyStateInquiryMsg(keyName, keyid), keyName, sak)
	if err != nil {
		return nil, false, fmt.Errorf("failed to sign KeyState inquiry: %v", err)
	}

	// Every address of the target is a candidate, and a response that FAILS
	// verification does not end the search: the address that answered may be
	// the one an attacker poisoned, and the genuine receiver may be behind
	// the next. What it can never do is make a wrong signature acceptable.
	// Authenticate before interpreting anything, the rcode included: a forged
	// rejection is as much a disruption as a forged key state.
	client := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
	var r *dns.Msg
	var authenticated bool
	var transportErr, verifyErr error
	for _, dst := range target.Addresses {
		if cerr := ctx.Err(); cerr != nil {
			return nil, false, fmt.Errorf("KeyState inquiry for %s abandoned: %w", keyName, cerr)
		}
		resp, respWire, err := exchangeRawCancellable(ctx, client, signedMsg, dst)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, false, fmt.Errorf("KeyState inquiry for %s abandoned mid-exchange with %s: %w", keyName, dst, cerr)
			}
			lgDns.Warn("KeyState inquiry: exchange failed, trying next address", "zone", keyName, "dst", dst, "err", err)
			transportErr = err
			continue
		}
		auth, verr := verifyKeyStateResponse(ctx, respWire, resp, target, trust, fetch, allowInsecure)
		if verr != nil {
			lgDns.Warn("KeyState inquiry: response failed verification, trying next address", "zone", keyName, "dst", dst, "err", verr)
			verifyErr = verr
			continue
		}
		r, authenticated = resp, auth
		break
	}
	if r == nil {
		if verifyErr != nil {
			return nil, false, verifyErr
		}
		return nil, false, fmt.Errorf("KeyState inquiry for %s: DNS exchange failed: %v", keyName, transportErr)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, authenticated, fmt.Errorf("KeyState inquiry for %s failed with rcode %s", keyName, dns.RcodeToString[r.Rcode])
	}
	opt := r.IsEdns0()
	if opt == nil {
		return nil, authenticated, fmt.Errorf("KeyState inquiry for %s: no EDNS(0) OPT RR in response", keyName)
	}
	ks, found := edns0.ExtractKeyStateOption(opt)
	if !found {
		return nil, authenticated, fmt.Errorf("KeyState inquiry for %s: KeyState option missing in response", keyName)
	}
	return ks, authenticated, nil
}
