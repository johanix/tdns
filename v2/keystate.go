package tdns

import (
	"fmt"
	"net"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// keyStateResponseWriter wraps a dns.ResponseWriter to intercept WriteMsg
// and attach a KeyState EDNS(0) response option and SIG(0) signature before sending.
type keyStateResponseWriter struct {
	dns.ResponseWriter
	keyStateResponse *edns0.KeyStateOption
	sig0Signer       string          // DSYNC target name (UPDATE Receiver identity)
	sig0Keys         *Sig0ActiveKeys // active SIG(0) keys for signing
}

func (w *keyStateResponseWriter) WriteMsg(m *dns.Msg) error {
	if w.keyStateResponse == nil {
		return w.ResponseWriter.WriteMsg(m)
	}

	// draft-berra-dnsop-keystate-03 §"KeyStates Set By The UPDATE Receiver":
	// a response carrying a KeyState option MUST be signed by the UPDATE
	// Receiver's SIG(0) key. Fail closed — if we cannot sign, send the reply
	// WITHOUT the KeyState option rather than emitting an unsigned key-state
	// signal, which §"Security Considerations" names as the forged-response
	// DoS vector (a child MUST NOT trust an unsigned signal). The option is
	// attached only to the copy we actually sign, so the optionless fallback
	// never carries it.
	if w.sig0Signer == "" || w.sig0Keys == nil || len(w.sig0Keys.Keys) == 0 {
		lgSigner.Warn("cannot SIG(0)-sign KeyState response: no active UPDATE Receiver key; omitting KeyState option (fail closed)",
			"signer", w.sig0Signer)
		return w.ResponseWriter.WriteMsg(m)
	}

	signedMsg := m.Copy()
	edns0.AttachKeyStateToResponse(signedMsg, w.keyStateResponse)
	signed, err := SignMsg(*signedMsg, w.sig0Signer, w.sig0Keys)
	if err != nil {
		lgSigner.Error("failed to SIG(0)-sign KeyState response; omitting KeyState option (fail closed)",
			"signer", w.sig0Signer, "err", err)
		return w.ResponseWriter.WriteMsg(m)
	}
	return w.ResponseWriter.WriteMsg(signed)
}

// Ensure keyStateResponseWriter satisfies dns.ResponseWriter.
func (w *keyStateResponseWriter) LocalAddr() net.Addr  { return w.ResponseWriter.LocalAddr() }
func (w *keyStateResponseWriter) RemoteAddr() net.Addr { return w.ResponseWriter.RemoteAddr() }
func (w *keyStateResponseWriter) Write(b []byte) (int, error) {
	return w.ResponseWriter.Write(b)
}
func (w *keyStateResponseWriter) Close() error { return w.ResponseWriter.Close() }
func (w *keyStateResponseWriter) TsigStatus() error {
	return w.ResponseWriter.TsigStatus()
}
func (w *keyStateResponseWriter) TsigTimersOnly(b bool) {
	w.ResponseWriter.TsigTimersOnly(b)
}
func (w *keyStateResponseWriter) Hijack() { w.ResponseWriter.Hijack() }

func (kdb *KeyDB) ProcessKeyState(ks *edns0.KeyStateOption, zonename string) (*edns0.KeyStateOption, error) {
	lgSigner.Debug("processing KeyState request", "zone", zonename, "keyid", ks.KeyID, "state", ks.KeyState)

	// Per draft-berra-dnsop-keystate-03 §"Protocol-Level Responses", the
	// only valid sender code in a request is 2 (INTENT_INQUIRE_KEY). Any
	// other KEY-STATE — including the unassigned codes 3 and 11-127 and the
	// receiver-only codes 0/1/4-10 — MUST be treated as malformed and
	// answered with KEY_REQUEST_MALFORMED(0), echoing the KEY-ID and with
	// KEY-DATA=0. (keystate-02's sender-set bootstrap-request codes 0/1 were
	// removed in -03; bootstrap is initiated via the self-signed UPDATE plus
	// the SVCB bootstrap SvcParamKey, not via a KeyState request.)
	if ks.KeyState != edns0.KeyStateInquiryKey {
		lgSigner.Warn("malformed KeyState request: unexpected KEY-STATE", "zone", zonename, "keyid", ks.KeyID, "state", ks.KeyState)
		return &edns0.KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  edns0.KeyStateRequestMalformed,
			KeyData:   0,
			ExtraText: fmt.Sprintf("Malformed KeyState request: unexpected KEY-STATE %d", ks.KeyState),
		}, nil
	}

	// KEY-STATE == 2 (INTENT_INQUIRE_KEY): report the current key status.
	status, err := kdb.GetKeyStatus(zonename, ks.KeyID)
	if err != nil {
		lgSigner.Error("failed to get key status from truststore", "err", err)
		return &edns0.KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  edns0.KeyStateUnknown,
			ExtraText: "Failed to get key status",
		}, nil
	}
	return status, nil
}

func (kdb *KeyDB) HandleKeyStateOption(opt *dns.OPT, zonename string) (*edns0.KeyStateOption, error) {
	if opt == nil {
		return nil, nil
	}
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok {
			if local.Code == edns0.EDNS0_KEYSTATE_OPTION_CODE {
				keystate, err := edns0.ParseKeyStateOption(local)
				if err != nil {
					return nil, err
				}

				// Process the key state request
				response, err := kdb.ProcessKeyState(keystate, zonename)
				if err != nil {
					return nil, err
				}

				return response, nil
			}
		}
	}
	return nil, nil
}

func (kdb *KeyDB) GetKeyStatus(zonename string, keyID uint16) (*edns0.KeyStateOption, error) {
	mapKey := fmt.Sprintf("%s::%d", zonename, keyID)

	lgSigner.Debug("GetKeyStatus", "zone", zonename, "keyid", keyID)

	tr, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: "list",
	})
	if err != nil {
		lgSigner.Error("failed to get truststore data", "err", err)
		return nil, fmt.Errorf("failed to get truststore data: %v", err)
	}

	if key, exists := tr.ChildSig0keys[mapKey]; exists {
		var state uint8
		if key.Trusted {
			state = edns0.KeyStateTrusted
		} else if key.Validated {
			// Key is validated but not yet trusted — verification is pending or hasn't started.
			state = edns0.KeyStateBootstrapAutoOngoing
		} else {
			state = edns0.KeyStateInvalid
		}
		lgSigner.Debug("determined key state", "zone", zonename, "keyid", keyID,
			"validated", key.Validated, "trusted", key.Trusted, "state", state)
		return &edns0.KeyStateOption{
			KeyID:     keyID,
			KeyState:  state,
			ExtraText: fmt.Sprintf("Key state: %s", edns0.KeyStateToString(state)),
		}, nil
	}
	lgSigner.Debug("key not found in truststore", "state", edns0.KeyStateUnknown)
	return &edns0.KeyStateOption{
		KeyID:     keyID,
		KeyState:  edns0.KeyStateUnknown,
		ExtraText: "Key not found in truststore",
	}, nil
}
