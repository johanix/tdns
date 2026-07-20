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
		// A transient store failure is not a statement about the key. Per
		// keystate-03 §"Protocol-Level Responses" report KEY_TEMPORARY_FAILURE(1)
		// (the KeyState equivalent of SERVFAIL) so the child MAY retry later,
		// rather than KEY_UNKNOWN(5) which would (wrongly) invite re-bootstrap.
		lgSigner.Error("failed to get key status from truststore", "err", err)
		return &edns0.KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  edns0.KeyStateTemporaryFailure,
			ExtraText: "Temporarily unable to determine key state",
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

	key, exists := tr.ChildSig0keys[mapKey]
	if !exists {
		lgSigner.Debug("key not found in truststore", "state", edns0.KeyStateUnknown)
		return &edns0.KeyStateOption{
			KeyID:     keyID,
			KeyState:  edns0.KeyStateUnknown,
			ExtraText: "Key not found in truststore",
		}, nil
	}

	state := childKeyState(&key, zoneRequiresManualBootstrap(zonename))
	lgSigner.Debug("determined key state", "zone", zonename, "keyid", keyID,
		"validated", key.Validated, "trusted", key.Trusted, "state", state)

	// KEY-DATA is left 0 for every key-state report. keystate-03 requires
	// KEY-DATA=0 except for codes 6/7, which MAY carry a receiver-defined
	// sub-reason; tdns does not emit sub-reasons, keeping human detail in
	// EXTRA-TEXT instead.
	return &edns0.KeyStateOption{
		KeyID:     keyID,
		KeyState:  state,
		ExtraText: fmt.Sprintf("Key state: %s", edns0.KeyStateToString(state)),
	}, nil
}

// childKeyState maps a child SIG(0) key's truststore record to its
// draft-berra-dnsop-keystate-03 KEY-STATE code.
//
// tdns tracks two INDEPENDENT properties of a child key; they must not be
// collapsed into one another:
//
//   - validated is a TECHNICAL fact: the child has demonstrably published /
//     controls this key (proven via at-apex / at-ns / DNSSEC lookup).
//   - trusted is a POLICY decision the parent layers on top of validation.
//     The parent MAY withhold trust even after a key is validated, pending an
//     out-of-band step (e.g. the child operator confirming in person).
//
// Hence validated=1,trusted=0 is a first-class state — "technically validated,
// trust withheld pending a manual/policy step" — reported as
// KEY_BOOTSTRAP_MANUAL(10), NOT as trusted and NOT as an error.
//
// manualBootstrap is the parent zone's policy for this child: true when no
// automatic bootstrap will run so trust requires a manual step.
func childKeyState(key *Sig0Key, manualBootstrap bool) uint8 {
	// 4 KEY_TRUSTED: the parent has granted policy trust (which implies the
	// key was validated first).
	if key.Trusted {
		return edns0.KeyStateTrusted
	}

	// 6 KEY_INVALID: the key bytes themselves are broken — the stored KEY RR
	// does not parse, or its material is absent/unsupported for its declared
	// algorithm. Intrinsic to the key; re-uploading a correct key fixes it.
	// (Distinct from 8 KEY_VALIDATION_FAILED, where the key is fine but proving
	// the child controls it failed.)
	if !childKeyStructurallyValid(key) {
		return edns0.KeyStateInvalid
	}

	// 7 KEY_REFUSED (dormant): the key is structurally fine but its algorithm
	// is rejected by policy.
	// TODO(phase2): emit 7 once a SIG(0) accepted-algorithm policy exists and
	// gates the UPDATE authorization path. A report-only algorithm policy is
	// incoherent — it must also refuse the UPDATEs it reports on — so it belongs
	// with the Phase 2 authorization work, not here.

	// 10 KEY_BOOTSTRAP_MANUAL, case (a): technically validated, but policy trust
	// is withheld pending a manual step (validated=1, trusted=0).
	if key.Validated {
		return edns0.KeyStateBootstrapManualRequired
	}

	// 10 KEY_BOOTSTRAP_MANUAL, case (b): not yet validated and the parent's
	// bootstrap policy is manual, so no automatic bootstrap will run.
	if manualBootstrap {
		return edns0.KeyStateBootstrapManualRequired
	}

	// 8 KEY_VALIDATION_FAILED (dormant): validated=0, trusted=0, and automatic
	// bootstrap validation has been attempted and exhausted.
	// TODO(phase2): emit 8 from the real retry/exhaustion state machine that
	// D-2b/D-4 build. Today the only failure source (TriggerChildKeyVerification
	// exhaustion) persists nothing and runs in an in-memory goroutine lost on
	// restart, so "failed" cannot be soundly distinguished from "in progress" —
	// we report 9 (in progress) below instead.

	// 9 KEY_BOOTSTRAP_AUTO: known and structurally valid, not yet validated;
	// automatic bootstrap is in progress.
	return edns0.KeyStateBootstrapAutoOngoing
}

// childKeyStructurallyValid reports whether the stored KEY RR parses and its
// public-key material is present for a non-reserved algorithm. A structurally
// broken KEY maps to KEY_INVALID(6).
func childKeyStructurallyValid(key *Sig0Key) bool {
	if key.Keystr == "" {
		return false
	}
	rr, err := dns.NewRR(key.Keystr)
	if err != nil {
		return false
	}
	keyRR, ok := rr.(*dns.KEY)
	if !ok {
		return false
	}
	// Algorithm 0 is reserved/invalid; an empty public key cannot match any
	// algorithm.
	if keyRR.Algorithm == 0 || keyRR.PublicKey == "" {
		return false
	}
	return true
}

// zoneRequiresManualBootstrap reports whether the parent zone delegating to
// childName requires MANUAL SIG(0) bootstrap (no automatic DNS-based
// validation), per its UpdatePolicy.Child.KeyBootstrap. It is consulted only to
// choose between KEY_BOOTSTRAP_MANUAL(10) and KEY_BOOTSTRAP_AUTO(9) for a
// not-yet-validated key; an unknown parent zone defaults to automatic.
func zoneRequiresManualBootstrap(childName string) bool {
	parent, ok := FindZone(childName)
	if !ok || parent == nil {
		return false
	}
	for _, m := range parent.UpdatePolicy.Child.KeyBootstrap {
		if m == "manual" || m == "strict-manual" {
			return true
		}
	}
	return false
}

// newKeyStateInquiryMsg builds the child's KeyState inquiry: a QTYPE=KEY query
// for keyName carrying a KeyState option with KEY-STATE=INTENT_INQUIRE_KEY(2)
// and the KeyId being inquired about, per keystate-03 §"KeyStates Set By The
// UPDATE Receiver" (QNAME=child.parent, QTYPE=KEY). The caller SIG(0)-signs it
// before sending.
func newKeyStateInquiryMsg(keyName string, keyid uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(keyName), dns.TypeKEY)
	edns0.AttachKeyStateToResponse(m, &edns0.KeyStateOption{
		KeyID:    keyid,
		KeyState: edns0.KeyStateInquiryKey,
	})
	return m
}
