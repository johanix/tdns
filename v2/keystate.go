package tdns

import (
	"fmt"
	"net"
	"time"

	"context"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
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
	if w.keyStateResponse != nil {
		edns0.AttachKeyStateToResponse(m, w.keyStateResponse)
	}
	// Sign the response with the UPDATE Receiver's SIG(0) key per
	// draft-berra-dnsop-keystate-02: responses containing a KeyState
	// option MUST be signed by the UPDATE Receiver.
	if w.sig0Signer != "" && w.sig0Keys != nil && len(w.sig0Keys.Keys) > 0 {
		signed, err := SignMsg(*m, w.sig0Signer, w.sig0Keys)
		if err != nil {
			lgSigner.Error("failed to SIG(0)-sign KeyState response", "signer", w.sig0Signer, "err", err)
			// Send unsigned — better than failing entirely
		} else {
			m = signed
		}
	}
	return w.ResponseWriter.WriteMsg(m)
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

	switch ks.KeyState {
	case edns0.KeyStateRequestAutoBootstrap:
		// Check if automatic bootstrap is allowed by policy
		if viper.GetBool("keystate.require_manual_bootstrap") {
			return &edns0.KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  edns0.KeyStateBootstrapManualRequired,
				ExtraText: "Manual bootstrap required by policy",
			}, nil
		}

		if !viper.GetBool("keystate.allow_auto_bootstrap") {
			return &edns0.KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  edns0.KeyStateBootstrapManualRequired,
				ExtraText: "Automatic bootstrap not allowed by policy",
			}, nil
		}

		// Start auto-bootstrap process in the background
		go func() {
			maxAttempts := viper.GetInt("keystate.max_bootstrap_attempts")
			retryInterval := time.Duration(viper.GetInt("keystate.bootstrap_retry_interval")) * time.Second
			timeout := time.Duration(viper.GetInt("keystate.bootstrap_timeout")) * time.Second

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			for attempt := 1; attempt <= maxAttempts; attempt++ {
				lgSigner.Info("auto-bootstrap attempt", "attempt", attempt, "max", maxAttempts, "zone", zonename, "keyid", ks.KeyID)

				// TODO: Implement startAutoBootstrap
				if attempt < maxAttempts {
					select {
					case <-ctx.Done():
						lgSigner.Warn("auto-bootstrap timed out", "zone", zonename, "keyid", ks.KeyID)
						return
					case <-time.After(retryInterval):
						continue
					}
				}
			}
			lgSigner.Error("auto-bootstrap failed after all attempts", "attempts", maxAttempts, "zone", zonename, "keyid", ks.KeyID)
		}()

		return &edns0.KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  edns0.KeyStateBootstrapAutoOngoing,
			ExtraText: "Auto bootstrap process initiated",
		}, nil

	case edns0.KeyStateInquiryKey:
		// Get current key status from truststore
		status, err := kdb.GetKeyStatus(zonename, ks.KeyID)
		if err != nil {
			lgSigner.Error("failed to get key status from truststore", "err", err)
			return &edns0.KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  edns0.KeyStateUnknown,
				ExtraText: fmt.Sprintf("Failed to get key status: %v", err),
			}, nil
		}

		return status, nil

	default:
		return &edns0.KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  edns0.KeyStateInvalid,
			ExtraText: fmt.Sprintf("Invalid key state request: %d", ks.KeyState),
		}, nil
	}
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
