package tdns

import (
	"fmt"
	"time"

	"context"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (kdb *KeyDB) ProcessKeyState(ks *edns0.KeyStateOption, zonename string) (*edns0.KeyStateOption, error) {
	lgSigner.Debug("processing KeyState request", "zone", zonename, "keyid", ks.KeyID, "state", ks.KeyState)

	switch ks.KeyState {
	case edns0.KeyStateRequestAutoBootstrap:
		// Kontrollera om automatisk bootstrap är tillåten enligt policy
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

		// Starta auto-bootstrap process i bakgrunden
		go func() {
			maxAttempts := viper.GetInt("keystate.max_bootstrap_attempts")
			retryInterval := time.Duration(viper.GetInt("keystate.bootstrap_retry_interval")) * time.Second
			timeout := time.Duration(viper.GetInt("keystate.bootstrap_timeout")) * time.Second

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			for attempt := 1; attempt <= maxAttempts; attempt++ {
				lgSigner.Info("auto-bootstrap attempt", "attempt", attempt, "max", maxAttempts, "zone", zonename, "keyid", ks.KeyID)

				/*err := kdb.startAutoBootstrap(ctx, zonename, ks.KeyID)
				if err == nil {
					log.Printf("Auto-bootstrap successful for zone %s, keyID %d",
						zonename, ks.KeyID)
					return
				}

				log.Printf("Auto-bootstrap attempt failed: %v", err)
				*/
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

		// Hämta aktuell nyckelstatus
		//status, err := kdb.getKeyStatus(zonename, ks.KeyID)
		// Hämta nyckelstatus från truststore
		status, err := kdb.GetKeyStatus(zonename, ks.KeyID)
		if err != nil {
			lgSigner.Error("failed to get key status from truststore", "err", err)
			return &edns0.KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  edns0.KeyStateUnknown,
				ExtraText: fmt.Sprintf("Kunde inte hämta nyckelstatus: %v", err),
			}, nil
		}

		return status, nil

	case edns0.KeyStateInquiryPolicy:
		// Returnera aktuell policy-konfiguration
		if viper.GetBool("keystate.require_manual_bootstrap") {
			return &edns0.KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  edns0.KeyStatePolicyManualRequired,
				ExtraText: "Manual bootstrap required by policy",
			}, nil
		}

		if !viper.GetBool("keystate.allow_auto_bootstrap") {
			return &edns0.KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  edns0.KeyStatePolicyManualRequired,
				ExtraText: "Automatic bootstrap not allowed",
			}, nil
		}

		return &edns0.KeyStateOption{
			KeyID:    ks.KeyID,
			KeyState: edns0.KeyStatePolicyAutoBootstrap,
			ExtraText: fmt.Sprintf("Auto bootstrap allowed (max attempts: %d, timeout: %ds)",
				viper.GetInt("keystate.max_bootstrap_attempts"),
				viper.GetInt("keystate.bootstrap_timeout")),
		}, nil

	default:
		return &edns0.KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  edns0.KeyStateInvalid,
			ExtraText: fmt.Sprintf("Invalid key state request: %d", ks.KeyState),
		}, nil
	}
}

func (kdb *KeyDB) HandleKeyStateOption(opt *dns.OPT, zonename string) (*dns.EDNS0_LOCAL, error) {
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok {
			if local.Code == edns0.EDNS0_KEYSTATE_OPTION_CODE {
				keystate, err := edns0.ParseKeyStateOption(local)
				if err != nil {
					return nil, err
				}

				// Hantera olika key states
				response, err := kdb.ProcessKeyState(keystate, zonename)
				if err != nil {
					return nil, err
				}

				return edns0.CreateKeyStateOption(
					keystate.KeyID,
					response.KeyState,
					response.ExtraText,
				), nil
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
		return nil, fmt.Errorf("kunde inte hämta truststore data: %v", err)
	}

	if key, exists := tr.ChildSig0keys[mapKey]; exists {
		var state uint8
		if key.Trusted {
			state = edns0.KeyStateTrusted
		} else if key.Validated {

			responseChan := make(chan *VerificationInfo)
			lgSigner.Debug("sending INFO request with response channel")
			kdb.KeyBootstrapperQ <- KeyBootstrapperRequest{
				Cmd:          kbCmdInfo,
				KeyName:      zonename,
				Keyid:        keyID,
				ResponseChan: responseChan,
			}

			lgSigner.Debug("waiting for response")
			var verInfo *VerificationInfo
			select {
			case verInfo = <-responseChan:
			case <-time.After(30 * time.Second):
				lgSigner.Warn("timeout waiting for key bootstrapper response", "zone", zonename, "keyid", keyID)
			}
			if verInfo != nil {

				lgSigner.Debug("received verification info", "info", verInfo)

				if verInfo.FailedAttempts > 0 {
					state = edns0.KeyStateValidationFail
				} else {
					state = edns0.KeyStateBootstrapAutoOngoing
				}

			} else {
				state = edns0.KeyStateValidationFail
			}

			lgSigner.Debug("response received")

		} else {
			state = edns0.KeyStateInvalid
		}
		lgSigner.Debug("determined key state", "state", state)
		return &edns0.KeyStateOption{
			KeyID:     keyID,
			KeyState:  state,
			ExtraText: fmt.Sprintf("Key is %d", state),
		}, nil
	}
	lgSigner.Debug("key not found in truststore", "state", edns0.KeyStateUnknown)
	return &edns0.KeyStateOption{
		KeyID:     keyID,
		KeyState:  edns0.KeyStateUnknown,
		ExtraText: "Nyckel hittades inte i truststore",
	}, nil
}
