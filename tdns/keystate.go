package tdns

import (
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

func (kdb *KeyDB) ProcessKeyState(ks *edns0.KeyStateOption, zonename string) (*edns0.KeyStateOption, error) {
	log.Printf("Processing KeyState request for zone %s, keyID %d, state %d",
		zonename, ks.KeyID, ks.KeyState)

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
				log.Printf("Auto-bootstrap attempt %d/%d for zone %s, keyID %d",
					attempt, maxAttempts, zonename, ks.KeyID)

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
						log.Printf("Auto-bootstrap timed out for zone %s, keyID %d",
							zonename, ks.KeyID)
						return
					case <-time.After(retryInterval):
						continue
					}
				}
			}
			log.Printf("Auto-bootstrap failed after %d attempts for zone %s, keyID %d",
				maxAttempts, zonename, ks.KeyID)
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
			log.Printf("Kunde inte hämta nyckelstatus från truststore: %v", err)
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
	// Skapa en nyckel för att söka i truststore
	mapKey := fmt.Sprintf("%s::%d", zonename, keyID)

	fmt.Printf("GetKeyStatus: zonename: %s, keyID: %d\n", zonename, keyID)

	// Hämta information från truststore
	tr, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: "list",
	})
	if err != nil {
		fmt.Printf("kunde inte hämta truststore data: %v\n", err)
		return nil, fmt.Errorf("kunde inte hämta truststore data: %v", err)
	}

	// Leta efter nyckeln i truststore
	if key, exists := tr.ChildSig0keys[mapKey]; exists {
		var state uint8
		if key.Trusted {
			state = edns0.KeyStateTrusted
		} else if key.Validated {

			// Skapa en svarskanal
			responseChan := make(chan *VerificationInfo)
			fmt.Printf("GetKeyStatus: Skicka förfrågan med svarskanal\n")
			// Skicka förfrågan med svarskanal
			kdb.KeyBootstrapperQ <- KeyBootstrapperRequest{
				Cmd:          kbCmdInfo,
				KeyName:      zonename,
				Keyid:        keyID,
				ResponseChan: responseChan,
			}

			fmt.Printf("GetKeyStatusVänta på svar\n")
			verInfo := <-responseChan
			if verInfo != nil {

				fmt.Printf("GetKeyStatus: VerInfo: %v\n", verInfo)

				if verInfo.FailedAttempts > 0 {
					state = edns0.KeyStateValidationFail
				} else {
					state = edns0.KeyStateBootstrapAutoOngoing
				}

			} else {
				state = edns0.KeyStateValidationFail
			}

			fmt.Printf("GetKeyStatus: Svar mottaget\n")

		} else {
			state = edns0.KeyStateInvalid // eller?
		}
		fmt.Printf("GetKeyStatus: KeyState: %d\n", state)
		return &edns0.KeyStateOption{
			KeyID:     keyID,
			KeyState:  state,
			ExtraText: fmt.Sprintf("Key is %d", state),
		}, nil
	}
	fmt.Printf("GetKeyStatus: KeyState: %d\n", edns0.KeyStateUnknown)
	return &edns0.KeyStateOption{
		KeyID:     keyID,
		KeyState:  edns0.KeyStateUnknown,
		ExtraText: "Nyckel hittades inte i truststore",
	}, nil
}

