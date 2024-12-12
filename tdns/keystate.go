package tdns

import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

const (
	// KeyState Option Code (temporary until IANA assignment)
	OptcodeKeyState = 65002

	// Sender (Child) KeyStates
	KeyStateRequestAutoBootstrap   = 0
	KeyStateRequestManualBootstrap = 1
	KeyStateInquiryKey             = 2
	KeyStateInquiryPolicy          = 3

	// Receiver (Parent) KeyStates
	KeyStateTrusted                 = 4
	KeyStateUnknown                 = 5
	KeyStateInvalid                 = 6
	KeyStateRefused                 = 7
	KeyStateValidationFail          = 8
	KeyStateBootstrapAutoOngoing    = 9
	KeyStateBootstrapManualRequired = 10
	KeyStatePolicyManualRequired    = 11
	KeyStatePolicyAutoBootstrap     = 12

	KeyStateUninitialized = 255 // Nytt värde för oinitierat tillstånd
)

type KeyStateOption struct {
	KeyID     uint16
	KeyState  uint8
	ExtraText string
}

// CreateKeyStateOption skapar en EDNS0_LOCAL option för KeyState
func CreateKeyStateOption(keyID uint16, keyState uint8, extraText string) *dns.EDNS0_LOCAL {
	data := make([]byte, 3+len(extraText))
	data[0] = byte(keyID >> 8)
	data[1] = byte(keyID & 0xFF)
	data[2] = keyState
	copy(data[3:], []byte(extraText))

	return &dns.EDNS0_LOCAL{
		Code: OptcodeKeyState,
		Data: data,
	}
}

func createKeyStateData(keyID uint16, keyState uint8, extraText string) []byte {
	// KEY-ID (2 bytes)
	data := make([]byte, 3+len(extraText))
	data[0] = byte(keyID >> 8)
	data[1] = byte(keyID & 0xFF)

	// KEY-STATE (1 byte)
	data[2] = keyState

	// EXTRA-TEXT (variable length)
	copy(data[3:], []byte(extraText))

	return data
}

// ParseKeyStateOption extraherar KeyState-data från en EDNS0_LOCAL option
func ParseKeyStateOption(opt *dns.EDNS0_LOCAL) (*KeyStateOption, error) {
	if len(opt.Data) < 3 {
		return nil, fmt.Errorf("invalid KeyState option data length")
	}

	keyID := uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
	keyState := opt.Data[2]
	extraText := string(opt.Data[3:])

	return &KeyStateOption{
		KeyID:     keyID,
		KeyState:  keyState,
		ExtraText: extraText,
	}, nil
}

func processKeyState(ks *KeyStateOption, kdb *KeyDB, zonename string) (*KeyStateOption, error) {
	log.Printf("Processing KeyState request for zone %s, keyID %d, state %d",
		zonename, ks.KeyID, ks.KeyState)

	switch ks.KeyState {
	case KeyStateRequestAutoBootstrap:
		// Kontrollera om automatisk bootstrap är tillåten enligt policy
		if viper.GetBool("keystate.require_manual_bootstrap") {
			return &KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  KeyStateBootstrapManualRequired,
				ExtraText: "Manual bootstrap required by policy",
			}, nil
		}

		if !viper.GetBool("keystate.allow_auto_bootstrap") {
			return &KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  KeyStateBootstrapManualRequired,
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

		return &KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  KeyStateBootstrapAutoOngoing,
			ExtraText: "Auto bootstrap process initiated",
		}, nil

	case KeyStateInquiryKey:

		// Hämta aktuell nyckelstatus
		//status, err := kdb.getKeyStatus(zonename, ks.KeyID)
		// Hämta nyckelstatus från truststore
		status, err := kdb.GetKeyStatus(zonename, ks.KeyID)
		if err != nil {
			log.Printf("Kunde inte hämta nyckelstatus från truststore: %v", err)
			return &KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  KeyStateUnknown,
				ExtraText: fmt.Sprintf("Kunde inte hämta nyckelstatus: %v", err),
			}, nil
		}

		return status, nil

	case KeyStateInquiryPolicy:
		// Returnera aktuell policy-konfiguration
		if viper.GetBool("keystate.require_manual_bootstrap") {
			return &KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  KeyStatePolicyManualRequired,
				ExtraText: "Manual bootstrap required by policy",
			}, nil
		}

		if !viper.GetBool("keystate.allow_auto_bootstrap") {
			return &KeyStateOption{
				KeyID:     ks.KeyID,
				KeyState:  KeyStatePolicyManualRequired,
				ExtraText: "Automatic bootstrap not allowed",
			}, nil
		}

		return &KeyStateOption{
			KeyID:    ks.KeyID,
			KeyState: KeyStatePolicyAutoBootstrap,
			ExtraText: fmt.Sprintf("Auto bootstrap allowed (max attempts: %d, timeout: %ds)",
				viper.GetInt("keystate.max_bootstrap_attempts"),
				viper.GetInt("keystate.bootstrap_timeout")),
		}, nil

	default:
		return &KeyStateOption{
			KeyID:     ks.KeyID,
			KeyState:  KeyStateInvalid,
			ExtraText: fmt.Sprintf("Invalid key state request: %d", ks.KeyState),
		}, nil
	}
}

func handleKeyStateOption(opt *dns.OPT, kdb *KeyDB, zonename string) (*dns.EDNS0_LOCAL, error) {
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok {
			if local.Code == OptcodeKeyState {
				keystate, err := ParseKeyStateOption(local)
				if err != nil {
					return nil, err
				}

				// Hantera olika key states
				response, err := processKeyState(keystate, kdb, zonename)
				if err != nil {
					return nil, err
				}

				return CreateKeyStateOption(
					keystate.KeyID,
					response.KeyState,
					response.ExtraText,
				), nil
			}
		}
	}
	return nil, nil
}

func keyStateToString(state uint8) string {
	fmt.Printf("keyStateToString: state=%d\n", state)

	states := map[uint8]string{
		KeyStateRequestAutoBootstrap:    "Request Auto Bootstrap",
		KeyStateRequestManualBootstrap:  "Request Manual Bootstrap",
		KeyStateInquiryKey:              "Key Inquiry",
		KeyStateInquiryPolicy:           "Policy Inquiry",
		KeyStateTrusted:                 "Trusted",
		KeyStateUnknown:                 "Unknown",
		KeyStateInvalid:                 "Invalid",
		KeyStateRefused:                 "Refused",
		KeyStateValidationFail:          "Validation Failed",
		KeyStateBootstrapAutoOngoing:    "Auto Bootstrap Ongoing",
		KeyStateBootstrapManualRequired: "Manual Bootstrap Required",
		KeyStatePolicyManualRequired:    "Policy Manual Required",
		KeyStatePolicyAutoBootstrap:     "Policy Auto Bootstrap",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "Unknown State"
}

func (kdb *KeyDB) GetKeyStatus(zonename string, keyID uint16) (*KeyStateOption, error) {
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
			state = KeyStateTrusted
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
					state = KeyStateValidationFail
				} else {
					state = KeyStateBootstrapAutoOngoing
				}

			} else {
				state = KeyStateValidationFail
			}

			fmt.Printf("GetKeyStatus: Svar mottaget\n")

		} else {
			state = KeyStateInvalid // eller?
		}
		fmt.Printf("GetKeyStatus: KeyState: %d\n", state)
		return &KeyStateOption{
			KeyID:     keyID,
			KeyState:  state,
			ExtraText: fmt.Sprintf("Key is %d", state),
		}, nil
	}
	fmt.Printf("GetKeyStatus: KeyState: %d\n", KeyStateUnknown)
	return &KeyStateOption{
		KeyID:     keyID,
		KeyState:  KeyStateUnknown,
		ExtraText: "Nyckel hittades inte i truststore",
	}, nil
}

func ExtractKeyStateFromMsg(msg *dns.Msg) (*KeyStateOption, error) {
	fmt.Printf("ExtractKeyStateFromMsg: msg.Extra: %+v", msg.Extra)

	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if local, ok := option.(*dns.EDNS0_LOCAL); ok {
				fmt.Printf("ExtractKeyStateFromMsg: Found KeyState option\n")
				fmt.Printf("ExtractKeyStateFromMsg: local.Code: %d\n", local.Code)
				if local.Code == OptcodeKeyState {
					keystate, err := ParseKeyStateOption(local)
					if err != nil {
						log.Printf("Error parsing KeyState option: %v", err)
						return nil, err
					}
					return keystate, nil
				}
			}
		}
	}

	return nil, nil
}

func AttachKeyStateToResponse(msg *dns.Msg, keyStateOpt *KeyStateOption) {

	edns0_keyStateOpt := CreateKeyStateOption(
		keyStateOpt.KeyID,
		keyStateOpt.KeyState,
		keyStateOpt.ExtraText,
	)

	msg.Extra = append(msg.Extra, &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  dns.DefaultMsgSize,
		},
		Option: []dns.EDNS0{edns0_keyStateOpt},
	})

}

/*
func AddKeyStateToOPT(opt *dns.OPT, keyStateOpt *KeyStateOption) {
	ede := new(dns.EDNS0_EDE)
	ede.InfoCode = edeCode
	ede.ExtraText = EDECodeToString[edeCode]

	opt.Option = append(opt.Option, ede)
}*/
