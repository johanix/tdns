package edns0

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
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
