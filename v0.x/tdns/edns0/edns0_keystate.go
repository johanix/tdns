package edns0

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

const (
	// KeyState Option Code (temporary until IANA assignment)
	// OptcodeKeyState = 65002

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
		Code: EDNS0_KEYSTATE_OPTION_CODE,
		Data: data,
	}
}

// ParseKeyStateOption extracts KeyState data from an EDNS0_LOCAL option
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

// ExtractKeyStateOption extracts the KeyState EDNS0 option from an OPT RR
// Returns the KeyStateOption and true if found, or nil and false if not found
// This function follows the same pattern as ExtractOTSOption and ExtractEdns0EROption
func ExtractKeyStateOption(opt *dns.OPT) (*KeyStateOption, bool) {
	if opt == nil {
		return nil, false
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_KEYSTATE_OPTION_CODE {
				keystate, err := ParseKeyStateOption(localOpt)
				if err != nil {
					log.Printf("Error parsing KeyState option: %v", err)
					return nil, false
				}
				return keystate, true
			}
		}
	}

	return nil, false
}

func AttachKeyStateToResponse(msg *dns.Msg, keyStateOpt *KeyStateOption) {
	if msg == nil || keyStateOpt == nil {
		return
	}

	// Ensure there is exactly one OPT RR on the message
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	// Remove any existing KeyState options to avoid duplicates
	filtered := make([]dns.EDNS0, 0, len(opt.Option))
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_KEYSTATE_OPTION_CODE {
				continue
			}
		}
		filtered = append(filtered, option)
	}
	opt.Option = filtered

	// Append the new KeyState option
	edns0KeyStateOpt := CreateKeyStateOption(
		keyStateOpt.KeyID,
		keyStateOpt.KeyState,
		keyStateOpt.ExtraText,
	)
	opt.Option = append(opt.Option, edns0KeyStateOpt)
}
