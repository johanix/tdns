package edns0

import (
	"fmt"
	"log/slog"

	"github.com/miekg/dns"
)

const (
	// KeyState Option Code (temporary until IANA assignment)
	// OptcodeKeyState = 65002

	// Sender (Child) KeyStates — per draft-berra-dnsop-keystate-02
	KeyStateRequestAutoBootstrap   = 0
	KeyStateRequestManualBootstrap = 1
	KeyStateInquiryKey             = 2
	// Code 3 removed in draft-02 (policy discovery via SVCB bootstrap SvcParamKey)

	// Receiver (Parent) KeyStates — per draft-berra-dnsop-keystate-02
	KeyStateTrusted                 = 4
	KeyStateUnknown                 = 5
	KeyStateInvalid                 = 6
	KeyStateRefused                 = 7
	KeyStateValidationFail          = 8
	KeyStateBootstrapAutoOngoing    = 9
	KeyStateBootstrapManualRequired = 10
	// Codes 11-12 removed in draft-02 (policy discovery via SVCB bootstrap SvcParamKey)

	KeyStateUninitialized = 255 // Uninitialized state
)

// KeyStateOption represents the KeyState EDNS(0) option per draft-berra-dnsop-keystate-02.
// Wire format: KEY-ID (16 bits) + KEY-STATE (8 bits) + KEY-DATA (8 bits) + EXTRA-TEXT (variable)
type KeyStateOption struct {
	KeyID     uint16
	KeyState  uint8
	KeyData   uint8
	ExtraText string
}

// CreateKeyStateOption creates an EDNS0_LOCAL option for KeyState.
// Wire format: KeyID(2) + KeyState(1) + KeyData(1) + ExtraText(var) = 4+ bytes
func CreateKeyStateOption(keyID uint16, keyState uint8, keyData uint8, extraText string) *dns.EDNS0_LOCAL {
	data := make([]byte, 4+len(extraText))
	data[0] = byte(keyID >> 8)
	data[1] = byte(keyID & 0xFF)
	data[2] = keyState
	data[3] = keyData
	copy(data[4:], []byte(extraText))

	return &dns.EDNS0_LOCAL{
		Code: EDNS0_KEYSTATE_OPTION_CODE,
		Data: data,
	}
}

// ParseKeyStateOption extracts KeyState data from an EDNS0_LOCAL option.
// Wire format per draft-02: KEY-ID(2) + KEY-STATE(1) + KEY-DATA(1) + EXTRA-TEXT(var) = 4+ bytes
func ParseKeyStateOption(opt *dns.EDNS0_LOCAL) (*KeyStateOption, error) {
	if len(opt.Data) < 4 {
		return nil, fmt.Errorf("invalid KeyState option data length: %d (minimum 4)", len(opt.Data))
	}

	return &KeyStateOption{
		KeyID:     uint16(opt.Data[0])<<8 | uint16(opt.Data[1]),
		KeyState:  opt.Data[2],
		KeyData:   opt.Data[3],
		ExtraText: string(opt.Data[4:]),
	}, nil
}

// KeyStateToString returns a human-readable string for a KeyState code.
func KeyStateToString(state uint8) string {
	states := map[uint8]string{
		KeyStateRequestAutoBootstrap:    "Request Auto Bootstrap",
		KeyStateRequestManualBootstrap:  "Request Manual Bootstrap",
		KeyStateInquiryKey:              "Key Inquiry",
		KeyStateTrusted:                 "Trusted",
		KeyStateUnknown:                 "Unknown",
		KeyStateInvalid:                 "Invalid",
		KeyStateRefused:                 "Refused",
		KeyStateValidationFail:          "Validation Failed",
		KeyStateBootstrapAutoOngoing:    "Auto Bootstrap Ongoing",
		KeyStateBootstrapManualRequired: "Manual Bootstrap Required",
		KeyStateUninitialized:           "Uninitialized",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return fmt.Sprintf("Unknown State (%d)", state)
}

// ExtractKeyStateOption extracts the KeyState EDNS0 option from an OPT RR.
// Returns the KeyStateOption and true if found, or nil and false if not found.
func ExtractKeyStateOption(opt *dns.OPT) (*KeyStateOption, bool) {
	if opt == nil {
		return nil, false
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_KEYSTATE_OPTION_CODE {
				keystate, err := ParseKeyStateOption(localOpt)
				if err != nil {
					slog.Error("failed to parse KeyState option", "err", err)
					return nil, false
				}
				return keystate, true
			}
		}
	}

	return nil, false
}

// AttachKeyStateToResponse attaches a KeyState EDNS0 option to a DNS message.
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
		keyStateOpt.KeyData,
		keyStateOpt.ExtraText,
	)
	opt.Option = append(opt.Option, edns0KeyStateOpt)
}
