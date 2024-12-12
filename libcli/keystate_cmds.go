package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
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
	KeyStateUninitialized           = 255
)

type KeyStateOption struct {
	KeyID     uint16
	KeyState  uint8
	ExtraText string
}

func init() {
	KeyStateCmd.AddCommand(keystateInquireKeyCmd)
	KeyStateCmd.AddCommand(keystateInquirePolicyCmd)

}

var KeyStateCmd = &cobra.Command{
	Use:   "keystate",
	Short: "The 'keystate' command is used to manage and query SIG(0) key states",
}

var keystateInquirePolicyCmd = &cobra.Command{
	Use:   "policy [zone]",
	Short: "Inquire about policy state from parent",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || len(args) > 2 {
			return fmt.Errorf("requires zone and optional keyid arguments")
		}

		zone := dns.Fqdn(args[0])

		resp, err := SendKeyStateCommand(tdns.Globals.Api, tdns.KeyStatePost{
			Command:  "inquire",
			Zone:     zone,
			KeyID:    0,
			KeyState: KeyStateInquiryPolicy,
		})
		if err != nil {
			return err
		}

		fmt.Printf("KeyState: %+v\n", resp.KeyState)
		return nil
	},
}

func createKeyStateData(keyID uint16, keyState uint8, extraText string) []byte {

	data := make([]byte, 3+len(extraText))
	data[0] = byte(keyID >> 8)
	data[1] = byte(keyID & 0xFF)

	// KEY-STATE (1 byte)
	data[2] = keyState

	// EXTRA-TEXT
	copy(data[3:], []byte(extraText))

	return data
}

func xxxxhandleKeyStateResponse(msg *dns.Msg) error {
	for _, rr := range msg.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			for _, o := range opt.Option {
				if local, ok := o.(*dns.EDNS0_LOCAL); ok {
					if local.Code == OptcodeKeyState {
						ks, err := tdns.ParseKeyStateOption(local)
						if err != nil {
							return err
						}

						// Print the result
						fmt.Printf("Key ID: %d\n", ks.KeyID)
						fmt.Printf("State: %s (%d)\n", keyStateToString(ks.KeyState), ks.KeyState)
						if ks.ExtraText != "" {
							fmt.Printf("Extra text: %s\n", ks.ExtraText)
						}
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("no KeyState option found in response")
}

func xxxParseKeyStateOption(opt *dns.EDNS0_LOCAL) (*KeyStateOption, error) {
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
		KeyStateUninitialized:           "Uninitialized",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "Unknown State"
}

var keystateInquireKeyCmd = &cobra.Command{
	Use:   "key [zone] [keyid]",
	Short: "Inquire about key state from parent",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || len(args) > 2 {
			return fmt.Errorf("requires zone and optional keyid arguments")
		}

		zone := dns.Fqdn(args[0])
		var keyid uint16

		if len(args) == 1 {
			// Hämta aktiv nyckel via keystore API
			data := tdns.KeystorePost{
				Command:    "sig0-mgmt",
				SubCommand: "list",
			}
			tr, err := SendKeystoreCmd(tdns.Globals.Api, data)
			if err != nil {
				return fmt.Errorf("could not fetch active key: %v", err)
			}

			for k, v := range tr.Sig0keys {
				tmp := strings.Split(k, "::")
				if v.State == "active" && zone == dns.Fqdn(tmp[0]) {
					keyid_int, _ := strconv.Atoi(tmp[1])
					keyid = uint16(keyid_int)
					break
				}
			}
		} else {
			keyid_int, _ := strconv.Atoi(args[1])
			keyid = uint16(keyid_int)
		}

		resp, err := SendKeyStateCommand(tdns.Globals.Api, tdns.KeyStatePost{
			Command:  "inquire",
			Zone:     zone,
			KeyID:    keyid,
			KeyState: KeyStateInquiryKey,
		})
		if err != nil {
			return err
		}

		fmt.Printf("KeyState: %+v\n", resp.KeyState)
		return nil
	},
}

func SendKeyStateCommand(api *tdns.ApiClient, data tdns.KeyStatePost) (tdns.KeyStateResponse, error) {
	var kr tdns.KeyStateResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	_, buf, err := api.Post("/keystate", bytebuf.Bytes())
	if err != nil {
		return kr, fmt.Errorf("error from api post: %v", err)
	}

	fmt.Printf("Response: %s\n", string(buf))

	err = json.Unmarshal(buf, &kr)
	if err != nil {
		return kr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if kr.Error {
		return kr, fmt.Errorf("error from tdnsd: %s", kr.ErrorMsg)
	}

	return kr, nil
}
