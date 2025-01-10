package music

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

const (
	// MSAData Option Code (temporary until IANA assignment)
	OptcodeMSAData = 65003

	MSADataHello = 0
)

type MSADataOption struct {
	MSAData   uint8
	ExtraText string
}

// CreateMSADataOption skapar en EDNS0_LOCAL option för MSAData
func CreateMSADataOption(MSAData uint8, extraText string) *dns.EDNS0_LOCAL {
	data := make([]byte, 1+len(extraText))
	data[0] = MSAData
	copy(data[1:], []byte(extraText))

	return &dns.EDNS0_LOCAL{
		Code: OptcodeMSAData,
		Data: data,
	}
}

func createMSADataData(MSAData uint8, extraText string) []byte {
	// MSAData (1 byte)
	data := make([]byte, 1+len(extraText))
	data[0] = MSAData

	// EXTRA-TEXT (variable length)
	copy(data[1:], []byte(extraText))

	return data
}

// ParseMSADataOption extraherar KeyState-data från en EDNS0_LOCAL option
func ParseMSADataOption(opt *dns.EDNS0_LOCAL) (*MSADataOption, error) {
	if len(opt.Data) < 1 {
		return nil, fmt.Errorf("invalid MSAData option data length")
	}

	MSAData := opt.Data[0]
	extraText := string(opt.Data[1:])

	return &MSADataOption{
		MSAData:   MSAData,
		ExtraText: extraText,
	}, nil
}

func processMSAData(ks *MSADataOption, zonename string) (*MSADataOption, error) {
	log.Printf("Processing MSAData request for zone %s, MSAData %d",
		zonename, ks.MSAData)

	return nil, nil
}

func handleMSADataOption(opt *dns.OPT, zonename string) (*dns.EDNS0_LOCAL, error) {

	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok {
			if local.Code == OptcodeMSAData {
				msadata, err := ParseMSADataOption(local)
				if err != nil {
					return nil, err
				}

				response, err := processMSAData(msadata, zonename)
				if err != nil {
					return nil, err
				}

				return CreateMSADataOption(
					msadata.MSAData,
					response.ExtraText,
				), nil
			}
		}
	}
	return nil, nil
}

func msaDataToString(state uint8) string {
	log.Printf("msaDataToString: state=%d\n", state)

	states := map[uint8]string{
		MSADataHello: "Init Hello",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "Unknown State"
}

func ExtractMSADataFromMsg(msg *dns.Msg) (*MSADataOption, error) {
	log.Printf("ExtractMSADataFromMsg: msg.Extra: %+v", msg.Extra)

	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if local, ok := option.(*dns.EDNS0_LOCAL); ok {
				fmt.Printf("ExtractMSADataFromMsg: Found MSAData option\n")
				fmt.Printf("ExtractMSADataFromMsg: local.Code: %d\n", local.Code)
				if local.Code == OptcodeMSAData {
					msadata, err := ParseMSADataOption(local)
					if err != nil {
						log.Printf("Error parsing MSAData option: %v", err)
						return nil, err
					}
					return msadata, nil
				}
			}
		}
	}

	return nil, nil
}

func AttachMSADataToResponse(msg *dns.Msg, msaDataOpt *MSADataOption) {

	edns0_msadataOpt := CreateMSADataOption(
		msaDataOpt.MSAData,
		msaDataOpt.ExtraText,
	)

	opt := msg.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  dns.DefaultMsgSize,
			},
		}
		msg.Extra = append(msg.Extra, opt)
	}
	opt.Option = append(opt.Option, edns0_msadataOpt)
}
