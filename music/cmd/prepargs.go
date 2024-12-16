/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package mcmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/johanix/tdns/music"
	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

func PrepArgs(required ...string) {

	for _, arg := range required {
		if tdns.Globals.Debug {
			fmt.Printf("Required: %s\n", arg)
		}
		switch arg {
		case "identity":
			if sidecarId == "" {
				fmt.Printf("Error: sidecar identity not specified (use --id flag)\n")
				os.Exit(1)
			}
			sidecarId = dns.Fqdn(sidecarId)

		case "method":
			sidecarMethod = strings.ToUpper(sidecarMethod)
			switch sidecarMethod {
			case "DNS", "API":
				break
			case "":
				fmt.Printf("Error: sidecar method not specified (use --method flag)\n")
				os.Exit(1)
			default:
				fmt.Printf("Error: sidecar method \"%s\" is not known\n", sidecarMethod)
				os.Exit(1)
			}

		case "zonename":
			tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)
			if tdns.Globals.Zonename == "." {
				fmt.Printf("Error: zone name not specified using --zone flag\n")
				os.Exit(1)
			}

		case "addr":
			if tdns.Globals.Address == "" {
				fmt.Printf("Error: address not specified using --addr flag\n")
				os.Exit(1)
			}

		case "uri":
			if tdns.Globals.BaseUri == "" {
				fmt.Printf("Error: URI not specified using --uri flag\n")
				os.Exit(1)
			}

		case "port":
			if tdns.Globals.Port == 0 {
				fmt.Printf("Error: port not specified using --port flag\n")
				os.Exit(1)
			}

		case "signergroupname":
			if music.Globals.Sgroupname == "" {
				fmt.Printf("Error: signer group not specified. Terminating.\n")
				os.Exit(1)
			}

		case "signername":
			if music.Globals.Signername == "" {
				fmt.Printf("Error: signer not specified. Terminating.\n")
				os.Exit(1)
			}

		case "fsmname":
			if music.Globals.FSMname == "" {
				fmt.Printf("Error: FSM not specified. Terminating.\n")
				os.Exit(1)
			}

		case "fsmmode":
			switch music.Globals.FSMmode {
			case "auto", "manual", "":
				break
			default:
				fmt.Printf("Error: FSM mode \"%s\" is unknown\n", music.Globals.FSMmode)
				os.Exit(1)
			}

		case "rrtype":
			if tdns.Globals.Rrtype == "" {
				fmt.Printf("Error: rrtype not specified\n")
				os.Exit(1)
			}
			rrtype, exist := dns.StringToType[strings.ToUpper(tdns.Globals.Rrtype)]
			if !exist {
				fmt.Printf("Error: rrtype \"%s\" is not known\n", tdns.Globals.Rrtype)
				os.Exit(1)
			}
			if rrtype != dns.TypeKEY && rrtype != dns.TypeDNSKEY {
				fmt.Printf("Error: rrtype \"%s\" is not KEY or DNSKEY\n", tdns.Globals.Rrtype)
				os.Exit(1)
			}

		default:
			fmt.Printf("Unknown required argument: \"%s\"\n", arg)
			os.Exit(1)
		}
	}
}
