/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package mcmd

import (
	"fmt"
	"os"
	"strings"

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
			if tdns.Globals.Zonename == "" {
				fmt.Printf("Error: zone name not specified using --zone flag\n")
				os.Exit(1)
			}
			tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)

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
