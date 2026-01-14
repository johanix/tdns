/*
 * Johan Stenstam
 */
package cli

import (
	"fmt"
	"log"
	"strings"

	tdns "github.com/johanix/tdns/v0.x"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	// "github.com/DNSSEC-Provisioning/music/music"
	// "github.com/DNSSEC-Provisioning/music/signer"
)

var zoneReadFake = &cobra.Command{
	Use:   "readfake",
	Short: "Create a fake zone from a compiled in string",
	Run: func(cmd *cobra.Command, args []string) {
		err := ReadZoneData(dns.Fqdn(tdns.Globals.Zonename))
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	},
}

func init() {
	ZoneCmd.AddCommand(zoneReadFake)
	// zoneReadFake.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zonename", "z", "", "Zone name to read")
}

func ReadZoneData(zonename string) error {
	log.Printf("ReadZoneData: enter")

	// Create a fake zone for the sidecar identity just to be able to
	// to use to generate the TLSA.
	tmpl := `
$ORIGIN %s
$TTL 86400
%s    IN SOA ns1.%s hostmaster.%s (
          2021010101 ; serial
          3600       ; refresh (1 hour)
          1800       ; retry (30 minutes)
          1209600    ; expire (2 weeks)
          86400      ; minimum (1 day)
          )
%s     IN NS  ns1.%s
ns1.%s IN A   192.0.2.1
`
	zonedatastr := strings.ReplaceAll(tmpl, "%s", zonename)

	log.Printf("ReadZoneData: template zone data:\n%s\n", zonedatastr)

	zd := &tdns.ZoneData{
		ZoneName:  zonename,
		ZoneStore: tdns.MapZone,
		Logger:    log.Default(),
		ZoneType:  tdns.Primary,
		Options:   nil,
		// Data:      cmap.New[tdns.OwnerData](),
	}

	log.Printf("ReadZoneData: reading zone data for zone '%s'", zonename)
	_, _, err := zd.ReadZoneData(zonedatastr, false)
	if err != nil {
		return fmt.Errorf("failed to read zone data: %v", err)
	}
	return nil
}
