/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Large KSK support: per-role policy algorithms and bulk-signing warnings.
 */

package imr

import (
	"strings"

	algorithms "github.com/johanix/tdns/v2/algorithms"
)

// DNSKEYTransportPolicy selects how the IMR chooses a transport for DNSKEY
// queries. See DnssecConf.DNSKEYTransport for the semantics of each value.
type DNSKEYTransportPolicy string

const (
	DNSKEYTransportForceUDP       DNSKEYTransportPolicy = "force_udp"
	DNSKEYTransportUseDSSignal    DNSKEYTransportPolicy = "use_ds_signal"
	DNSKEYTransportTryEncrypted   DNSKEYTransportPolicy = "try_encrypted"
	DNSKEYTransportForceEncrypted DNSKEYTransportPolicy = "force_encrypted"
)

// defaultLargeAlgorithmFamilies are the families whose DNSKEY RRsets do not
// fit a UDP answer, as tdns-imr's sample config lists them for
// dnssec.large-algorithms: the post-quantum signature schemes.
var defaultLargeAlgorithmFamilies = []string{"MLDSA", "SLHDSA", "FALCON", "CROSS"}

// largeAlgorithmsOrDefault is set, or for a nil set the default: every
// algorithm the registry knows, implemented or not, in one of the default
// families. An empty set stays empty: no large algorithms.
func largeAlgorithmsOrDefault(set map[uint8]bool) map[uint8]bool {
	if set != nil {
		return set
	}
	def := map[uint8]bool{}
	for _, name := range algorithms.SupportedDNSSEC() {
		for _, family := range defaultLargeAlgorithmFamilies {
			if strings.HasPrefix(name, family) {
				if num, ok := algorithms.AlgorithmNumber(name); ok {
					def[num] = true
				}
			}
		}
	}
	return def
}
