/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Large KSK support: per-role policy algorithms and bulk-signing warnings.
 */

package imr

// DNSKEYTransportPolicy selects how the IMR chooses a transport for DNSKEY
// queries. See DnssecConf.DNSKEYTransport for the semantics of each value.
type DNSKEYTransportPolicy string

const (
	DNSKEYTransportForceUDP       DNSKEYTransportPolicy = "force_udp"
	DNSKEYTransportUseDSSignal    DNSKEYTransportPolicy = "use_ds_signal"
	DNSKEYTransportTryEncrypted   DNSKEYTransportPolicy = "try_encrypted"
	DNSKEYTransportForceEncrypted DNSKEYTransportPolicy = "force_encrypted"
)
