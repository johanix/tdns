/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

type Option uint8

const (
	OptRevalidateNS Option = iota + 1
	OptQueryForTransport
	OptAlwaysQueryForTransport
	OptTransportSignalType
	OptQueryForTransportTLSA
	OptUseTransportSignals
	OptAllowLoopbackNameservers
)
