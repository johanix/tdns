/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

type ImrOption uint8

const (
	ImrOptRevalidateNS ImrOption = iota + 1
	ImrOptQueryForTransport
	ImrOptAlwaysQueryForTransport
	ImrOptTransportSignalType
	ImrOptQueryForTransportTLSA
	ImrOptUseTransportSignals
	ImrOptAllowLoopbackNameservers
)
