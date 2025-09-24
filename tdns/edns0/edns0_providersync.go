/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

// EDNS0 Provider-Synchronization option constants
const (
	EDNS0_PROVIDERSYNC_OPTION_CODE = 65002 // TBD: Replace with actual IANA assigned code

	// OPERATION field values
	PROVIDERSYNC_OP_FORBIDDEN = 0
	PROVIDERSYNC_OP_HELLO     = 1
	PROVIDERSYNC_OP_HEARTBEAT = 2

	// TRANSPORT field bitmask values
	PROVIDERSYNC_TRANSPORT_DNS = 1 << 0
	PROVIDERSYNC_TRANSPORT_API = 1 << 1

	// SYNCHRONIZATION-MODEL field bitmask values
	PROVIDERSYNC_SYNC_LEADERFOLLOWER = 1 << 0
	PROVIDERSYNC_SYNC_PEERTOPEER     = 1 << 1
)

// ProviderSyncOption represents the parsed Provider-Synchronization EDNS(0) option
type ProviderSyncOption struct {
	Operation          uint8
	Transport          uint8
	Synchronization    uint8
	OperationBody      []byte // Variable length, may be empty
}

// CreateProviderSyncOption creates a ProviderSyncOption struct
func CreateProviderSyncOption(op, transport, sync uint8, body []byte) *ProviderSyncOption {
	return &ProviderSyncOption{
		Operation:       op,
		Transport:       transport,
		Synchronization: sync,
		OperationBody:   body,
	}
}

// SerializeProviderSyncOption serializes the ProviderSyncOption to wire format ([]byte)
func SerializeProviderSyncOption(opt *ProviderSyncOption) []byte {
	bodyLen := len(opt.OperationBody)
	data := make([]byte, 4+bodyLen)
	data[0] = opt.Operation
	data[1] = opt.Transport
	data[2] = opt.Synchronization
	data[3] = 0 // Reserved, set to 0 for now (could be used for future expansion)
	copy(data[4:], opt.OperationBody)
	return data
}

// ParseProviderSyncOption parses the wire format ([]byte) into a ProviderSyncOption struct
func ParseProviderSyncOption(data []byte) (*ProviderSyncOption, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ProviderSyncOption: data too short")
	}
	return &ProviderSyncOption{
		Operation:       data[0],
		Transport:       data[1],
		Synchronization: data[2],
		OperationBody:   data[4:],
	}, nil
}

// AddProviderSyncOption adds a ProviderSyncOption to an existing OPT RR
func AddProviderSyncOption(opt *dns.OPT, pso *ProviderSyncOption) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}
	optionData := SerializeProviderSyncOption(pso)
	option := &dns.EDNS0_LOCAL{
		Code: EDNS0_PROVIDERSYNC_OPTION_CODE,
		Data: optionData,
	}
	opt.Option = append(opt.Option, option)
	return nil
}

// ExtractProviderSyncOption extracts the ProviderSyncOption from an OPT RR
// Returns the parsed option and true if found, or nil and false if not found
func ExtractProviderSyncOption(opt *dns.OPT) (*ProviderSyncOption, bool) {
	if opt == nil {
		return nil, false
	}
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_PROVIDERSYNC_OPTION_CODE {
				pso, err := ParseProviderSyncOption(localOpt.Data)
				if err == nil {
					return pso, true
				}
			}
		}
	}
	return nil, false
}
