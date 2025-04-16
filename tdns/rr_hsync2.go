/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// example.com. IN MSIGNER ON API multisigner.provider.com.
// example.com. IN MSIGNER OFF 53 ms-conductor.signerco.net.

func init() {
	RegisterHsync2RR()
}

//const TypeHSYNC = 0x0F9D

type HSYNC2 struct {
	State    uint8  // 0=OFF, 1=ON
	Flags    uint16 // Will hold both NSmgmt and Sign bits
	Identity string
	Upstream string
}

// Define bit positions and masks in the Flags field
const (
	// Single bit flags
	FlagNSmgmt uint16 = 1 << 0 // bit 0: 0=OWNER, 1=AGENT
	FlagSign   uint16 = 1 << 1 // bit 1: 0=NOSIGN, 1=SIGN
	FlagAudit  uint16 = 1 << 2 // bit 2: 0=NO, 1=YES

	// Multi-bit fields
	ParentSyncMask  uint16 = 0x7 << 3 // bits 3-5: 3 bits for parentsync
	ParentSyncShift uint   = 3        // shift amount for parentsync field
)

// ParentSync values (using iota for sequential values)
const (
	ParentSyncOwner uint16 = iota
	ParentSyncNotify
	ParentSyncUpdate
	ParentSyncAPI
	// room for 4 more values
)

// Keep these constants for State
const (
	Hsync2StateON  uint8 = 1
	Hsync2StateOFF uint8 = 0
)

// Keep the State mappings
var Hsync2StateToString = map[uint8]string{
	Hsync2StateON:  "ON",
	Hsync2StateOFF: "OFF",
}

var StringToHsync2State = map[string]uint8{
	"ON":  Hsync2StateON,
	"OFF": Hsync2StateOFF,
}

func NewHSYNC2() dns.PrivateRdata { return new(HSYNC2) }

func (rd HSYNC2) String() string {
	// Build the flags string
	flags := make([]string, 0, 4) // increased capacity for new flags

	// Add nsmgmt flag
	if rd.IsAgent() {
		flags = append(flags, "nsmgmt=agent")
	} else {
		flags = append(flags, "nsmgmt=owner")
	}

	// Add sign flag
	if rd.DoSign() {
		flags = append(flags, "sign=yes")
	} else {
		flags = append(flags, "sign=no")
	}

	// Add audit flag
	if rd.DoAudit() {
		flags = append(flags, "audit=yes")
	} else {
		flags = append(flags, "audit=no")
	}

	// Add parentsync flag
	if psStr, ok := parentSyncToString[rd.GetParentSync()]; ok {
		flags = append(flags, "parentsync="+psStr)
	} else {
		flags = append(flags, "parentsync=unknown")
	}

	// Combine flags with semicolons
	flagStr := strings.Join(flags, "; ")

	return fmt.Sprintf("%s \"%s\" %s %s",
		Hsync2StateToString[rd.State],
		flagStr,
		rd.Identity,
		rd.Upstream)
}

func (rd *HSYNC2) Parse(txt []string) error {
	if len(txt) != 4 {
		return errors.New("HSYNC2 requires: State, flags-string, identity and upstream domain names")
	}

	// Parse State
	state, exist := StringToHsync2State[txt[0]]
	if !exist {
		return fmt.Errorf("invalid HSYNC2 state: %s", txt[0])
	}
	rd.State = state

	// Parse flags string - remove quotes and split on semicolons
	flagsStr := strings.Trim(txt[1], "\"")
	flagPairs := strings.Split(flagsStr, ";")

	// Initialize flags
	rd.Flags = 0

	// Track which flags we've seen
	seenFlags := map[string]bool{
		"nsmgmt":     false,
		"sign":       false,
		"audit":      false,
		"parentsync": false,
	}

	// Process each flag
	for _, pair := range flagPairs {
		pair = strings.TrimSpace(pair)
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			return fmt.Errorf("invalid flag format: %s", pair)
		}

		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.ToLower(strings.TrimSpace(kv[1]))

		// Mark this flag as seen
		seenFlags[key] = true

		switch key {
		case "nsmgmt":
			switch value {
			case "owner":
				rd.SetNSmgmt(false)
			case "agent":
				rd.SetNSmgmt(true)
			default:
				return fmt.Errorf("invalid nsmgmt value: %s", value)
			}
		case "sign":
			switch value {
			case "yes":
				rd.SetSign(true)
			case "no":
				rd.SetSign(false)
			default:
				return fmt.Errorf("invalid sign value: %s", value)
			}
		case "audit":
			switch value {
			case "yes":
				rd.SetAudit(true)
			case "no":
				rd.SetAudit(false)
			default:
				return fmt.Errorf("invalid audit value: %s", value)
			}
		case "parentsync":
			if psValue, ok := stringToParentSync[value]; ok {
				if err := rd.SetParentSync(psValue); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("invalid parentsync value: %s", value)
			}
		default:
			return fmt.Errorf("unknown flag: %s", key)
		}
	}

	// Check that all required flags were present
	for flag, seen := range seenFlags {
		if !seen {
			return fmt.Errorf("missing required flag: %s", flag)
		}
	}

	// Parse Identity
	id := dns.Fqdn(txt[2])
	if _, ok := dns.IsDomainName(id); !ok {
		return fmt.Errorf("invalid HSYNC2 identity: %s", txt[2])
	}
	rd.Identity = id

	// Parse Upstream
	upstream := dns.Fqdn(txt[3])
	if _, ok := dns.IsDomainName(upstream); !ok {
		return fmt.Errorf("invalid HSYNC2 upstream: %s", txt[3])
	}
	rd.Upstream = upstream

	return nil
}

func (rd *HSYNC2) Pack(buf []byte) (int, error) {
	var off int
	off, err := packUint8(rd.State, buf, off)
	if err != nil {
		return off, err
	}

	off, err = packUint16(rd.Flags, buf, off)
	if err != nil {
		return off, err
	}

	off, err = dns.PackDomainName(rd.Identity, buf, off, nil, false)
	if err != nil {
		return off, err
	}

	off, err = dns.PackDomainName(rd.Upstream, buf, off, nil, false)
	if err != nil {
		return off, err
	}

	return off, nil
}

func (rd *HSYNC2) Unpack(buf []byte) (int, error) {
	var off = 0
	var err error

	rd.State, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Flags, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}

	rd.Identity, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}

	rd.Upstream, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rd *HSYNC2) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*HSYNC2)
	d.State = rd.State
	d.Flags = rd.Flags
	d.Identity = rd.Identity
	d.Upstream = rd.Upstream
	return nil
}

func (rd *HSYNC2) Len() int {
	return 1 + 2 + len(rd.Identity) + len(rd.Upstream) + 2 // +2 for two terminating zeros
}

func RegisterHsync2RR() error {
	dns.PrivateHandle("HSYNC2", TypeHSYNC2, NewHSYNC2)
	// log.Printf("Registered HSYNC RR")
	return nil
}

// Helper functions for flag handling
func (rd *HSYNC2) SetNSmgmt(isAgent bool) {
	if isAgent {
		rd.Flags |= FlagNSmgmt
	} else {
		rd.Flags &^= FlagNSmgmt
	}
}

func (rd *HSYNC2) SetSign(doSign bool) {
	if doSign {
		rd.Flags |= FlagSign
	} else {
		rd.Flags &^= FlagSign
	}
}

func (rd *HSYNC2) IsAgent() bool {
	return (rd.Flags & FlagNSmgmt) != 0
}

func (rd *HSYNC2) DoSign() bool {
	return (rd.Flags & FlagSign) != 0
}

// Add helper functions for the new flags
func (rd *HSYNC2) SetAudit(enabled bool) {
	if enabled {
		rd.Flags |= FlagAudit
	} else {
		rd.Flags &^= FlagAudit
	}
}

func (rd *HSYNC2) DoAudit() bool {
	return (rd.Flags & FlagAudit) != 0
}

func (rd *HSYNC2) SetParentSync(value uint16) error {
	if value >= 8 { // 3 bits = 8 values
		return fmt.Errorf("invalid parentsync value: %d", value)
	}
	// Clear the field
	rd.Flags &^= ParentSyncMask
	// Set the new value
	rd.Flags |= (value << ParentSyncShift) & ParentSyncMask
	return nil
}

func (rd *HSYNC2) GetParentSync() uint16 {
	return (rd.Flags & ParentSyncMask) >> ParentSyncShift
}

// Helper for parentsync string conversion
var parentSyncToString = map[uint16]string{
	ParentSyncOwner:  "owner",
	ParentSyncNotify: "notify",
	ParentSyncUpdate: "update",
	ParentSyncAPI:    "api",
}

var stringToParentSync = map[string]uint16{
	"owner":  ParentSyncOwner,
	"notify": ParentSyncNotify,
	"update": ParentSyncUpdate,
	"api":    ParentSyncAPI,
}
