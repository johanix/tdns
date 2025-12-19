/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS RRtypes for HPKE-based key distribution:
 * - KMCTRL: Key Management Control record
 * - KMREQ: Key Management Request record
 * - KMPKG: Key Management Package record
 */

package hpke

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Experimental RRtype codes (to be replaced with IANA assignments)
const (
	TypeKMCTRL = 65010 // Key Management Control
	TypeKMREQ  = 65011 // Key Management Request
	TypeKMPKG  = 65012 // Key Management Package
)

func init() {
	RegisterKMCTRLRR()
	RegisterKMREQRR()
	RegisterKMPKGRR()
}

// KMCTRL - Key Management Control record
// Format: <distribution-id> <keyid> <state> <timestamp> <zone>
// Example: kdc.example.com. IN KMCTRL a1b2c3d4e5f6 12345 standby 1704067200 example.com.
type KMCTRL struct {
	DistributionID string    // Hex string (e.g., "a1b2c3d4e5f6")
	KeyID          uint16    // DNSSEC key ID
	State          KeyState  // "published" | "active" | "standby" | "distributed"
	Timestamp      uint64    // Unix timestamp
	Zone           string    // Zone name this key is for (e.g., "example.com.")
}

func NewKMCTRL() dns.PrivateRdata { return new(KMCTRL) }

func (rd KMCTRL) String() string {
	return fmt.Sprintf("%s %d %s %d %s",
		rd.DistributionID,
		rd.KeyID,
		string(rd.State),
		rd.Timestamp,
		rd.Zone,
	)
}

func (rd *KMCTRL) Parse(txt []string) error {
	if len(txt) != 5 {
		return errors.New("KMCTRL requires distribution-id, keyid, state, timestamp, and zone")
	}

	// Validate distribution ID (hex string)
	distributionID := txt[0]
	if _, err := hex.DecodeString(distributionID); err != nil {
		return fmt.Errorf("invalid KMCTRL distribution-id (must be hex): %s", distributionID)
	}

	// Parse key ID
	keyID, err := strconv.ParseUint(txt[1], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid KMCTRL keyid: %s", txt[1])
	}

	// Parse state
	state := KeyState(txt[2])
	switch state {
	case KeyStatePublished, KeyStateActive, KeyStateStandby, KeyStateDistributed:
		// Valid states
	default:
		return fmt.Errorf("invalid KMCTRL state: %s (must be published, active, standby, or distributed)", txt[2])
	}

	// Parse timestamp
	timestamp, err := strconv.ParseUint(txt[3], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid KMCTRL timestamp: %s", txt[3])
	}

	// Parse zone name
	zone := txt[4]
	if zone == "" {
		return errors.New("KMCTRL zone name cannot be empty")
	}

	rd.DistributionID = distributionID
	rd.KeyID = uint16(keyID)
	rd.State = state
	rd.Timestamp = timestamp
	rd.Zone = zone

	return nil
}

func (rd *KMCTRL) Pack(buf []byte) (int, error) {
	off := 0

	// Pack distribution ID (hex string, length-prefixed)
	distIDBytes := []byte(rd.DistributionID)
	if len(distIDBytes) > 255 {
		return off, errors.New("distribution ID too long")
	}
	buf[off] = byte(len(distIDBytes))
	off++
	copy(buf[off:], distIDBytes)
	off += len(distIDBytes)

	// Pack key ID (uint16)
	buf[off] = byte(rd.KeyID >> 8)
	buf[off+1] = byte(rd.KeyID)
	off += 2

	// Pack state (string, length-prefixed)
	stateBytes := []byte(string(rd.State))
	if len(stateBytes) > 255 {
		return off, errors.New("state string too long")
	}
	buf[off] = byte(len(stateBytes))
	off++
	copy(buf[off:], stateBytes)
	off += len(stateBytes)

	// Pack timestamp (uint64)
	for i := 0; i < 8; i++ {
		buf[off+i] = byte(rd.Timestamp >> (56 - i*8))
	}
	off += 8

	// Pack zone name (string, length-prefixed)
	zoneBytes := []byte(rd.Zone)
	if len(zoneBytes) > 255 {
		return off, errors.New("zone name too long")
	}
	buf[off] = byte(len(zoneBytes))
	off++
	copy(buf[off:], zoneBytes)
	off += len(zoneBytes)

	return off, nil
}

func (rd *KMCTRL) Unpack(buf []byte) (int, error) {
	off := 0

	// Unpack distribution ID
	if len(buf) < off+1 {
		return off, errors.New("buffer too short for distribution ID length")
	}
	distIDLen := int(buf[off])
	off++
	if len(buf) < off+distIDLen {
		return off, errors.New("buffer too short for distribution ID")
	}
	rd.DistributionID = string(buf[off : off+distIDLen])
	off += distIDLen

	// Unpack key ID
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for key ID")
	}
	rd.KeyID = uint16(buf[off])<<8 | uint16(buf[off+1])
	off += 2

	// Unpack state
	if len(buf) < off+1 {
		return off, errors.New("buffer too short for state length")
	}
	stateLen := int(buf[off])
	off++
	if len(buf) < off+stateLen {
		return off, errors.New("buffer too short for state")
	}
	rd.State = KeyState(string(buf[off : off+stateLen]))
	off += stateLen

	// Unpack timestamp
	if len(buf) < off+8 {
		return off, errors.New("buffer too short for timestamp")
	}
	rd.Timestamp = uint64(buf[off])<<56 | uint64(buf[off+1])<<48 |
		uint64(buf[off+2])<<40 | uint64(buf[off+3])<<32 |
		uint64(buf[off+4])<<24 | uint64(buf[off+5])<<16 |
		uint64(buf[off+6])<<8 | uint64(buf[off+7])
	off += 8

	// Unpack zone name
	if len(buf) < off+1 {
		return off, errors.New("buffer too short for zone name length")
	}
	zoneLen := int(buf[off])
	off++
	if len(buf) < off+zoneLen {
		return off, errors.New("buffer too short for zone name")
	}
	rd.Zone = string(buf[off : off+zoneLen])
	off += zoneLen

	return off, nil
}

func (rd *KMCTRL) Copy(dest dns.PrivateRdata) error {
	d := dest.(*KMCTRL)
	d.DistributionID = rd.DistributionID
	d.KeyID = rd.KeyID
	d.State = rd.State
	d.Timestamp = rd.Timestamp
	d.Zone = rd.Zone
	return nil
}

func (rd *KMCTRL) Len() int {
	return 1 + len(rd.DistributionID) + // distribution ID length + data
		2 + // key ID
		1 + len(string(rd.State)) + // state length + data
		8 + // timestamp
		1 + len(rd.Zone) // zone name length + data
}

func RegisterKMCTRLRR() error {
	dns.PrivateHandle("KMCTRL", TypeKMCTRL, NewKMCTRL)
	return nil
}

// KMREQ - Key Management Request record
// Format: <ephemeral-pubkey> (base64-encoded)
// The QNAME encodes: <distribution-id>.<zone>.kdc.example.com
type KMREQ struct {
	EphemeralPubKey []byte // X25519 public key (32 bytes, base64-encoded in text)
}

func NewKMREQ() dns.PrivateRdata { return new(KMREQ) }

func (rd KMREQ) String() string {
	return base64.StdEncoding.EncodeToString(rd.EphemeralPubKey)
}

func (rd *KMREQ) Parse(txt []string) error {
	if len(txt) != 1 {
		return errors.New("KMREQ requires ephemeral public key")
	}

	// Decode base64-encoded public key
	pubKey, err := base64.StdEncoding.DecodeString(txt[0])
	if err != nil {
		return fmt.Errorf("invalid KMREQ ephemeral public key (base64 decode failed): %v", err)
	}

	// X25519 public key must be 32 bytes
	if len(pubKey) != 32 {
		return fmt.Errorf("invalid KMREQ ephemeral public key length: %d (expected 32)", len(pubKey))
	}

	rd.EphemeralPubKey = pubKey
	return nil
}

func (rd *KMREQ) Pack(buf []byte) (int, error) {
	if len(rd.EphemeralPubKey) != 32 {
		return 0, errors.New("KMREQ ephemeral public key must be 32 bytes")
	}
	copy(buf, rd.EphemeralPubKey)
	return 32, nil
}

func (rd *KMREQ) Unpack(buf []byte) (int, error) {
	if len(buf) < 32 {
		return 0, errors.New("buffer too short for KMREQ ephemeral public key")
	}
	rd.EphemeralPubKey = make([]byte, 32)
	copy(rd.EphemeralPubKey, buf[:32])
	return 32, nil
}

func (rd *KMREQ) Copy(dest dns.PrivateRdata) error {
	d := dest.(*KMREQ)
	d.EphemeralPubKey = make([]byte, len(rd.EphemeralPubKey))
	copy(d.EphemeralPubKey, rd.EphemeralPubKey)
	return nil
}

func (rd *KMREQ) Len() int {
	return 32 // X25519 public key is always 32 bytes
}

func RegisterKMREQRR() error {
	dns.PrivateHandle("KMREQ", TypeKMREQ, NewKMREQ)
	return nil
}

// KMPKG - Key Management Package record
// Format: <encrypted-key-data> (base64-encoded HPKE-encrypted private key)
// May be split across multiple KMPKG records if large
type KMPKG struct {
	EncryptedData []byte // HPKE-encrypted key material (base64-encoded in text)
	Sequence      uint16 // Sequence number if split across multiple records (0 = single record)
	Total         uint16 // Total number of records if split (1 = single record)
}

func NewKMPKG() dns.PrivateRdata { return new(KMPKG) }

func (rd KMPKG) String() string {
	encDataStr := base64.StdEncoding.EncodeToString(rd.EncryptedData)
	if rd.Total > 1 {
		return fmt.Sprintf("%s %d %d", encDataStr, rd.Sequence, rd.Total)
	}
	return encDataStr
}

func (rd *KMPKG) Parse(txt []string) error {
	if len(txt) < 1 || len(txt) > 3 {
		return errors.New("KMPKG requires encrypted data and optionally sequence/total")
	}

	// Decode base64-encoded encrypted data
	encData, err := base64.StdEncoding.DecodeString(txt[0])
	if err != nil {
		return fmt.Errorf("invalid KMPKG encrypted data (base64 decode failed): %v", err)
	}

	rd.EncryptedData = encData
	rd.Sequence = 0
	rd.Total = 1

	// Parse sequence and total if present
	if len(txt) >= 3 {
		seq, err := strconv.ParseUint(txt[1], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid KMPKG sequence: %s", txt[1])
		}
		total, err := strconv.ParseUint(txt[2], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid KMPKG total: %s", txt[2])
		}
		rd.Sequence = uint16(seq)
		rd.Total = uint16(total)
	}

	return nil
}

func (rd *KMPKG) Pack(buf []byte) (int, error) {
	off := 0

	// Pack sequence and total (uint16 each)
	buf[off] = byte(rd.Sequence >> 8)
	buf[off+1] = byte(rd.Sequence)
	off += 2
	buf[off] = byte(rd.Total >> 8)
	buf[off+1] = byte(rd.Total)
	off += 2

	// Pack encrypted data length (uint16)
	dataLen := len(rd.EncryptedData)
	if dataLen > 65535 {
		return off, errors.New("KMPKG encrypted data too long")
	}
	buf[off] = byte(dataLen >> 8)
	buf[off+1] = byte(dataLen)
	off += 2

	// Pack encrypted data
	copy(buf[off:], rd.EncryptedData)
	off += dataLen

	return off, nil
}

func (rd *KMPKG) Unpack(buf []byte) (int, error) {
	off := 0

	// Unpack sequence
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for KMPKG sequence")
	}
	rd.Sequence = uint16(buf[off])<<8 | uint16(buf[off+1])
	off += 2

	// Unpack total
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for KMPKG total")
	}
	rd.Total = uint16(buf[off])<<8 | uint16(buf[off+1])
	off += 2

	// Unpack encrypted data length
	if len(buf) < off+2 {
		return off, errors.New("buffer too short for KMPKG data length")
	}
	dataLen := int(buf[off])<<8 | int(buf[off+1])
	off += 2

	// Unpack encrypted data
	if len(buf) < off+dataLen {
		return off, errors.New("buffer too short for KMPKG encrypted data")
	}
	rd.EncryptedData = make([]byte, dataLen)
	copy(rd.EncryptedData, buf[off:off+dataLen])
	off += dataLen

	return off, nil
}

func (rd *KMPKG) Copy(dest dns.PrivateRdata) error {
	d := dest.(*KMPKG)
	d.EncryptedData = make([]byte, len(rd.EncryptedData))
	copy(d.EncryptedData, rd.EncryptedData)
	d.Sequence = rd.Sequence
	d.Total = rd.Total
	return nil
}

func (rd *KMPKG) Len() int {
	return 2 + // sequence
		2 + // total
		2 + // data length
		len(rd.EncryptedData) // encrypted data
}

func RegisterKMPKGRR() error {
	dns.PrivateHandle("KMPKG", TypeKMPKG, NewKMPKG)
	return nil
}

// ParseQnameForKMREQ extracts distribution ID and zone from KMREQ QNAME
// Format: <distribution-id>.<zone>.<control-zone>
// The control zone is needed to correctly extract multi-label zones
func ParseQnameForKMREQ(qname string, controlZone string) (distributionID, zone string, err error) {
	// Remove trailing dot if present
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	labels := dns.SplitDomainName(qname)
	if len(labels) < 3 {
		return "", "", fmt.Errorf("invalid KMREQ QNAME format: %s (need at least distribution-id.zone.control-zone)", qname)
	}

	// Distribution ID is the first label
	distributionID = labels[0]

	// Validate distribution ID is hex
	if _, err := hex.DecodeString(distributionID); err != nil {
		return "", "", fmt.Errorf("invalid distribution ID in QNAME: %s (must be hex)", distributionID)
	}

	// Extract control zone labels (remove trailing dot if present)
	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}
	controlLabels := dns.SplitDomainName(controlZoneClean)
	
	if len(controlLabels) == 0 {
		return "", "", fmt.Errorf("invalid control zone: %s", controlZone)
	}

	// The zone is everything between the distribution ID and the control zone
	// QNAME format: <distribution-id>.<zone-labels>.<control-zone-labels>
	// We need at least: distribution-id (1) + zone (1+) + control-zone (1+) = 3+ labels
	if len(labels) < len(controlLabels) + 2 {
		return "", "", fmt.Errorf("invalid KMREQ QNAME format: %s (too few labels)", qname)
	}

	// Check that the last N labels match the control zone
	controlStartIdx := len(labels) - len(controlLabels)
	for i := 0; i < len(controlLabels); i++ {
		if labels[controlStartIdx+i] != controlLabels[i] {
			return "", "", fmt.Errorf("QNAME %s does not end with control zone %s", qname, controlZone)
		}
	}

	// Zone is everything between distribution ID (index 0) and control zone
	// Zone labels are from index 1 to controlStartIdx-1
	if controlStartIdx <= 1 {
		return "", "", fmt.Errorf("invalid KMREQ QNAME format: %s (no zone labels found)", qname)
	}

	zoneLabels := labels[1:controlStartIdx]
	zone = strings.Join(zoneLabels, ".")
	
	// Ensure zone is FQDN
	zone = dns.Fqdn(zone)

	return distributionID, zone, nil
}

// BuildKMREQQname constructs a QNAME for a KMREQ query
// All inputs are expected to be FQDN (dot-terminated), but we handle both cases
// Format: <distribution-id>.<zone>.<control-zone>
func BuildKMREQQname(distributionID, zone, controlZone string) string {
	// Strip trailing dots to avoid ".." in the QNAME
	zoneClean := zone
	if len(zoneClean) > 0 && zoneClean[len(zoneClean)-1] == '.' {
		zoneClean = zoneClean[:len(zoneClean)-1]
	}
	
	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}
	
	// Build QNAME: <distribution-id>.<zone>.<control-zone>.
	// Always ensure the result is FQDN (ends with ".")
	return fmt.Sprintf("%s.%s.%s.", distributionID, zoneClean, controlZoneClean)
}

