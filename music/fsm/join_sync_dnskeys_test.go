// join_sync_dnskeys_test.go (written by CodeRabbit)

package fsm

import (
	"testing"

	"github.com/johanix/tdns/music"
	"github.com/johanix/tdns/music/mocks"
	"github.com/miekg/dns"
)

func TestJoinSyncDnskeys(t *testing.T) {
	// Set up a mock zone and signers
	zone := &music.Zone{
		Name:     "example.com",
		ZoneType: "normal",
		SGroup: &music.SignerGroup{
			Name: "default",
			SignerMap: map[string]*music.Signer{
				"signer1": {
					Name:   "signer1",
					Method: "mock",
				},
				"signer2": {
					Name:   "signer2",
					Method: "mock",
				},
			},
		},
	}

	// Mock DNSKEY records for each signer
	dnskey1 := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256, // ZSK
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "publickey1",
	}

	dnskey2 := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256, // ZSK
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "publickey2",
	}

	// Set up mock updater
	music.Updaters["mock"] = &mocks.MockUpdater{
		FetchRRsetFunc: func(signer *music.Signer, zoneName, owner string, rrtype uint16) (error, []dns.RR) {
			if signer.Name == "signer1" {
				return nil, []dns.RR{dnskey1}
			}
			if signer.Name == "signer2" {
				return nil, []dns.RR{dnskey2}
			}
			return nil, nil
		},
		UpdateFunc: func(signer *music.Signer, zoneName, owner string, inserts, removes *[][]dns.RR) error {
			// Simulate successful update
			return nil
		},
	}

	// Execute the function under test
	success := JoinSyncDnskeys(zone)
	if !success {
		t.Errorf("JoinSyncDnskeys failed")
	}

	// Verify that keys have been set for signers
	if len(zone.SignerDnskeys) == 0 {
		t.Errorf("SignerDnskeys map is empty")
	}
}

func TestVerifyDnskeysSynched(t *testing.T) {
	// Set up mock zone and signers
	zone := &music.Zone{
		Name:     "example.com",
		ZoneType: "normal",
		SGroup: &music.SignerGroup{
			Name: "default",
			SignerMap: map[string]*music.Signer{
				"signer1": {
					Name:   "signer1",
					Method: "mock",
				},
				"signer2": {
					Name:   "signer2",
					Method: "mock",
				},
			},
		},
	}

	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "publickey",
	}

	// Both signers have the same DNSKEY
	music.Updaters["mock"] = &mocks.MockUpdater{
		FetchRRsetFunc: func(signer *music.Signer, zoneName, owner string, rrtype uint16) (error, []dns.RR) {
			return nil, []dns.RR{dnskey}
		},
	}

	// Execute the function under test
	success := VerifyDnskeysSynched(zone)
	if !success {
		t.Errorf("VerifyDnskeysSynched failed: DNSKEYs are not synchronized")
	}
}

func TestVerifyDnskeysNotSynched(t *testing.T) {
	// Set up mock zone and signers with different DNSKEYs
	zone := &music.Zone{
		Name:     "example.com",
		ZoneType: "normal",
		SGroup: &music.SignerGroup{
			Name: "default",
			SignerMap: map[string]*music.Signer{
				"signer1": {
					Name:   "signer1",
					Method: "mock",
				},
				"signer2": {
					Name:   "signer2",
					Method: "mock",
				},
			},
		},
	}

	dnskey1 := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "publickey1",
	}

	dnskey2 := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "publickey2",
	}

	// Signers have different DNSKEYs
	music.Updaters["mock"] = &mocks.MockUpdater{
		FetchRRsetFunc: func(signer *music.Signer, zoneName, owner string, rrtype uint16) (error, []dns.RR) {
			if signer.Name == "signer1" {
				return nil, []dns.RR{dnskey1}
			}
			if signer.Name == "signer2" {
				return nil, []dns.RR{dnskey2}
			}
			return nil, nil
		},
	}

	// Execute the function under test
	success := VerifyDnskeysSynched(zone)
	if success {
		t.Errorf("VerifyDnskeysSynched should have failed: DNSKEYs are not synchronized")
	}
}
