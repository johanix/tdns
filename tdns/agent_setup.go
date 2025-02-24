/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"
)

type AgentConf struct {
	Identity string `validate:"required,hostname"`
	Api      AgentApiConf
	Dns      AgentDnsConf
}

type AgentApiConf struct {
	Addresses struct {
		Publish []string
		Listen  []string
	}
	BaseUrl  string
	Port     uint16
	Cert     string
	Key      string
	CertData string
	KeyData  string
}

type AgentDnsConf struct {
	Addresses struct {
		Publish []string
		Listen  []string
	}
	Port uint16
}

// Commenting out MSA-specific functions
/*
func LoadMusicConfig(mconf *Config, appMode string, safemode bool) error {
	if Globals.Debug {
		log.Printf("LoadMusicConfig: enter")
	}
	var cfgfile string
	switch appMode {
	case "server":
		cfgfile = DefaultCfgFile
	case "msa", "msa-cli":
		cfgfile = DefaultMSACfgFile
	default:
		log.Fatalf("Unknown app mode: %q", appMode)
	}

	if Globals.Debug {
		fmt.Printf("*** LoadMusicConfig: reloading config from %q. Safemode: %v\n", cfgfile, safemode)
	}
	if safemode {
		tmpviper := viper.New()
		tmpviper.SetConfigFile(cfgfile)

		var err error
		switch appMode {
		case "server":
			err = tmpviper.ReadInConfig()
		case "msa", "msa-cli":
			err = tmpviper.MergeInConfig()
		default:
			log.Fatalf("Unknown app mode: %q", appMode)
		}
		if err != nil {
			return err
		}

		err = ValidateConfig(tmpviper, cfgfile, appMode, true) // will not terminate on error
		if err != nil {
			return err
		}
		fmt.Printf("LoadConfig: safe config validation succeeded, no errors. Now reloading.\n")
	}

	viper.SetConfigFile(cfgfile)

	var err error
	switch appMode {
	case "server":
		err = viper.ReadInConfig()
		if Globals.Debug {
			fmt.Printf("*** LoadMusicConfig: server config merged from %q\n", cfgfile)
		}
	case "msa":
		err = viper.MergeInConfig()
		if err != nil {
			log.Printf("Error from viper.MergeInConfig: %v", err)
			return err
		}
		if Globals.Debug {
			fmt.Printf("*** LoadMusicConfig: MSA config merged from %q\n", cfgfile)
		}
	case "msa-cli":
		err = viper.MergeInConfig()
		if Globals.Debug {
			fmt.Printf("*** LoadMusicConfig: msa-cli config merged from %q\n", cfgfile)
		}
	default:
		log.Fatalf("Unknown app mode: %q", appMode)
	}
	if err != nil {
		log.Fatalf("Could not load config (%s)", err)
	}

	err = ValidateConfig(nil, cfgfile, appMode, false) // will terminate on error
	if err != nil {
		return err
	}

	err = viper.Unmarshal(&mconf)
	if err != nil {
		log.Fatalf("Error unmarshalling MUSIC config into struct: %v", err)
	}
	// dump.P(mconf.MSA)

	CliConf.Verbose = viper.GetBool("common.verbose")
	CliConf.Debug = viper.GetBool("common.debug")

	if Globals.Debug {
		log.Printf("LoadMusicConfig: exit")
	}
	return nil
}

func (mconf *Config) LoadMSAConfig(tconf *Config, all_zones []string) error {
	if Globals.Debug {
		log.Printf("LoadMSAConfig: enter")
	}

	if len(mconf.MSA.Api.Addresses.Listen) == 0 && len(mconf.MSA.Dns.Addresses.Listen) == 0 {
		dump.P(mconf.MSA)
		return errors.New("LoadMSAConfig: neither MSA syncapi nor syncdns addresses set in config file")
	}

	mconf.MSA.Identity = dns.Fqdn(mconf.MSA.Identity)
	if !slices.Contains(all_zones, mconf.MSA.Identity) {
		_, err := mconf.SetupMSAAutoZone(mconf.MSA.Identity, tconf)
		if err != nil {
			return fmt.Errorf("LoadMSAConfig: failed to create minimal auto zone for MSA identity %q: %v", mconf.MSA.Identity, err)
		}
	}

	if len(mconf.MSA.Api.Addresses.Publish) > 0 {
		err := mconf.SetupApiMethod(tconf, all_zones)
		if err != nil {
			return fmt.Errorf("LoadMSAConfig: failed to setup API method: %v", err)
		}
	}

	if len(mconf.MSA.Dns.Addresses.Publish) > 0 {
		err := mconf.SetupDnsMethod()
		if err != nil {
			return fmt.Errorf("LoadMSAConfig: failed to setup DNS method: %v", err)
		}
	}

	if Globals.Debug {
		log.Printf("LoadMSAConfig: exit")
	}

	return nil
}

func (mconf *Config) SetupMSAAutoZone(zonename string, tconf *Config) (*ZoneData, error) {
	log.Printf("SetupMSAAutoZone: Zone %q not found, creating a minimal auto zone", zonename)

	addrs, err := tconf.FindNameserverAddrs()
	if err != nil {
		return nil, fmt.Errorf("SetupMSAAutoZone: failed to find nameserver addresses: %v", err)
	}

	zd, err := mconf.Internal.KeyDB.CreateAutoZone(zonename, addrs)
	if err != nil {
		return nil, fmt.Errorf("SetupMSAAutoZone: failed to create minimal auto zone for MSA auto zone %q: %v", zonename, err)
	}
	zd.Options[OptAllowUpdates] = true
	zd.MusicSyncQ = mconf.Internal.MusicSyncQ

	// A MSA auto zone will try to set up delegation syncing with the parent.
	zd.Options[OptDelSyncChild] = true
	err = zd.SetupZoneSync(tconf.Internal.DelegationSyncQ)
	if err != nil {
		return nil, fmt.Errorf("SetupMSAAutoZone: failed to set up delegation syncing for MSA auto zone %q: %v", zonename, err)
	}

	return zd, nil
}

func (mconf *Config) SetupApiMethod(tconf *Config, all_zones []string) error {
	apiname := "api." + mconf.MSA.Identity

	certFile := viper.GetString("msa.api.cert")
	keyFile := viper.GetString("msa.api.key")

	if certFile == "" || keyFile == "" {
		return errors.New("LoadMSAConfig: MSA API identity defined, but cert or key file not set in config file")
	}

	certPEM, err := os.ReadFile(mconf.MSA.Api.Cert)
	if err != nil {
		return fmt.Errorf("LoadMSAConfig: error reading cert file: %v", err)
	}

	keyPEM, err := os.ReadFile(mconf.MSA.Api.Key)
	if err != nil {
		return fmt.Errorf("LoadMSAConfig: error reading key file: %v", err)
	}

	mconf.MSA.Api.CertData = string(certPEM)
	mconf.MSA.Api.KeyData = string(keyPEM)

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("LoadMSAConfig: failed to parse certificate PEM")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("LoadMSAConfig: failed to parse certificate: %v", err)
	}

	// Extract the CN from the certificate
	certCN := cert.Subject.CommonName

	// Compare the CN with the expected CN
	if certCN != "api."+mconf.MSA.Identity {
		log.Printf("LoadMSAConfig: Error: mconf.MSA.Identity: %q viper: %q", mconf.MSA.Identity, viper.GetString("msa.identity"))
		dump.P(mconf.MSA)
		return fmt.Errorf("LoadMSAConfig: Error: MSA certificate CN %q does not match MSA API target %q", certCN, mconf.MSA.Identity)
	}

	log.Printf("LoadMSAConfig: cert CN %q matches MSA API identity 'api.%s'", certCN, mconf.MSA.Identity)

	du := createDeferredUpdate(
		mconf.MSA.Identity,
		fmt.Sprintf("Publish TLSA RR for MSA API target %q", apiname),
		func() error {
			zd, ok := Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadMSAConfig: Action: zone data for MSA identity %q still not found", mconf.MSA.Identity)
			}

			log.Printf("LoadMSAConfig: sending PING command to MSA  %q", mconf.MSA.Identity)
			zd.KeyDB.UpdateQ <- UpdateRequest{
				Cmd: "PING",
			}

			// MSA API identity
			log.Printf("LoadMSAConfig: publishing TLSA RR for MSA API target %q", apiname)

			err = zd.PublishTlsaRR(apiname, mconf.MSA.Api.Port, string(certPEM))
			if err != nil {
				return fmt.Errorf("LoadMSAConfig: failed to publish TLSA RR: %v", err)
			}

			log.Printf("LoadMSAConfig: Successfully published TLSA RR for MSA API target %q", apiname)
			return nil
		},
	)

	mconf.Internal.DeferredUpdateQ <- du

	du = createDeferredUpdate(
		mconf.MSA.Identity,
		fmt.Sprintf("Publish URI RR for MSA API target %q", apiname),
		func() error {
			zd, ok := Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadMSAConfig: Action: zone data for MSA identity %q still not found", mconf.MSA.Identity)
			}

			log.Printf("LoadMSAConfig: sending PING command to MSA %q", mconf.MSA.Identity)
			zd.KeyDB.UpdateQ <- UpdateRequest{
				Cmd: "PING",
			}

			// MSA API identity
			log.Printf("LoadMSAConfig: publishing URI RR for MSA API target %q", apiname)

			err = zd.PublishUriRR(apiname, mconf.MSA.Api.BaseUrl, mconf.MSA.Api.Port)
			if err != nil {
				return fmt.Errorf("LoadMSAConfig: failed to publish URI RR: %v", err)
			}

			log.Printf("LoadMSAConfig: Successfully published TLSA RR for MSA API target %q", apiname)
			return nil
		},
	)
	mconf.Internal.DeferredUpdateQ <- du

	du = createDeferredUpdate(
		mconf.MSA.Identity,
		fmt.Sprintf("Publish SVCB RR for MSA API target %q", apiname),
		func() error {
			zd, ok := Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadMSAConfig: Action: zone data for MSA identity %q still not found", mconf.MSA.Identity)
			}

			var ipv4hint, ipv6hint []net.IP
			var value []dns.SVCBKeyValue
			if len(mconf.MSA.Api.Addresses.Publish) > 0 {
				for _, addr := range mconf.MSA.Api.Addresses.Publish {
					ip := net.ParseIP(addr)
					if ip == nil {
						log.Printf("LoadMSAConfig: failed to parse address %q", addr)
						continue
					}
					if ip.To4() != nil {
						ipv4hint = append(ipv4hint, ip)
					} else {
						ipv6hint = append(ipv6hint, ip)
					}
				}
			}

			if mconf.MSA.Api.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: mconf.MSA.Api.Port})
			}

			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}

			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			err = zd.PublishSvcbRR(apiname, mconf.MSA.Api.Port, value)
			if err != nil {
				return fmt.Errorf("LoadMSAConfig: failed to publish MSA API target SVCB RR: %v", err)
			}

			log.Printf("LoadMSAConfig: Successfully published MSA API target SVCB RR %q", apiname)
			return nil
		},
	)
	mconf.Internal.DeferredUpdateQ <- du

	du = createDeferredUpdate(
		mconf.MSA.Identity,
		fmt.Sprintf("Publish ADDR RRs for MSA API target %q", apiname),
		func() error {
			zd, ok := Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadMSAConfig: Action: zone data for MSA identity %q still not found", mconf.MSA.Identity)
			}

			for _, addr := range mconf.MSA.Api.Addresses.Publish {
				err = zd.PublishAddrRR(apiname, addr)
				if err != nil {
					return fmt.Errorf("LoadMSAConfig: failed to publish MSA API address RRs: %v", err)
				}
			}
			log.Printf("LoadMSAig: Successfully published sidecar API address RRs %q", apiname)
			return nil
		},
	)
	mconf.Internal.DeferredUpdateQ <- du
	return nil
}

func (mconf *Config) SetupDnsMethod() error {
	dnsname := "dns." + mconf.MSA.Identity

	du := createDeferredUpdate(
		mconf.MSA.Identity,
		fmt.Sprintf("Publish KEY RR for sidecar DNS target %q SIG(0) public key", dnsname),
		func() error {
			zd, ok := Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity %q still not found", mconf.MSA.Identity)
			}

			err := zd.MusicSig0KeyPrep(dnsname, zd.KeyDB)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish KEY RR for sidecar DNS target '%s' SIG(0) public key: %v", dnsname, err)
			}

			log.Printf("LoadSidecarConfig: Successfully published KEY RR for sidecar DNS target %q SIG(0) public key", dnsname)
			return nil
		},
	)
	mconf.Internal.DeferredUpdateQ <- du

	du = createDeferredUpdate(
		mconf.MSA.Identity,
		fmt.Sprintf("Publish SVCB RRs for sidecar DNS identity %q", dnsname),
		func() error {
			zd, ok := Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity %q still not found", mconf.MSA.Identity)
			}

			var ipv4hint, ipv6hint []net.IP
			var value []dns.SVCBKeyValue

			if len(mconf.MSA.Dns.Addresses.Publish) > 0 {
				for _, addr := range mconf.MSA.Dns.Addresses.Publish {
					ip := net.ParseIP(addr)
					if ip == nil {
						log.Printf("LoadSidecarConfig: failed to parse address %q", addr)
						continue
					}
					if ip.To4() != nil {
						ipv4hint = append(ipv4hint, ip)
					} else {
						ipv6hint = append(ipv6hint, ip)
					}
				}
			}

			if mconf.MSA.Dns.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: mconf.MSA.Dns.Port})
			}

			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}

			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			log.Printf("LoadSidecarConfig: publishing SVCB RR for sidecar DNS target %q", dnsname)
			err := zd.PublishSvcbRR(dnsname, mconf.MSA.Dns.Port, value)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish sidecar DNS target SVCB RR: %v", err)
			}
			log.Printf("LoadSidecarConfig: Successfully published sidecar DNS target SVCB RR %q", dnsname)
			return nil
		},
	)
	mconf.Internal.DeferredUpdateQ <- du

	du = createDeferredUpdate(
		mconf.MSA.Identity,
		fmt.Sprintf("Publish ADDR RRs for sidecar DNS target %q", dnsname),
		func() error {
			zd, ok := Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity %q still not found", mconf.MSA.Identity)
			}

			for _, addr := range mconf.MSA.Dns.Addresses.Publish {
				err := zd.PublishAddrRR(dnsname, addr)
				if err != nil {
					return fmt.Errorf("LoadSidecarConfig: failed to publish sidecar DNS address RRs: %v", err)
				}
			}
			log.Printf("LoadSidecarConfig: Successfully published sidecar DNS address RRs %q", dnsname)
			return nil
		},
	)
	mconf.Internal.DeferredUpdateQ <- du

	return nil
}
*/

func createDeferredUpdate(zoneName, description string, action func() error) DeferredUpdate {
	return DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     zoneName,
		AddTime:      time.Now(),
		Description:  description,
		PreCondition: ZoneIsReady(zoneName),
		Action:       action,
	}
}

func (conf *Config) SetupAgentAutoZone(zonename string) (*ZoneData, error) {
	log.Printf("SetupAgentAutoZone: Zone %q not found, creating a minimal auto zone", zonename)

	addrs, err := conf.FindNameserverAddrs()
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to find nameserver addresses: %v", err)
	}

	zd, err := conf.Internal.KeyDB.CreateAutoZone(zonename, addrs)
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to create minimal auto zone for agent identity %q: %v", zonename, err)
	}
	zd.Options[OptAllowUpdates] = true
	zd.SyncQ = conf.Internal.SyncQ

	// Agent auto zone needs to be signed
	zd.Options[OptOnlineSigning] = true
	if tmp, exists := conf.Internal.DnssecPolicies["default"]; !exists {
		return nil, fmt.Errorf("SetupAgentAutoZone: DnssecPolicy 'default' not defined")
	} else {
		zd.DnssecPolicy = &tmp
	}
	err = zd.SetupZoneSigning(conf.Internal.ResignQ)
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to set up zone signing: %v", err)
	}

	return zd, nil
}

func (conf *Config) SetupApiTransport() error {
	identity := conf.Agent.Identity

	du := createDeferredUpdate(
		identity,
		fmt.Sprintf("Publish HTTPS transport records for agent %q", identity),
		func() error {
			zd, ok := Zones.Get(identity)
			if !ok {
				return fmt.Errorf("SetupApiTransport: zone data for agent identity %q not found", identity)
			}

			// Publish _https._tcp URI record
			err := zd.PublishUriRR("_https._tcp."+identity, conf.Agent.Api.BaseUrl, conf.Agent.Api.Port)
			if err != nil {
				return fmt.Errorf("failed to publish URI record: %v", err)
			}

			// Publish TLSA record
			err = zd.PublishTlsaRR(identity, conf.Agent.Api.Port, conf.Agent.Api.CertData)
			if err != nil {
				return fmt.Errorf("failed to publish TLSA record: %v", err)
			}

			// Publish SVCB record with addresses
			var value []dns.SVCBKeyValue
			var ipv4hint, ipv6hint []net.IP

			for _, addr := range conf.Agent.Api.Addresses.Publish {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					ipv4hint = append(ipv4hint, ip)
				} else {
					ipv6hint = append(ipv6hint, ip)
				}
			}

			if conf.Agent.Api.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: conf.Agent.Api.Port})
			}
			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}
			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			err = zd.PublishSvcbRR(identity, conf.Agent.Api.Port, value)
			if err != nil {
				return fmt.Errorf("failed to publish SVCB record: %v", err)
			}

			return nil
		},
	)
	conf.Internal.DeferredUpdateQ <- du
	return nil
}

func (conf *Config) SetupDnsTransport() error {
	identity := conf.Agent.Identity

	du := createDeferredUpdate(
		identity,
		fmt.Sprintf("Publish DNS transport records for agent %q", identity),
		func() error {
			zd, ok := Zones.Get(identity)
			if !ok {
				return fmt.Errorf("SetupDnsTransport: zone data for agent identity %q not found", identity)
			}

			// Publish _dns._tcp URI record
			err := zd.PublishUriRR("_dns._tcp."+identity, "", conf.Agent.Dns.Port)
			if err != nil {
				return fmt.Errorf("failed to publish URI record: %v", err)
			}

			// Publish KEY record for SIG(0)
			err = zd.AgentSig0KeyPrep(identity, zd.KeyDB)
			if err != nil {
				return fmt.Errorf("failed to publish KEY record: %v", err)
			}

			// Publish SVCB record with addresses
			var value []dns.SVCBKeyValue
			var ipv4hint, ipv6hint []net.IP

			for _, addr := range conf.Agent.Dns.Addresses.Publish {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					ipv4hint = append(ipv4hint, ip)
				} else {
					ipv6hint = append(ipv6hint, ip)
				}
			}

			if conf.Agent.Dns.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: conf.Agent.Dns.Port})
			}
			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}
			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			err = zd.PublishSvcbRR(identity, conf.Agent.Dns.Port, value)
			if err != nil {
				return fmt.Errorf("failed to publish SVCB record: %v", err)
			}

			return nil
		},
	)
	conf.Internal.DeferredUpdateQ <- du
	return nil
}

func (conf *Config) SetupAgent(all_zones []string) error {
	if Globals.Debug {
		log.Printf("SetupAgent: enter. all_zones: %v", all_zones)
	}

	if len(conf.Agent.Api.Addresses.Listen) == 0 && len(conf.Agent.Dns.Addresses.Listen) == 0 {
		dump.P(conf.Agent)
		return errors.New("SetupAgent: neither API nor DNS addresses set in config file")
	}

	// Ensure identity is FQDN
	conf.Agent.Identity = dns.Fqdn(conf.Agent.Identity)

	// Create auto zone for agent identity if needed
	if !slices.Contains(all_zones, conf.Agent.Identity) {
		_, err := conf.SetupAgentAutoZone(conf.Agent.Identity)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to create auto zone for agent identity %q: %v",
				conf.Agent.Identity, err)
		}
	}

	// Setup API transport if configured
	if len(conf.Agent.Api.Addresses.Publish) > 0 {
		// Load and verify API certificate
		certFile := conf.Agent.Api.Cert
		keyFile := conf.Agent.Api.Key

		if certFile == "" || keyFile == "" {
			return errors.New("SetupAgent: API transport defined, but cert or key file not set")
		}

		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("SetupAgent: error reading cert file: %v", err)
		}

		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("SetupAgent: error reading key file: %v", err)
		}

		conf.Agent.Api.CertData = string(certPEM)
		conf.Agent.Api.KeyData = string(keyPEM)

		// Verify certificate CN matches agent identity
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate: %v", err)
		}

		if cert.Subject.CommonName != conf.Agent.Identity {
			return fmt.Errorf("SetupAgent: certificate CN %q does not match agent identity %q",
				cert.Subject.CommonName, conf.Agent.Identity)
		}

		err = conf.SetupApiTransport()
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to setup API transport: %v", err)
		}
	}

	// Setup DNS transport if configured
	if len(conf.Agent.Dns.Addresses.Publish) > 0 {
		err := conf.SetupDnsTransport()
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to setup DNS transport: %v", err)
		}
	}

	if Globals.Debug {
		log.Printf("SetupAgent: exit")
	}
	return nil
}

func (zd *ZoneData) AgentSig0KeyPrep(name string, kdb *KeyDB) error {
	alg, err := parseKeygenAlgorithm("agent.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		log.Printf("AgentSig0KeyPrep: Zone %s: Error from parseKeygenAlgorithm(): %v", zd.ZoneName, err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, kdb)
}
