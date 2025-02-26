/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

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

	"github.com/go-playground/validator/v10"
	"github.com/gookit/goutil/dump"
	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	// "github.com/DNSSEC-Provisioning/music/music"
	// "github.com/DNSSEC-Provisioning/music/signer"
)

// var cfgFile string
// var verbose bool

type Config struct {
	ApiServer tdns.ApiServerConf
	Signers   []SignerConf
	Db        DbConf
	Common    CommonConf
	Internal  InternalConf
	FSMEngine FSMEngineConf
	Zones     ZonesConf
	MSA       MSAConf
}

type MSAConf struct {
	Identity string `validate:"required,hostname"`
	Api      MSAApiConf
	Dns      MSADnsConf
}

type MSAApiConf struct {
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

type MSADnsConf struct {
	Addresses struct {
		Publish []string
		Listen  []string
	}
	Port uint16
}

type ZonesConf struct {
	Config string `validate:"file"` // not required
}

type FSMEngineConf struct {
	Active    *bool `validate:"required"`
	Intervals IntervalsConf
}

type IntervalsConf struct {
	Target   int `validate:"required"`
	Minimum  int `validate:"required"`
	Maximum  int `validate:"required"`
	Complete int `validate:"required,gte=3599,lte=86401"` // must be greater 1hr and less than 24hr
}

type SignerConf struct {
	Name    string
	Address string `validate:"hostname_port"`
	BaseURL string `validate:"url"`
	Method  string // ddns | desec | ...
	Auth    string // tsig | userpasstoken
	Tsig    TsigConf
	Limits  RateLimitsConf
}

type RateLimitsConf struct {
	Fetch  int // get rrset ops / second
	Update int // update rrset ops / second
}

type TsigConf struct {
	KeyName   string `dns:"domain-name"`
	KeyAlg    string // dns.HmacSHA256 is most common
	KeySecret string
}

type DbConf struct {
	File string // `validate:"file"` // not required, will be checked later
	Mode string `validate:"required"`
}

type CommonConf struct {
	Debug     *bool  `validate:"required"`
	TokenFile string `validate:"file,required"`
	RootCA    string `validate:"file,required"`
}

// Internal stuff that we want to be able to reach via the Config struct, but are not
// represented in the yaml config file.
type InternalConf struct {
	APIStopCh        chan struct{}
	EngineCheck      chan EngineCheck
	MusicDB          *MusicDB
	TokViper         *viper.Viper
	DesecFetch       chan SignerOp
	DesecUpdate      chan SignerOp
	DdnsFetch        chan SignerOp
	DdnsUpdate       chan SignerOp
	Processes        map[string]FSM
	MusicSyncQ       chan tdns.MusicSyncRequest
	HeartbeatQ       chan MSABeatReport
	MSAId            string
	UpdateQ          chan tdns.UpdateRequest
	DeferredUpdateQ  chan tdns.DeferredUpdate
	KeyDB            *tdns.KeyDB
	MusicSyncStatusQ chan MusicSyncStatus
}

func ValidateConfig(v *viper.Viper, cfgfile, appMode string, safemode bool) error {
	var config Config

	if safemode {
		if v == nil {
			return fmt.Errorf("ValidateConfig: cannot use safe mode with nil viper")
		} else {
			if err := v.Unmarshal(&config); err != nil {
				return fmt.Errorf("ValidateConfig: unable to unmarshal the config %v", err)
			}
		}

		validate := validator.New()
		if err := validate.Struct(&config); err != nil {
			return fmt.Errorf("ValidateConfig: %q is missing required attributes:\n%v", cfgfile, err)
		} else {
			if tdns.Globals.Debug {
				fmt.Printf("ValidateConfig: %q config in %q validated successfully\n", appMode, cfgfile)
			}
		}
	} else {
		if v == nil {
			if err := viper.Unmarshal(&config); err != nil {
				return fmt.Errorf("unable to unmarshal the config %v", err)
			}
		} else {
			if err := v.Unmarshal(&config); err != nil {
				return fmt.Errorf("unable to unmarshal the config %v", err)
			}
		}

		validate := validator.New()
		if err := validate.Struct(&config); err != nil {
			return fmt.Errorf("config %q is missing required attributes:\n%v", cfgfile, err)
		} else {
			if tdns.Globals.Debug {
				fmt.Printf("ValidateConfig: %q config in %q validated successfully\n", appMode, cfgfile)
			}
		}
		// fmt.Printf("config: %v\n", config)
	}

	if appMode != "msa-cli" && appMode != "tdns-cli" {
		// Verify that we have a MUSIC DB file.
		if _, err := os.Stat(config.Db.File); os.IsNotExist(err) {
			log.Printf("ValidateConfig: MUSIC DB file %q does not exist.", config.Db.File)
			log.Printf("Please initialize MUSIC DB using 'msa-cli music db init -f %s'.", config.Db.File)
			return fmt.Errorf("ValidateConfig: MUSIC DB file %q does not exist", config.Db.File)
		}
	}
	return nil
}

// yes, these must be global
var TokVip *viper.Viper
var CliConf = CliConfig{}

func LoadMusicConfig(mconf *Config, appMode string, safemode bool) error {
	if tdns.Globals.Debug {
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

	if tdns.Globals.Debug {
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
		if tdns.Globals.Debug {
			fmt.Printf("*** LoadMusicConfig: server config merged from %q\n", cfgfile)
		}
	case "msa":
		err = viper.MergeInConfig()
		if err != nil {
			log.Printf("Error from viper.MergeInConfig: %v", err)
			return err
		}
		if tdns.Globals.Debug {
			fmt.Printf("*** LoadMusicConfig: MSA config merged from %q\n", cfgfile)
		}
	case "msa-cli":
		err = viper.MergeInConfig()
		if tdns.Globals.Debug {
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

	TokVip = viper.New()
	var tokenfile string
	if viper.GetString("common.tokenfile") != "" {
		tokenfile = viper.GetString("common.tokenfile")
	}

	TokVip.SetConfigFile(tokenfile)
	err = TokVip.ReadInConfig()
	if err != nil {
		log.Printf("Error from TokVip.ReadInConfig: %v\n", err)
	} else {
		if CliConf.Verbose {
			fmt.Println("Using token store file:", TokVip.ConfigFileUsed())
		}
	}

	CliConf.Verbose = viper.GetBool("common.verbose")
	CliConf.Debug = viper.GetBool("common.debug")

	if tdns.Globals.Debug {
		log.Printf("LoadMusicConfig: exit")
	}
	return nil
}

func (mconf *Config) LoadMSAConfig(tconf *tdns.Config, all_zones []string) error {
	if tdns.Globals.Debug {
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

	if tdns.Globals.Debug {
		log.Printf("LoadMSAConfig: exit")
	}

	return nil
}

func createDeferredUpdate(zoneName, description string, action func() error) tdns.DeferredUpdate {
	return tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     zoneName,
		AddTime:      time.Now(),
		Description:  description,
		PreCondition: tdns.ZoneIsReady(zoneName),
		Action:       action,
	}
}

func (mconf *Config) SetupApiMethod(tconf *tdns.Config, all_zones []string) error {
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
			zd, ok := tdns.Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadMSAConfig: Action: zone data for MSA identity %q still not found", mconf.MSA.Identity)
			}

			log.Printf("LoadMSAConfig: sending PING command to MSA  %q", mconf.MSA.Identity)
			zd.KeyDB.UpdateQ <- tdns.UpdateRequest{
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
			zd, ok := tdns.Zones.Get(mconf.MSA.Identity)
			if !ok {
				return fmt.Errorf("LoadMSAConfig: Action: zone data for MSA identity %q still not found", mconf.MSA.Identity)
			}

			log.Printf("LoadMSAConfig: sending PING command to MSA %q", mconf.MSA.Identity)
			zd.KeyDB.UpdateQ <- tdns.UpdateRequest{
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
			zd, ok := tdns.Zones.Get(mconf.MSA.Identity)
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
			zd, ok := tdns.Zones.Get(mconf.MSA.Identity)
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
			zd, ok := tdns.Zones.Get(mconf.MSA.Identity)
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
			zd, ok := tdns.Zones.Get(mconf.MSA.Identity)
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
			zd, ok := tdns.Zones.Get(mconf.MSA.Identity)
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

func (mconf *Config) SetupSidecarAutoZone(zonename string, tconf *tdns.Config) (*tdns.ZoneData, error) {
	log.Printf("SetupSidecarAutoZone: Zone %q not found, creating a minimal auto zone", zonename)

	addrs, err := tconf.FindNameserverAddrs()
	if err != nil {
		return nil, fmt.Errorf("SetupSidecarAutoZone: failed to find nameserver addresses: %v", err)
	}

	zd, err := mconf.Internal.KeyDB.CreateAutoZone(zonename, addrs)
	if err != nil {
		return nil, fmt.Errorf("SetupSidecarAutoZone: failed to create minimal auto zone for sidecar DNS identity %q: %v", zonename, err)
	}
	zd.Options[tdns.OptAllowUpdates] = true
	zd.MusicSyncQ = mconf.Internal.MusicSyncQ

	// A sidecar auto zone needs to be signed by the sidecar.
	zd.Options[tdns.OptOnlineSigning] = true
	if tmp, exists := tconf.Internal.DnssecPolicies["default"]; !exists {
		return nil, fmt.Errorf("SetupSidecarAutoZone: DnssecPolicy 'default' not defined. Default policy is required for sidecar auto zones")
	} else {
		zd.DnssecPolicy = &tmp
	}
	err = zd.SetupZoneSigning(tconf.Internal.ResignQ)
	if err != nil {
		return nil, fmt.Errorf("SetupMSAAutoZone: failed to set up zone signing for MSA auto zone %q: %v", zonename, err)
	}

	// A MSA auto zone will try to set up delegation syncing with the parent.
	zd.Options[tdns.OptDelSyncChild] = true
	err = zd.SetupZoneSync(tconf.Internal.DelegationSyncQ)
	if err != nil {
		return nil, fmt.Errorf("SetupMSAAutoZone: failed to set up delegation syncing for MSA auto zone %q: %v", zonename, err)
	}

	return zd, nil
}
