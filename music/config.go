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
	Sidecar   SidecarConf
}

type SidecarConf struct {
	Identity string
	Api      SidecarApiConf
	Dns      SidecarDnsConf
}

type SidecarApiConf struct {
	//	Identity  string
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

type SidecarDnsConf struct {
	//	Identity  string
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
	HeartbeatQ       chan SidecarBeatReport
	SidecarId        string
	UpdateQ          chan tdns.UpdateRequest
	DeferredUpdateQ  chan tdns.DeferredUpdate
	KeyDB            *tdns.KeyDB
	MusicSyncStatusQ chan MusicSyncStatus
}

func ValidateConfig(v *viper.Viper, cfgfile, appMode string, safemode bool) error {
	var config Config
	var msg string

	if safemode {
		if v == nil {
			return errors.New("ValidateConfig: cannot use safe mode with nil viper")
		} else {
			if err := v.Unmarshal(&config); err != nil {
				msg = fmt.Sprintf("ValidateConfig: unable to unmarshal the config %v",
					err)
				return errors.New(msg)
			}
		}

		validate := validator.New()
		if err := validate.Struct(&config); err != nil {
			msg = fmt.Sprintf("ValidateConfig: \"%s\" is missing required attributes:\n%v\n",
				cfgfile, err)
			return errors.New(msg)
		} else {
			if tdns.Globals.Debug {
				fmt.Printf("ValidateConfig: %s config in \"%s\" validated successfully\n", appMode, cfgfile)
			}
		}
	} else {
		if v == nil {
			if err := viper.Unmarshal(&config); err != nil {
				log.Fatalf("unable to unmarshal the config %v", err)
			}
		} else {
			if err := v.Unmarshal(&config); err != nil {
				log.Fatalf("unable to unmarshal the config %v", err)
			}
		}

		validate := validator.New()
		if err := validate.Struct(&config); err != nil {
			log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
		} else {
			if tdns.Globals.Debug {
				fmt.Printf("ValidateConfig: %s config in \"%s\" validated successfully\n", appMode, cfgfile)
			}
		}
		// fmt.Printf("config: %v\n", config)
	}

	if appMode != "sidecar-cli" && appMode != "tdns-cli" {
		// Verify that we have a MUSIC DB file.
		if _, err := os.Stat(config.Db.File); os.IsNotExist(err) {
			log.Printf("ValidateConfig: MUSIC DB file '%s' does not exist.", config.Db.File)
			log.Printf("Please initialize MUSIC DB using 'sidecar-cli music db init -f %s'.", config.Db.File)
			return errors.New("ValidateConfig: MUSIC DB file does not exist")
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
	case "sidecar", "sidecar-cli":
		cfgfile = DefaultSidecarCfgFile
	default:
		log.Fatalf("Unknown app mode: %s", appMode)
	}

	if tdns.Globals.Debug {
		fmt.Printf("*** LoadMusicConfig: reloading config from \"%s\". Safemode: %v\n", cfgfile, safemode)
	}
	if safemode {
		tmpviper := viper.New()
		tmpviper.SetConfigFile(cfgfile)

		var err error
		switch appMode {
		case "server":
			err = tmpviper.ReadInConfig()
		case "sidecar", "sidecar-cli":
			err = tmpviper.MergeInConfig()
		default:
			log.Fatalf("Unknown app mode: %s", appMode)
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
			fmt.Printf("*** LoadMusicConfig: server config merged from \"%s\"\n", cfgfile)
		}
	case "sidecar":
		err = viper.MergeInConfig()
		if err != nil {
			log.Printf("Error from viper.MergeInConfig: %v", err)
			return err
		}
		if tdns.Globals.Debug {
			fmt.Printf("*** LoadMusicConfig: sidecar config merged from \"%s\"\n", cfgfile)
		}
	case "sidecar-cli":
		err = viper.MergeInConfig()
		if tdns.Globals.Debug {
			fmt.Printf("*** LoadMusicConfig: sidecar-cli config merged from \"%s\"\n", cfgfile)
		}
	default:
		log.Fatalf("Unknown app mode: %s", appMode)
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
	// dump.P(mconf.Sidecar)

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

func (mconf *Config) LoadSidecarConfig(tconf *tdns.Config, all_zones []string) error {
	if tdns.Globals.Debug {
		log.Printf("loadSidecarConfig: enter")
	}

	if len(mconf.Sidecar.Api.Addresses.Listen) == 0 && len(mconf.Sidecar.Dns.Addresses.Listen) == 0 {
		dump.P(mconf.Sidecar)
		return errors.New("LoadSidecarConfig: neither sidecar syncapi nor syncdns addresses set in config file")
	}

	mconf.Sidecar.Identity = dns.Fqdn(mconf.Sidecar.Identity)

	if len(mconf.Sidecar.Api.Addresses.Publish) > 0 {
		err := mconf.SetupApiMethod(tconf, all_zones)
		if err != nil {
			return fmt.Errorf("LoadSidecarConfig: failed to setup API method: %v", err)
		}
	}

	if len(mconf.Sidecar.Dns.Addresses.Publish) > 0 {
		err := mconf.SetupDnsMethod()
		if err != nil {
			return fmt.Errorf("LoadSidecarConfig: failed to setup DNS method: %v", err)
		}
	}

	if tdns.Globals.Debug {
		log.Printf("LoadSidecarConfig: exit")
	}

	return nil
}

func (mconf *Config) SetupApiMethod(tconf *tdns.Config, all_zones []string) error {
	apiname := "api." + mconf.Sidecar.Identity

	if !slices.Contains(all_zones, mconf.Sidecar.Identity) {
		_, err := mconf.SetupSidecarAutoZone(mconf.Sidecar.Identity, tconf)
		if err != nil {
			return fmt.Errorf("LoadSidecarConfig: failed to create minimal auto zone for sidecar identity '%s': %v", mconf.Sidecar.Identity, err)
		}
	}

	certFile := viper.GetString("sidecar.api.cert")
	keyFile := viper.GetString("sidecar.api.key")

	if certFile == "" || keyFile == "" {
		return errors.New("LoadSidecarConfig: Sidecar API identity defined, but cert or key file not set in config file")
	}

	certPEM, err := os.ReadFile(mconf.Sidecar.Api.Cert)
	if err != nil {
		return fmt.Errorf("LoadSidecarConfig: error reading cert file: %v", err)
	}

	keyPEM, err := os.ReadFile(mconf.Sidecar.Api.Key)
	if err != nil {
		return fmt.Errorf("LoadSidecarConfig: error reading key file: %v", err)
	}

	mconf.Sidecar.Api.CertData = string(certPEM)
	mconf.Sidecar.Api.KeyData = string(keyPEM)

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("LoadSidecarConfig: failed to parse certificate PEM")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("LoadSidecarConfig: failed to parse certificate: %v", err)
	}

	// Extract the CN from the certificate
	certCN := cert.Subject.CommonName

	// Compare the CN with the expected CN
	if certCN != "api."+mconf.Sidecar.Identity {
		log.Printf("LoadSidecarConfig: Error: mconf.Sidecar.Identity: %s viper: %v", mconf.Sidecar.Identity, viper.GetString("sidecar.identity"))
		dump.P(mconf.Sidecar)
		return fmt.Errorf("LoadSidecarConfig: Error: Sidecar certificate CN '%s' does not match sidecar API target 'api.%s'", certCN, mconf.Sidecar.Identity)
	}

	log.Printf("LoadSidecarConfig: cert CN '%s' matches sidecar API identity 'api.%s'", certCN, mconf.Sidecar.Identity)

	du := tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     mconf.Sidecar.Identity,
		AddTime:      time.Now(),
		Description:  fmt.Sprintf("Publish TLSA RR for sidecar API target '%s'", apiname),
		PreCondition: tdns.ZoneIsReady(mconf.Sidecar.Identity),
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}

			log.Printf("LoadSidecarConfig: sending PING command to sidecar '%s'", mconf.Sidecar.Identity)
			zd.KeyDB.UpdateQ <- tdns.UpdateRequest{
				Cmd: "PING",
			}

			// sidecar API identity
			log.Printf("LoadSidecarConfig: publishing TLSA RR for sidecar API target '%s'", apiname)

			err = zd.PublishTlsaRR(apiname, mconf.Sidecar.Api.Port, string(certPEM))
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish TLSA RR: %v", err)
			}

			log.Printf("LoadSidecarConfig: Successfully published TLSA RR for sidecar API target '%s'\n", apiname)
			return nil
		},
	}
	mconf.Internal.DeferredUpdateQ <- du

	du = tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     mconf.Sidecar.Identity,
		AddTime:      time.Now(),
		Description:  fmt.Sprintf("Publish URI RR for sidecar API target '%s'", apiname),
		PreCondition: tdns.ZoneIsReady(mconf.Sidecar.Identity),
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}

			log.Printf("LoadSidecarConfig: sending PING command to sidecar '%s'", mconf.Sidecar.Identity)
			zd.KeyDB.UpdateQ <- tdns.UpdateRequest{
				Cmd: "PING",
			}

			// sidecar API identity
			log.Printf("LoadSidecarConfig: publishing URI RR for sidecar API target '%s'", apiname)

			err = zd.PublishUriRR(apiname, mconf.Sidecar.Api.BaseUrl, mconf.Sidecar.Api.Port)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish URI RR: %v", err)
			}

			log.Printf("LoadSidecarConfig: Successfully published TLSA RR for sidecar API target '%s'\n", apiname)
			return nil
		},
	}
	mconf.Internal.DeferredUpdateQ <- du

	du = tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     mconf.Sidecar.Identity,
		AddTime:      time.Now(),
		Description:  fmt.Sprintf("Publish SVCB RR for sidecar API target '%s'", apiname),
		PreCondition: tdns.ZoneIsReady(mconf.Sidecar.Identity),
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}

			var ipv4hint, ipv6hint []net.IP
			var value []dns.SVCBKeyValue
			if len(mconf.Sidecar.Api.Addresses.Publish) > 0 {
				for _, addr := range mconf.Sidecar.Api.Addresses.Publish {
					ip := net.ParseIP(addr)
					if ip == nil {
						log.Printf("LoadSidecarConfig: failed to parse address '%s'", addr)
						continue
					}
					if ip.To4() != nil {
						ipv4hint = append(ipv4hint, ip)
					} else {
						ipv6hint = append(ipv6hint, ip)
					}
				}
			}

			if mconf.Sidecar.Api.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: mconf.Sidecar.Api.Port})
			}

			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}

			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			err = zd.PublishSvcbRR(apiname, mconf.Sidecar.Api.Port, value)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish sidecar API target SVCB RR: %v", err)
			}

			log.Printf("LoadSidecarConfig: Successfully published sidecar API target SVCB RR '%s'\n", apiname)
			return nil
		},
	}
	mconf.Internal.DeferredUpdateQ <- du

	du = tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     mconf.Sidecar.Identity,
		AddTime:      time.Now(),
		Description:  fmt.Sprintf("Publish ADDR RRs for sidecar API target '%s'", apiname),
		PreCondition: tdns.ZoneIsReady(mconf.Sidecar.Identity),
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}

			for _, addr := range mconf.Sidecar.Api.Addresses.Publish {
				err = zd.PublishAddrRR(apiname, addr)
				if err != nil {
					return fmt.Errorf("LoadSidecarConfig: failed to publish sidecar API address RRs: %v", err)
				}
			}
			log.Printf("LoadSidecarConfig: Successfully published sidecar API address RRs '%s'\n", apiname)
			return nil
		},
	}
	mconf.Internal.DeferredUpdateQ <- du
	return nil
}

func (mconf *Config) SetupDnsMethod() error {
	dnsname := "dns." + mconf.Sidecar.Identity

	du := tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     mconf.Sidecar.Identity,
		AddTime:      time.Now(),
		Description:  fmt.Sprintf("Publish KEY RR for sidecar DNS target '%s' SIG(0) public key", dnsname),
		PreCondition: tdns.ZoneIsReady(mconf.Sidecar.Identity),
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}

			err := zd.MusicSig0KeyPrep(dnsname, zd.KeyDB)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish KEY RR for sidecar DNS target '%s' SIG(0) public key: %v", dnsname, err)
			}

			log.Printf("LoadSidecarConfig: Successfully published KEY RR for sidecar DNS target '%s' SIG(0) public key\n", dnsname)
			return nil
		},
	}
	mconf.Internal.DeferredUpdateQ <- du

	du = tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     mconf.Sidecar.Identity,
		AddTime:      time.Now(),
		Description:  fmt.Sprintf("Publish SVCB RRs for sidecar DNS identity '%s'", dnsname),
		PreCondition: tdns.ZoneIsReady(mconf.Sidecar.Identity),
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}

			var ipv4hint, ipv6hint []net.IP
			var value []dns.SVCBKeyValue

			if len(mconf.Sidecar.Dns.Addresses.Publish) > 0 {
				for _, addr := range mconf.Sidecar.Dns.Addresses.Publish {
					ip := net.ParseIP(addr)
					if ip == nil {
						log.Printf("LoadSidecarConfig: failed to parse address '%s'", addr)
						continue
					}
					if ip.To4() != nil {
						ipv4hint = append(ipv4hint, ip)
					} else {
						ipv6hint = append(ipv6hint, ip)
					}
				}
			}

			if mconf.Sidecar.Dns.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: mconf.Sidecar.Dns.Port})
			}

			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}

			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			log.Printf("LoadSidecarConfig: publishing SVCB RR for sidecar DNS target '%s'", dnsname)
			err := zd.PublishSvcbRR(dnsname, mconf.Sidecar.Dns.Port, value)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish sidecar DNS target SVCB RR: %v", err)
			}
			log.Printf("LoadSidecarConfig: Successfully published sidecar DNS target SVCB RR '%s'\n", dnsname)
			return nil
		},
	}
	mconf.Internal.DeferredUpdateQ <- du

	du = tdns.DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     mconf.Sidecar.Identity,
		AddTime:      time.Now(),
		Description:  fmt.Sprintf("Publish ADDR RRs for sidecar DNS target '%s'", dnsname),
		PreCondition: tdns.ZoneIsReady(mconf.Sidecar.Identity),
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}

			for _, addr := range mconf.Sidecar.Dns.Addresses.Publish {
				err := zd.PublishAddrRR(dnsname, addr)
				if err != nil {
					return fmt.Errorf("LoadSidecarConfig: failed to publish sidecar DNS address RRs: %v", err)
				}
			}
			log.Printf("LoadSidecarConfig: Successfully published sidecar DNS address RRs '%s'\n", dnsname)
			return nil
		},
	}
	mconf.Internal.DeferredUpdateQ <- du

	return nil
}

func (mconf *Config) SetupSidecarAutoZone(zonename string, tconf *tdns.Config) (*tdns.ZoneData, error) {
	log.Printf("SetupSidecarAutoZone: Zone %s not found, creating a minimal auto zone", zonename)

	addrs, err := tconf.FindNameserverAddrs()
	if err != nil {
		return nil, fmt.Errorf("SetupSidecarAutoZone: failed to find nameserver addresses: %v", err)
	}

	zd, err := mconf.Internal.KeyDB.CreateAutoZone(zonename, addrs)
	if err != nil {
		return nil, fmt.Errorf("SetupSidecarAutoZone: failed to create minimal auto zone for sidecar DNS identity '%s': %v", zonename, err)
	}
	zd.Options[tdns.OptAllowUpdates] = true
	zd.MusicSyncQ = mconf.Internal.MusicSyncQ

	// A sidecar auto zone needs to be signed by the sidecar.
	zd.Options[tdns.OptOnlineSigning] = true
	if tmp, exists := tconf.Internal.DnssecPolicies["default"]; !exists {
		return nil, fmt.Errorf("SetupSidecarAutoZone: DnssecPolicy 'default' not defined. Default policy is required for sidecar auto zones.")
	} else {
		zd.DnssecPolicy = &tmp
	}
	err = zd.SetupZoneSigning(tconf.Internal.ResignQ)
	if err != nil {
		return nil, fmt.Errorf("SetupSidecarAutoZone: failed to set up zone signing for sidecar auto zone '%s': %v", zonename, err)
	}

	// A sidecar auto zone will try to set up delegation syncing with the parent.
	zd.Options[tdns.OptDelSyncChild] = true
	err = zd.SetupZoneSync(tconf.Internal.DelegationSyncQ)
	if err != nil {
		return nil, fmt.Errorf("SetupSidecarAutoZone: failed to set up delegation syncing for sidecar auto zone '%s': %v", zonename, err)
	}

	return zd, nil
}
