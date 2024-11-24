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
	ApiServer ApiServerConf
	Signers   []SignerConf
	Db        DbConf
	Common    CommonConf
	Internal  InternalConf
	FSMEngine FSMEngineConf
	Zones     ZonesConf
	Sidecar   SidecarConf
}

type SidecarConf struct {
	Api SidecarApiConf
	Dns SidecarDnsConf
}

type SidecarApiConf struct {
	Identity  string
	Addresses []string
	Port      uint16
	Cert      string
	Key       string
	CertData  string
	KeyData   string
}

type SidecarDnsConf struct {
	Identity  string
	Addresses []string
	Port      uint16
}

type ZonesConf struct {
	Config string `validate:"file"` // not required
}

type ApiServerConf struct {
	Address  string `validate:"required,hostname_port"`
	ApiKey   string `validate:"required"`
	CertFile string `validate:"required,file"`
	KeyFile  string `validate:"required,file"`
	UseTLS   bool
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
	MultiSignerSyncQ chan tdns.MultiSignerSyncRequest
	HeartbeatQ       chan Heartbeat
	SidecarId        string
	UpdateQ          chan tdns.UpdateRequest
	KeyDB            *tdns.KeyDB
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
			if Globals.Debug {
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
			if Globals.Debug {
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
	var cfgfile string
	switch appMode {
	case "server":
		cfgfile = DefaultCfgFile
	case "sidecar", "sidecar-cli":
		cfgfile = DefaultSidecarCfgFile
	default:
		log.Fatalf("Unknown app mode: %s", appMode)
	}

	if Globals.Debug {
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
		// This should be loaded later, when zones are available.
		//		err = LoadSidecarConfig(mconf)
		//		if err != nil {
		//			log.Printf("Error loading sidecar config: %v", err)
		//			return err
		//		}
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

	log.Printf("LoadMusicConfig: unmarshalling MUSIC config into struct")
	err = viper.Unmarshal(&mconf)
	if err != nil {
		log.Fatalf("Error unmarshalling MUSIC config into struct: %v", err)
	}
	// dump.P(mconf)

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

	return nil
}

func LoadSidecarConfig(mconf *Config, tconf *tdns.Config, all_zones []string) error {
	log.Printf("loadSidecarConfig: enter")
	mconf.Sidecar.Api.Identity = dns.Fqdn(mconf.Sidecar.Api.Identity)
	mconf.Sidecar.Dns.Identity = dns.Fqdn(mconf.Sidecar.Dns.Identity)

	if len(mconf.Sidecar.Api.Addresses) == 0 && len(mconf.Sidecar.Dns.Addresses) == 0 {
		return errors.New("LoadSidecarConfig: neither sidecar syncapi nor syncdns addresses set in config file")
	}

	certFile := viper.GetString("sidecar.api.cert")
	keyFile := viper.GetString("sidecar.api.key")

	if mconf.Sidecar.Api.Identity != "." {
		if !slices.Contains(all_zones, mconf.Sidecar.Api.Identity) {
			_, err := mconf.SetupSidecarAutoZone(mconf.Sidecar.Api.Identity, tconf)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to create minimal auto zone for sidecar API identity '%s': %v", mconf.Sidecar.Api.Identity, err)
			}
		}

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
		if certCN != mconf.Sidecar.Api.Identity {
			log.Printf("LoadSidecarConfig: Error: mconf.Sidecar.Api.Identity: %s viper: %v", mconf.Sidecar.Api.Identity, viper.GetString("sidecar.api.identity"))
			dump.P(mconf.Sidecar)
			return fmt.Errorf("LoadSidecarConfig: Error: Sidecar certificate CN '%s' does not match sidecar identity '%s'", certCN, mconf.Sidecar.Api.Identity)
		}

		log.Printf("LoadSidecarConfig: cert CN '%s' matches sidecar identity '%s'", certCN, mconf.Sidecar.Api.Identity)

		ur := tdns.UpdateRequest{
			Cmd:         "DEFERRED-UPDATE",
			ZoneName:    mconf.Sidecar.Api.Identity,
			Description: fmt.Sprintf("Publish TLSA+SVCB RRs for sidecar API identity '%s'", mconf.Sidecar.Api.Identity),
			PreCondition: func() bool {
				_, ok := tdns.Zones.Get(mconf.Sidecar.Api.Identity)
				if !ok {
					log.Printf("LoadSidecarConfig: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Api.Identity)
				}
				return ok
			},
			Action: func() error {
				zd, ok := tdns.Zones.Get(mconf.Sidecar.Api.Identity)
				if !ok {
					return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Api.Identity)
				}
				zd.Options[tdns.OptAllowUpdates] = true

				log.Printf("LoadSidecarConfig: sending PING command to sidecar '%s'", mconf.Sidecar.Api.Identity)
				zd.KeyDB.UpdateQ <- tdns.UpdateRequest{
					Cmd: "PING",
				}

				log.Printf("LoadSidecarConfig: publishing TLSA RR for sidecar identity '%s'", mconf.Sidecar.Api.Identity)

				err = zd.PublishTLSARR(string(certPEM), mconf.Sidecar.Api.Port)
				if err != nil {
					return fmt.Errorf("LoadSidecarConfig: failed to publish TLSA RR: %v", err)
				}

				log.Printf("LoadSidecarConfig: Successfully published TLSA RR for sidecar identity '%s'\n", mconf.Sidecar.Api.Identity)

				var ipv4hint, ipv6hint []net.IP
				if len(mconf.Sidecar.Api.Addresses) > 0 {
					for _, addr := range mconf.Sidecar.Api.Addresses {
						ip := net.ParseIP(addr)
						if ip.To4() != nil {
							ipv4hint = append(ipv4hint, ip)
						} else {
							ipv6hint = append(ipv6hint, ip)
						}
					}
				}
				var value []dns.SVCBKeyValue

				if mconf.Sidecar.Api.Port != 0 {
					value = append(value, &dns.SVCBPort{Port: mconf.Sidecar.Api.Port})
				}

				if len(ipv4hint) > 0 {
					value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
				}

				if len(ipv6hint) > 0 {
					value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
				}

				err = zd.PublishSvcbRR(mconf.Sidecar.Api.Identity, mconf.Sidecar.Api.Port, value)
				if err != nil {
					return fmt.Errorf("LoadSidecarConfig: failed to publish SVCB RR: %v", err)
				}

				log.Printf("LoadSidecarConfig: Successfully published SVCB RR for sidecar API identity '%s'\n", mconf.Sidecar.Api.Identity)

				for _, addr := range mconf.Sidecar.Api.Addresses {
					err = zd.PublishAddrRR(mconf.Sidecar.Api.Identity, addr)
					if err != nil {
						return fmt.Errorf("LoadSidecarConfig: failed to publish address RR: %v", err)
					}
				}
				log.Printf("LoadSidecarConfig: Successfully published address RRs for sidecar API identity '%s'\n", mconf.Sidecar.Api.Identity)
				return nil
			},
		}

		mconf.Internal.UpdateQ <- ur

	}

	if mconf.Sidecar.Dns.Identity != "." {

		if !slices.Contains(all_zones, mconf.Sidecar.Dns.Identity) {
			_, err := mconf.SetupSidecarAutoZone(mconf.Sidecar.Dns.Identity, tconf)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to create minimal auto zone for sidecar DNS identity '%s': %v", mconf.Sidecar.Dns.Identity, err)
			}
		}

		ur := tdns.UpdateRequest{
			Cmd:         "DEFERRED-UPDATE",
			ZoneName:    mconf.Sidecar.Dns.Identity,
			Description: fmt.Sprintf("Publish SVCB + SIG(0) KEY RR for sidecar DNS identity '%s'", mconf.Sidecar.Dns.Identity),
			PreCondition: func() bool {
				_, ok := tdns.Zones.Get(mconf.Sidecar.Dns.Identity)
				if !ok {
					log.Printf("LoadSidecarConfig: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Dns.Identity)
				}
				return ok
			},
			Action: func() error {
				var err error
				zd, ok := tdns.Zones.Get(mconf.Sidecar.Dns.Identity)
				if !ok {
					return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Dns.Identity)
				}
				zd.Options[tdns.OptAllowUpdates] = true

				log.Printf("LoadSidecarConfig: sending PING command to sidecar '%s'", mconf.Sidecar.Dns.Identity)
				zd.KeyDB.UpdateQ <- tdns.UpdateRequest{
					Cmd: "PING",
				}

				log.Printf("LoadSidecarConfig: publishing KEY RR for sidecar identity '%s' SIG(0) public key", mconf.Sidecar.Dns.Identity)

				err = zd.MusicSig0KeyPrep(mconf.Sidecar.Dns.Identity, zd.KeyDB)
				if err != nil {
					return fmt.Errorf("LoadSidecarConfig: failed to publish KEY RR for sidecar DNS identity '%s' SIG(0) public key: %v", mconf.Sidecar.Dns.Identity, err)
				}

				log.Printf("LoadSidecarConfig: Successfully published KEY RR for sidecar DNS identity '%s' SIG(0) public key\n", mconf.Sidecar.Dns.Identity)

				var ipv4hint, ipv6hint []net.IP
				if len(mconf.Sidecar.Dns.Addresses) > 0 {
					for _, addr := range mconf.Sidecar.Dns.Addresses {
						ip := net.ParseIP(addr)
						if ip.To4() != nil {
							ipv4hint = append(ipv4hint, ip)
						} else {
							ipv6hint = append(ipv6hint, ip)
						}
					}
				}
				var value []dns.SVCBKeyValue

				if mconf.Sidecar.Dns.Port != 0 {
					value = append(value, &dns.SVCBPort{Port: mconf.Sidecar.Dns.Port})
				}

				if len(ipv4hint) > 0 {
					value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
				}

				if len(ipv6hint) > 0 {
					value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
				}

				log.Printf("LoadSidecarConfig: publishing SVCB RR for sidecar DNS identity '%s'", mconf.Sidecar.Dns.Identity)
				err = zd.PublishSvcbRR(mconf.Sidecar.Dns.Identity, mconf.Sidecar.Dns.Port, value)
				if err != nil {
					return fmt.Errorf("LoadSidecarConfig: failed to publish SVCB RR: %v", err)
				}
				log.Printf("LoadSidecarConfig: Successfully published SVCB RR for sidecar identity '%s'\n", mconf.Sidecar.Dns.Identity)

				for _, addr := range mconf.Sidecar.Dns.Addresses {
					err = zd.PublishAddrRR(mconf.Sidecar.Dns.Identity, addr)
					if err != nil {
						return fmt.Errorf("LoadSidecarConfig: failed to publish address RR: %v", err)
					}
				}
				log.Printf("LoadSidecarConfig: Successfully published address RRs for sidecar DNS identity '%s'\n", mconf.Sidecar.Dns.Identity)

				return nil
			},
		}

		mconf.Internal.UpdateQ <- ur
	}

	return nil
}

func (mconf *Config) SetupSidecarAutoZone(zonename string, tconf *tdns.Config) (*tdns.ZoneData, error) {
	log.Printf("SetupSidecarAutoZone: Zone %s not found, creating a minimal auto zone", zonename)
	zd, err := mconf.Internal.KeyDB.CreateAutoZone(zonename)
	if err != nil {
		return nil, fmt.Errorf("SetupSidecarAutoZone: failed to create minimal auto zone for sidecar DNS identity '%s': %v", zonename, err)
	}
	zd.Options[tdns.OptAllowUpdates] = true
	zd.MultiSignerSyncQ = mconf.Internal.MultiSignerSyncQ

	// A sidecar auto zone needs to be signed by the sidecar.
	if tmp, exists := tconf.Internal.DnssecPolicies["default"]; !exists {
		log.Fatalf("SetupSidecarAutoZone: DnssecPolicy 'default' not defined. Default policy is required for sidecar auto zones.")
	} else {
		zd.DnssecPolicy = &tmp
	}

	zd.Options[tdns.OptOnlineSigning] = true
	zd.SetupZoneSigning(tconf.Internal.ResignQ)

	return zd, nil
}
