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
	"os"

	"github.com/go-playground/validator/v10"
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
	Identity string
	Port     uint16
	Cert     string
	Key      string
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

func LoadSidecarConfig(mconf *Config, all_zones []string) error {
	log.Printf("loadSidecarConfig: enter")
	mconf.Sidecar.Identity = viper.GetString("music.sidecar.identity")
	if mconf.Sidecar.Identity == "" {
		return errors.New("LoadSidecarConfig: sidecar identity not set in config file")
	}
	mconf.Sidecar.Identity = dns.Fqdn(mconf.Sidecar.Identity)
	mconf.Sidecar.Port = uint16(viper.GetInt("music.sidecar.port"))
	if mconf.Sidecar.Port == 0 {
		return errors.New("LoadSidecarConfig: sidecar port not set in config file")
	}

	certFile := viper.GetString("music.sidecar.cert")
	keyFile := viper.GetString("music.sidecar.key")

	if certFile == "" || keyFile == "" {
		return errors.New("LoadSidecarConfig: cert or key file not set in config file")
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("LoadSidecarConfig: error reading cert file: %v", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("LoadSidecarConfig: error reading key file: %v", err)
	}

	mconf.Sidecar.Cert = string(certPEM)
	mconf.Sidecar.Key = string(keyPEM)

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
	if certCN != mconf.Sidecar.Identity {
		return fmt.Errorf("LoadSidecarConfig: Error: Sidecar certificate CN '%s' does not match sidecar identity '%s'", certCN, mconf.Internal.SidecarId)
	}

	log.Printf("LoadSidecarConfig: cert CN '%s' matches sidecar identity '%s'", certCN, mconf.Sidecar.Identity)

	ur := tdns.UpdateRequest{
		Cmd:      "DEFERRED-UPDATE",
		ZoneName: mconf.Sidecar.Identity,
		PreCondition: func() bool {
			_, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				log.Printf("LoadSidecarConfig: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}
			return ok
		},
		Action: func() error {
			zd, ok := tdns.Zones.Get(mconf.Sidecar.Identity)
			if !ok {
				return fmt.Errorf("LoadSidecarConfig: Action: zone data for sidecar identity '%s' still not found", mconf.Sidecar.Identity)
			}
			zd.Options[tdns.OptAllowUpdates] = true

			log.Printf("LoadSidecarConfig: sending PING command to sidecar '%s'", mconf.Sidecar.Identity)
			zd.KeyDB.UpdateQ <- tdns.UpdateRequest{
				Cmd: "PING",
			}

			log.Printf("LoadSidecarConfig: publishing TLSA RR for sidecar identity '%s'", mconf.Sidecar.Identity)

			err = zd.PublishTLSARR(string(certPEM), mconf.Sidecar.Port)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: failed to publish TLSA RR: %v", err)
			}

			log.Printf("LoadSidecarConfig: Successfully published TLSA RR for sidecar identity '%s'\n", mconf.Sidecar.Identity)

			apex, _ := zd.Data.Get(zd.ZoneName)
			if err != nil {
				return fmt.Errorf("LoadSidecarConfig: Error: failed to get zone apex %s: %v", zd.ZoneName, err)
			}

			tlsarr_rrset := apex.RRtypes.GetOnlyRRSet(dns.TypeTLSA)
			var tlsarr *dns.TLSA
			if len(tlsarr_rrset.RRs) > 0 {
				tlsarr = tlsarr_rrset.RRs[0].(*dns.TLSA)
				log.Printf("LoadSidecarConfig: TLSA RR: %s", tlsarr.String())
			} else {
				log.Printf("LoadSidecarConfig: Error: TLSA: %v", tlsarr_rrset)
				return fmt.Errorf("LoadSidecarConfig: Error: TLSA: %v", tlsarr_rrset)
			}
			return nil
		},
	}

	mconf.Internal.UpdateQ <- ur

	return nil
}
