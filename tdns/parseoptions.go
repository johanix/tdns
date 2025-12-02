package tdns

import (
	"log"
	"strings"
)

func (conf *Config) parseImrOptions() {
	raw := conf.Imr.OptionsStrs
	clean := make(map[ImrOption]string)

	if len(raw) == 0 {
		conf.Imr.Options = clean
		return
	}

	for _, entry := range raw {
		val := strings.TrimSpace(entry)
		if val == "" {
			continue
		}

		var optval string
		key := val
		if idx := strings.Index(val, ":"); idx >= 0 {
			key = val[:idx]
			optval = val[idx+1:]
		}

		key = strings.ToLower(strings.TrimSpace(key))
		optval = strings.TrimSpace(optval)

		imrOpt, ok := StringToImrOption[key]
		if !ok {
			log.Printf("ParseConfig: IMR option %q is unknown and will be ignored", key)
			continue
		}

		switch imrOpt {
		case ImrOptRevalidateNS, ImrOptQueryForTransport, ImrOptAlwaysQueryForTransport, ImrOptQueryForTransportTLSA, ImrOptUseTransportSignals:
			if optval != "" {
				log.Printf("ParseConfig: IMR option %q does not accept a value; provided value %q will be ignored", key, optval)
			}
			clean[imrOpt] = "true"
		case ImrOptTransportSignalType:
			val := strings.ToLower(optval)
			if val == "" {
				val = "svcb"
			}
			switch val {
			case "svcb", "tsync":
				clean[imrOpt] = val
			default:
				log.Printf("ParseConfig: IMR option %q has invalid value %q (allowed: svcb|tsync); defaulting to svcb", key, optval)
				clean[imrOpt] = "svcb"
			}
		default:
			clean[imrOpt] = optval
		}
	}

	conf.Imr.Options = clean
}

func parseZoneOptions(conf *Config, zname string, zconf *ZoneConf, zd *ZoneData) map[ZoneOption]bool {
	log.Printf("ParseZones: zone %s incoming options: %v", zname, zconf.OptionsStrs)
	options := map[ZoneOption]bool{}
	var cleanoptions []ZoneOption
	for _, option := range zconf.OptionsStrs {
		option = strings.ToLower(strings.TrimSpace(option))
		if option == "" {
			continue
		}
		log.Printf("ParseZones: zone %s: checking option: %q", zname, option)
		opt, exist := StringToZoneOption[option]
		if !exist {
			log.Printf("ParseZones: Zone %s: Unknown option: %q. Ignored.", zname, option)
			log.Printf("ParseZones: zone %s: defined options: %v", zname, StringToZoneOption)
			if zd != nil {
				zd.SetError(ConfigError, "unknown config option: %q", option)
			}
			continue
		}

		switch opt {
		case OptDelSyncParent,
			OptDelSyncChild,
			OptAllowUpdates,
			OptAllowChildUpdates,
			OptAllowCombine,
			OptFoldCase,
			OptBlackLies,
			OptDontPublishKey,
			OptAddTransportSignal:
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)

		case OptOnlineSigning:
			if Globals.App.Type == AppTypeAgent {
				log.Printf("Error: Zone %s: Option \"%s\" is ignored because TDNS-AGENT does not allow online signing.", zname, ZoneOptionToString[opt])
				continue
			}
			if zconf.DnssecPolicy != "" {
				options[opt] = true
				cleanoptions = append(cleanoptions, opt)
			} else {
				if zd != nil {
					zd.SetError(ConfigError, "online-signing is ignored because the DNSSEC policy is not set")
				}
				log.Printf("Error: Zone %s: Option \"online-signing\" is ignored because the DNSSEC policy is not set.", zname)
			}

		case OptMultiSigner:
			if zconf.MultiSigner == "" || zconf.MultiSigner == "none" {
				log.Printf("Error: Zone %s: Option \"%s\" set without a corresponding multisigner config. Option ignored.", zname, ZoneOptionToString[opt])
				if zd != nil {
					zd.SetError(ConfigError, "option %s set without a corresponding multisigner config", ZoneOptionToString[opt])
				}
				continue
			}
			if _, exist := conf.MultiSigner[zconf.MultiSigner]; !exist {
				log.Printf("Error: Zone %s: Option \"%s\" set to non-existing multi-signer config \"%s\". Option ignored.", zname, ZoneOptionToString[opt], zconf.MultiSigner)
				if zd != nil {
					zd.SetError(ConfigError, "option %s set to non-existing multi-signer config \"%s\"", ZoneOptionToString[opt], zconf.MultiSigner)
				}
				continue
			}
			if conf.Internal.MusicSyncQ == nil {
				log.Printf("Error: Zone %s: Option \"%s\" set but no multi-signer sync channel configured. This is a fatal error.", zname, ZoneOptionToString[opt])
				if zd != nil {
					zd.SetError(ConfigError, "no multi-signer sync channel configured")
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			log.Printf("ParseZones: Zone %s: option \"%s\" accepted. Using multi-signer config \"%s\"", zname, ZoneOptionToString[opt], zconf.MultiSigner)

		default:
			log.Printf("Error: Zone %s: Unknown option: \"%s\". Option ignored.", zname, ZoneOptionToString[opt])
			if zd != nil {
				zd.SetError(ConfigError, "unknown config option: %s", ZoneOptionToString[opt])
			}
			continue
		}
	}
	zconf.Options = cleanoptions
	return options
}
