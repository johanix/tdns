package tdns

import (
	"fmt"
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

func (conf *Config) parseAuthOptions() {
	raw := conf.DnsEngine.OptionsStrs
	clean := make(map[AuthOption]string)

	// Apply defaults for options that have them, even when no options are configured
	clean[AuthOptParentUpdate] = UpdateModeReplace

	if len(raw) == 0 {
		conf.DnsEngine.Options = clean
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

		authOpt, ok := StringToAuthOption[key]
		if !ok {
			log.Printf("ParseConfig: Auth option %q is unknown and will be ignored", key)
			continue
		}

		switch authOpt {
		case AuthOptParentUpdate:
			val := strings.ToLower(optval)
			if val == "" {
				val = UpdateModeReplace
			}
			switch val {
			case UpdateModeReplace, UpdateModeDelta:
				clean[authOpt] = val
			default:
				log.Printf("ParseConfig: Auth option %q has invalid value %q (allowed: %s|%s); defaulting to %s", key, optval, UpdateModeReplace, UpdateModeDelta, UpdateModeReplace)
				clean[authOpt] = UpdateModeReplace
			}
		default:
			clean[authOpt] = optval
		}
	}

	conf.DnsEngine.Options = clean
}

// parseZoneOptions validates and applies zone-specific option strings, updating zconf.Options and returning a map of enabled ZoneOption flags.
//
// It parses and normalizes the options listed in zconf.OptionsStrs, enables recognized options, and ignores unknown or invalid ones.
// For configuration problems (unknown options, missing dependencies such as DNSSEC policy for online signing or missing multisigner config/sync channel),
// the function records a ConfigError on zd when provided and logs the issue.
// The function returns a map whose keys are the enabled ZoneOption values.
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

	case OptCatalogZone:
		// Catalog zone requires valid catalog configuration
		if conf.Catalog.MetaGroups == nil {
			errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone (option catalog-zone), but catalog.meta_groups is missing or incorrectly structured. Please ensure your config has:\n"+
				"catalog:\n"+
				"  policy:\n"+
				"    zones:\n"+
				"      add: auto\n"+
				"  meta_groups:  # NOTE: This must be a sibling of 'policy', not nested under it\n"+
				"    meta_foo:\n"+
				"      upstream: \"...\"\n"+
				"      store: xfr", zname)
			log.Printf("Error: %s", errorMsg)
			if zd != nil {
				zd.SetError(ConfigError, errorMsg)
			}
			continue
		}

		// Validate catalog policy configuration
		if conf.Catalog.Policy.Zones.Add == "" {
			errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone, but catalog.policy.zones.add is not set. Please set it to either 'auto' or 'manual'.", zname)
			log.Printf("Error: %s", errorMsg)
			if zd != nil {
				zd.SetError(ConfigError, errorMsg)
			}
			continue
		}
		if conf.Catalog.Policy.Zones.Add != "auto" && conf.Catalog.Policy.Zones.Add != "manual" {
			errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone, but catalog.policy.zones.add has invalid value '%s'. Must be either 'auto' or 'manual'.", zname, conf.Catalog.Policy.Zones.Add)
			log.Printf("Error: %s", errorMsg)
			if zd != nil {
				zd.SetError(ConfigError, errorMsg)
			}
			continue
		}
		if conf.Catalog.Policy.Zones.Remove != "" && conf.Catalog.Policy.Zones.Remove != "auto" && conf.Catalog.Policy.Zones.Remove != "manual" {
			errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone, but catalog.policy.zones.remove has invalid value '%s'. Must be either 'auto' or 'manual'.", zname, conf.Catalog.Policy.Zones.Remove)
			log.Printf("Error: %s", errorMsg)
			if zd != nil {
				zd.SetError(ConfigError, errorMsg)
			}
			continue
		}

		options[opt] = true
		cleanoptions = append(cleanoptions, opt)
		log.Printf("ParseZones: Zone %s: catalog zone option enabled (type: %s, policy: add=%s, remove=%s)", zname, zconf.Type, conf.Catalog.Policy.Zones.Add, conf.Catalog.Policy.Zones.Remove)

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
