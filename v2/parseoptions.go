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
		case ImrOptRevalidateNS, ImrOptQueryForTransport, ImrOptAlwaysQueryForTransport, ImrOptQueryForTransportTLSA:
			if optval != "" {
				log.Printf("ParseConfig: IMR option %q does not accept a value; provided value %q will be ignored", key, optval)
			}
			clean[imrOpt] = "true"
		case ImrOptUseTransportSignals:
			// This option is now opt-out: enabled by default, only disabled if explicitly set to false
			if optval == "false" {
				clean[imrOpt] = "false"
			} else {
				if optval != "" && optval != "true" {
					log.Printf("ParseConfig: IMR option %q has invalid value %q (use 'false' to disable); ignoring", key, optval)
				}
				// Default to enabled (don't set in map, absence = enabled)
			}
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

	// PRE-SCAN: Check if catalog-zone is in the options list
	// This allows catalog-member-auto-create/auto-delete validation to work
	// regardless of YAML option order
	isCatalogZone := false
	for _, option := range zconf.OptionsStrs {
		option = strings.ToLower(strings.TrimSpace(option))
		if option == "catalog-zone" {
			isCatalogZone = true
			options[OptCatalogZone] = true
			break
		}
	}

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

		case OptOnlineSigning, OptInlineSigning:
			if Globals.App.Type == AppTypeAgent {
				log.Printf("Error: Zone %s: Option \"%s\" is ignored because TDNS-AGENT does not allow signing.", zname, ZoneOptionToString[opt])
				continue
			}
			if zconf.DnssecPolicy != "" {
				options[opt] = true
				cleanoptions = append(cleanoptions, opt)
			} else {
				if zd != nil {
					zd.SetError(ConfigError, "%s is ignored because the DNSSEC policy is not set", ZoneOptionToString[opt])
				}
				log.Printf("Error: Zone %s: Option \"%s\" is ignored because the DNSSEC policy is not set.", zname, ZoneOptionToString[opt])
			}

		case OptMultiProvider:
			// On the signer (AppTypeAuth), require server-level multi-provider config.
			// On agents, the zone option alone is sufficient — the HSYNC RRset is the authority.
			if Globals.App.Type == AppTypeAuth && (conf.MultiProvider == nil || !conf.MultiProvider.Active) {
				log.Printf("Error: Zone %s: Option \"%s\" set but multi-provider.active is not true in server config. Option ignored.", zname, ZoneOptionToString[opt])
				if zd != nil {
					zd.SetError(ConfigError, "option %s requires multi-provider.active: true in server config", ZoneOptionToString[opt])
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			log.Printf("ParseZones: Zone %s: option \"%s\" accepted", zname, ZoneOptionToString[opt])

		case OptCatalogZone:
			// Catalog zone requires valid catalog configuration
			// Note: options[OptCatalogZone] was already set in pre-scan above

			// Check for group_prefixes (required if config_groups exist)
			if len(conf.Catalog.ConfigGroups) > 0 && (conf.Catalog.GroupPrefixes.Config == "" || conf.Catalog.GroupPrefixes.Signing == "") {
				errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone (option catalog-zone), but catalog.group_prefixes is missing. Please ensure your config has:\n"+
					"catalog:\n"+
					"  group_prefixes:\n"+
					"    config: \"config\"\n"+
					"    signing: \"sign\"\n"+
					"  config_groups:\n"+
					"    example:\n"+
					"      upstream: \"primary-server:port\"\n"+
					"      store: map\n", zname)
				log.Printf("Error: %s", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, errorMsg)
				}
				continue
			}

			// Check for config_groups (or legacy meta_groups)
			if conf.Catalog.ConfigGroups == nil && conf.Catalog.MetaGroups == nil {
				errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone (option catalog-zone), but catalog.config_groups is missing or incorrectly structured. Please ensure your config has:\n"+
					"catalog:\n"+
					"  group_prefixes:\n"+
					"    config: \"config\"\n"+
					"    signing: \"sign\"\n"+
					"  config_groups:\n"+
					"    example:\n"+
					"      upstream: \"primary-server:port\"\n"+
					"      store: map\n"+
					"dynamiczones:\n"+
					"  catalog_members:\n"+
					"    add: auto\n", zname)
				log.Printf("Error: %s", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, errorMsg)
				}
				continue
			}

			// options[opt] already set in pre-scan
			cleanoptions = append(cleanoptions, opt)
			log.Printf("ParseZones: Zone %s: catalog zone option enabled (type: %s)", zname, zconf.Type)

		case OptCatalogMemberAutoCreate:
			// Only valid on catalog zones (checked via pre-scan above)
			if !isCatalogZone {
				errorMsg := fmt.Sprintf("Zone %s: catalog-member-auto-create option is only valid on catalog zones (must also have catalog-zone option)", zname)
				log.Printf("Error: %s", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, errorMsg)
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			log.Printf("ParseZones: Zone %s: catalog member auto-create enabled", zname)

		case OptCatalogMemberAutoDelete:
			// Only valid on catalog zones (checked via pre-scan above)
			if !isCatalogZone {
				errorMsg := fmt.Sprintf("Zone %s: catalog-member-auto-delete option is only valid on catalog zones (must also have catalog-zone option)", zname)
				log.Printf("Error: %s", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, errorMsg)
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			log.Printf("ParseZones: Zone %s: catalog member auto-delete enabled", zname)

		case OptMPManualApproval:
			// Only valid on the combiner — controls whether incoming UPDATEs
			// from agents require manual approval before being applied.
			if Globals.App.Type != AppTypeCombiner {
				log.Printf("Error: Zone %s: Option \"mp-manual-approval\" is only valid on the combiner. Ignored.", zname)
				if zd != nil {
					zd.SetError(ConfigError, "mp-manual-approval is only valid on combiner zones")
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			log.Printf("ParseZones: Zone %s: mp-manual-approval enabled", zname)

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
