package tdns

import (
	"fmt"
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
			lg.Warn("unknown IMR option, ignoring", "option", key)
			continue
		}

		switch imrOpt {
		case ImrOptRevalidateNS, ImrOptQueryForTransport, ImrOptAlwaysQueryForTransport, ImrOptQueryForTransportTLSA:
			if optval != "" {
				lg.Warn("IMR option does not accept a value, ignoring provided value", "option", key, "value", optval)
			}
			clean[imrOpt] = "true"
		case ImrOptUseTransportSignals:
			// This option is now opt-out: enabled by default, only disabled if explicitly set to false
			if optval == "false" {
				clean[imrOpt] = "false"
			} else {
				if optval != "" && optval != "true" {
					lg.Warn("IMR option has invalid value (use 'false' to disable), ignoring", "option", key, "value", optval)
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
				lg.Warn("IMR option has invalid value (allowed: svcb|tsync), defaulting to svcb", "option", key, "value", optval)
				clean[imrOpt] = "svcb"
			}
		default:
			clean[imrOpt] = optval
		}
	}

	conf.Imr.Options = clean
}

func (conf *Config) ParseAuthOptions() {
	raw := conf.DnsEngine.OptionsStrs
	clean := make(map[AuthOption]string)

	// Apply defaults for options that have them, even when no options are configured
	clean[AuthOptParentUpdate] = UpdateModeDelta

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
			lg.Warn("unknown Auth option, ignoring", "option", key)
			continue
		}

		switch authOpt {
		case AuthOptParentUpdate:
			val := strings.ToLower(optval)
			if val == "" {
				val = UpdateModeDelta
			}
			switch val {
			case UpdateModeDelta:
				clean[authOpt] = val
			default:
				lg.Warn("Auth option has invalid value, defaulting", "option", key, "value", optval, "allowed", UpdateModeDelta, "default", UpdateModeDelta)
				clean[authOpt] = UpdateModeDelta
			}
		case AuthOptPersistOutboundSerial:
			if optval != "" {
				lg.Warn("Auth option does not accept a value, ignoring provided value", "option", key, "value", optval)
			}
			clean[authOpt] = "true"
		default:
			clean[authOpt] = optval
		}
	}

	conf.DnsEngine.Options = clean
}

func (conf *Config) parseMultiProviderOptions() {
	if conf.MultiProvider == nil {
		return
	}
	mp := conf.MultiProvider

	// Combiner options
	mp.CombinerOptions = map[CombinerOption]bool{}
	for _, raw := range mp.CombinerOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if co, ok := StringToCombinerOption[opt]; ok {
			mp.CombinerOptions[co] = true
		} else {
			lg.Warn("unknown combiner option, ignoring", "option", opt)
		}
	}
	// Migrate legacy add-signature field
	if mp.AddSignature && !mp.CombinerOptions[CombinerOptAddSignature] {
		mp.CombinerOptions[CombinerOptAddSignature] = true
	}

	// Signer options
	mp.SignerOptions = map[SignerOption]bool{}
	for _, raw := range mp.SignerOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if so, ok := StringToSignerOption[opt]; ok {
			mp.SignerOptions[so] = true
		} else {
			lg.Warn("unknown signer option, ignoring", "option", opt)
		}
	}

	// Agent options
	mp.AgentOptions = map[AgentOption]bool{}
	for _, raw := range mp.AgentOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if ao, ok := StringToAgentOption[opt]; ok {
			mp.AgentOptions[ao] = true
		} else {
			lg.Warn("unknown agent option, ignoring", "option", opt)
		}
	}
}

// parseZoneOptions validates and applies zone-specific option strings, updating zconf.Options and returning a map of enabled ZoneOption flags.
//
// It parses and normalizes the options listed in zconf.OptionsStrs, enables recognized options, and ignores unknown or invalid ones.
// For configuration problems (unknown options, missing dependencies such as DNSSEC policy for online signing or missing multisigner config/sync channel),
// the function records a ConfigError on zd when provided and logs the issue.
// The function returns a map whose keys are the enabled ZoneOption values.
func parseZoneOptions(conf *Config, zname string, zconf *ZoneConf, zd *ZoneData) map[ZoneOption]bool {
	lg.Debug("zone incoming options", "zone", zname, "options", zconf.OptionsStrs)
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
		lg.Debug("checking zone option", "zone", zname, "option", option)
		opt, exist := StringToZoneOption[option]
		if !exist {
			lg.Warn("unknown zone option, ignoring", "zone", zname, "option", option)
			lg.Debug("defined zone options", "zone", zname, "options", StringToZoneOption)
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
			OptAllowEdits,
			OptFoldCase,
			OptBlackLies,
			OptDontPublishKey,
			OptAddTransportSignal:
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)

		case OptOnlineSigning, OptInlineSigning:
			if Globals.App.Type == AppTypeAgent {
				lg.Error("option ignored: agent does not allow signing", "zone", zname, "option", ZoneOptionToString[opt])
				continue
			}
			if zconf.DnssecPolicy != "" {
				options[opt] = true
				cleanoptions = append(cleanoptions, opt)
			} else {
				if zd != nil {
					zd.SetError(ConfigError, "%s is ignored because the DNSSEC policy is not set", ZoneOptionToString[opt])
				}
				lg.Error("option ignored: DNSSEC policy not set", "zone", zname, "option", ZoneOptionToString[opt])
			}

		case OptMultiProvider:
			// On the signer (AppTypeAuth), require server-level multi-provider config.
			// On agents, the zone option alone is sufficient — the HSYNC RRset is the authority.
			if Globals.App.Type == AppTypeAuth && (conf.MultiProvider == nil || !conf.MultiProvider.Active) {
				lg.Error("option requires multi-provider.active in server config", "zone", zname, "option", ZoneOptionToString[opt])
				if zd != nil {
					zd.SetError(ConfigError, "option %s requires multi-provider.active: true in server config", ZoneOptionToString[opt])
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			lg.Debug("zone option accepted", "zone", zname, "option", ZoneOptionToString[opt])

		case OptCatalogZone:
			// Catalog zone requires valid catalog configuration
			// Note: options[OptCatalogZone] was already set in pre-scan above

			// Check for group_prefixes (required if config_groups exist)
			if conf.Catalog != nil && len(conf.Catalog.ConfigGroups) > 0 && (conf.Catalog.GroupPrefixes.Config == "" || conf.Catalog.GroupPrefixes.Signing == "") {
				errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone (option catalog-zone), but catalog.group_prefixes is missing. Please ensure your config has:\n"+
					"catalog:\n"+
					"  group_prefixes:\n"+
					"    config: \"config\"\n"+
					"    signing: \"sign\"\n"+
					"  config_groups:\n"+
					"    example:\n"+
					"      upstream: \"primary-server:port\"\n"+
					"      store: map\n", zname)
				lg.Error("catalog zone missing group_prefixes config", "zone", zname, "detail", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, "%s", errorMsg)
				}
				continue
			}

			// Check for config_groups (or legacy meta_groups)
			if conf.Catalog == nil || (conf.Catalog.ConfigGroups == nil && conf.Catalog.MetaGroups == nil) {
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
				lg.Error("catalog zone missing config_groups", "zone", zname, "detail", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, "%s", errorMsg)
				}
				continue
			}

			// options[opt] already set in pre-scan
			cleanoptions = append(cleanoptions, opt)
			lg.Debug("catalog zone option enabled", "zone", zname, "type", zconf.Type)

		case OptCatalogMemberAutoCreate:
			// Only valid on catalog zones (checked via pre-scan above)
			if !isCatalogZone {
				errorMsg := fmt.Sprintf("Zone %s: catalog-member-auto-create option is only valid on catalog zones (must also have catalog-zone option)", zname)
				lg.Error("catalog-member-auto-create requires catalog-zone option", "zone", zname, "detail", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, "%s", errorMsg)
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			lg.Debug("catalog member auto-create enabled", "zone", zname)

		case OptCatalogMemberAutoDelete:
			// Only valid on catalog zones (checked via pre-scan above)
			if !isCatalogZone {
				errorMsg := fmt.Sprintf("Zone %s: catalog-member-auto-delete option is only valid on catalog zones (must also have catalog-zone option)", zname)
				lg.Error("catalog-member-auto-delete requires catalog-zone option", "zone", zname, "detail", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, "%s", errorMsg)
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			lg.Debug("catalog member auto-delete enabled", "zone", zname)

		case OptMPManualApproval:
			// Only valid on the combiner — controls whether incoming UPDATEs
			// from agents require manual approval before being applied.
			if Globals.App.Type != AppTypeMPCombiner {
				lg.Error("mp-manual-approval is only valid on the combiner, ignoring", "zone", zname)
				if zd != nil {
					zd.SetError(ConfigError, "mp-manual-approval is only valid on combiner zones")
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			lg.Debug("mp-manual-approval enabled", "zone", zname)

		default:
			lg.Warn("unknown zone option in switch, ignoring", "zone", zname, "option", ZoneOptionToString[opt])
			if zd != nil {
				zd.SetError(ConfigError, "unknown config option: %s", ZoneOptionToString[opt])
			}
			continue
		}
	}
	zconf.Options = cleanoptions
	return options
}
