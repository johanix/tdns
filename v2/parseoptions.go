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
			case UpdateModeDelta, UpdateModeReplace:
				clean[authOpt] = val
			default:
				lg.Warn("Auth option has invalid value, defaulting", "option", key, "value", optval, "allowed", UpdateModeDelta+"|"+UpdateModeReplace, "default", UpdateModeDelta)
				clean[authOpt] = UpdateModeDelta
			}
		case AuthOptMinimalResponses:
			val := strings.ToLower(optval)
			switch val {
			case "", "true":
				clean[authOpt] = "true"
			case "false":
				clean[authOpt] = "false"
			default:
				lg.Warn("Auth option has invalid value, defaulting to true", "option", key, "value", optval)
				clean[authOpt] = "true"
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

	// PRE-SCAN: signing, for the same reason -- request-ixfr's verdict below
	// depends on it, and YAML option order must not decide the answer.
	signsOwnContent := false
	for _, option := range zconf.OptionsStrs {
		switch strings.ToLower(strings.TrimSpace(option)) {
		case "inline-signing", "online-signing":
			signsOwnContent = true
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
			OptDelSyncProxy,
			OptAllowUpdates,
			OptAllowChildUpdates,
			OptAllowApiUpdates,
			OptAllowEdits,
			OptFoldCase,
			OptBlackLies,
			OptDontPublishKey,
			OptAddTransportSignal,
			// Conflict resolution carries no condition of its own here. The
			// pair is mutually exclusive and db-wins is materialised when
			// neither is given, but both of those are decided in
			// activateUpdatePolicy, which runs after this switch and needs
			// the flags to have survived it.
			OptOnConflictDBWins,
			OptOnConflictZonefileWins:
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)

		case OptRequestIxfr, OptNoRequestIxfr:
			// IXFR-in enablement, and meaningful only on a secondary: nothing
			// outside Refresh's Secondary branch consults it. On a primary the
			// option is inert, which is exactly why it has to be reported --
			// an operator who writes it there has made a config mistake that
			// otherwise produces no symptom at all, and will go on believing
			// the setting does something.
			//
			// ConfigWarning, not ConfigError: the zone is entirely fine and
			// keeps serving. ConfigError is in serviceImpactingErrors, so
			// using it here would take a healthy zone dark over a setting that
			// does nothing.
			if zconf.Type == "primary" {
				errorMsg := fmt.Sprintf("Zone %s: %s is only meaningful on a secondary; ignored on a primary",
					zname, ZoneOptionToString[opt])
				lg.Error("option ignored: not a secondary", "zone", zname,
					"option", ZoneOptionToString[opt], "type", zconf.Type)
				if zd != nil {
					zd.SetError(ConfigWarning, "%s", errorMsg)
				}
				continue
			}
			// A signing secondary never asks for a delta either
			// (shouldRequestIxfr): its baseline is its OWN signatures, so a
			// difference sequence computed against the primary's copy names
			// records it does not hold. Reported for the same reason the
			// primary case is -- an option that does nothing produces no
			// symptom, so silence leaves the operator believing it works.
			//
			// Worth distinguishing from the primary case when reading the
			// message: here the option is inert only while the zone signs.
			// Turn signing off and it takes effect, which is why the text
			// names the reason rather than the role.
			if signsOwnContent {
				errorMsg := fmt.Sprintf("Zone %s: %s is ignored while the zone signs its own content; "+
					"a delta computed against the primary's copy cannot apply to locally re-signed data",
					zname, ZoneOptionToString[opt])
				lg.Error("option ignored: zone signs its own content", "zone", zname,
					"option", ZoneOptionToString[opt])
				if zd != nil {
					zd.SetError(ConfigWarning, "%s", errorMsg)
				}
				continue
			}
			// Default ON is expressed by requestIxfr() rather than by
			// materialising a flag here, so the persisted as-configured set
			// keeps saying what the operator actually wrote.
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

		case OptPublishZonemd, OptVerifyZonemd:
			// The `zonemd` block is only consulted for a zone that asks for
			// one, so a leftover block under a zone whose option was removed
			// is inert rather than an error.
			//
			// A bad block rejects the OPTION, not the zone: an unpublishable
			// digest is a degraded zone, not an unusable one, and taking a
			// zone off the air over a mistyped hash algorithm would be the
			// larger failure. The ConfigError is how the operator finds out.
			if _, err := resolveZonemdConf(zconf.Zonemd); err != nil {
				lg.Error("option ignored: invalid zonemd configuration",
					"zone", zname, "option", ZoneOptionToString[opt], "err", err)
				if zd != nil {
					zd.SetError(ConfigError, "zonemd: %v", err)
				}
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)

		case OptMultiProvider:
			if !invokeOptionValidator(opt, conf, zname, zd, options) {
				continue
			}
			options[opt] = true
			cleanoptions = append(cleanoptions, opt)
			lg.Debug("zone option accepted", "zone", zname, "option", ZoneOptionToString[opt])

		case OptCatalogZone:
			// Catalog zone requires valid catalog configuration
			// Note: options[OptCatalogZone] was already set in pre-scan above

			// Check for group-prefixes (required if config-groups exist)
			if conf.Catalog != nil && len(conf.Catalog.ConfigGroups) > 0 && (conf.Catalog.GroupPrefixes.Config == "" || conf.Catalog.GroupPrefixes.Signing == "") {
				errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone (option catalog-zone), but catalog.group-prefixes is missing. Please ensure your config has:\n"+
					"catalog:\n"+
					"  group-prefixes:\n"+
					"    config: \"config\"\n"+
					"    signing: \"sign\"\n"+
					"  config-groups:\n"+
					"    example:\n"+
					"      upstream: \"primary-server:port\"\n"+
					"      store: map\n", zname)
				lg.Error("catalog zone missing group-prefixes config", "zone", zname, "detail", errorMsg)
				if zd != nil {
					zd.SetError(ConfigError, "%s", errorMsg)
				}
				continue
			}

			// Check for config-groups (or legacy meta-groups)
			if conf.Catalog == nil || (conf.Catalog.ConfigGroups == nil && conf.Catalog.MetaGroups == nil) {
				errorMsg := fmt.Sprintf("Zone %s is configured as a catalog zone (option catalog-zone), but catalog.config-groups is missing or incorrectly structured. Please ensure your config has:\n"+
					"catalog:\n"+
					"  group-prefixes:\n"+
					"    config: \"config\"\n"+
					"    signing: \"sign\"\n"+
					"  config-groups:\n"+
					"    example:\n"+
					"      upstream: \"primary-server:port\"\n"+
					"      store: map\n"+
					"dynamiczones:\n"+
					"  catalog-members:\n"+
					"    add: auto\n", zname)
				lg.Error("catalog zone missing config-groups", "zone", zname, "detail", errorMsg)
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
