/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "fmt"

type CacheContext uint8

const (
	ContextAnswer CacheContext = iota + 1
	ContextHint
	ContextPriming
	ContextReferral
	ContextNXDOMAIN
	ContextNoErrNoAns
	ContextGlue    // from additional section
	ContextFailure // some sort of general failure that we cannot sort out
)

var CacheContextToString = map[CacheContext]string{
	ContextAnswer:     "answer",
	ContextHint:       "hint",
	ContextPriming:    "priming",
	ContextReferral:   "referral",
	ContextNXDOMAIN:   "NXDOMAIN",
	ContextNoErrNoAns: "NOERROR, NODATA (negative response type 0)",
	ContextGlue:       "glue",
	ContextFailure:    "failure",
}

type ZoneOption uint8

const (
	OptDelSyncParent ZoneOption = iota + 1
	OptDelSyncChild
	OptAllowUpdates
	OptAllowChildUpdates
	OptAllowCombine // Dynamically et if app=combiner and zone contains a HSYNC RRset
	OptFoldCase
	OptBlackLies
	OptDontPublishKey
	OptOnlineSigning
	OptMultiSigner // OBE?
	OptDirty
	OptFrozen
	OptAutomaticZone
	// OptServerSvcb
	OptAddTransportSignal
)

var ZoneOptionToString = map[ZoneOption]string{
	OptDelSyncParent:     "delegation-sync-parent",
	OptDelSyncChild:      "delegation-sync-child",
	OptAllowUpdates:      "allow-updates",
	OptAllowChildUpdates: "allow-child-updates",
	OptAllowCombine:      "allow-combine", // Dynamically et if app=combiner and zone contains a HSYNC RRset
	OptFoldCase:          "fold-case",
	OptBlackLies:         "black-lies",
	OptDontPublishKey:    "dont-publish-key",
	OptOnlineSigning:     "online-signing",
	OptMultiSigner:       "multisigner", // OBE?
	OptDirty:             "dirty",
	OptFrozen:            "frozen",
	OptAutomaticZone:     "automatic-zone",
	// OptServerSvcb:        "create-server-svcb",
	OptAddTransportSignal: "add-transport-signal",
}

var StringToZoneOption = map[string]ZoneOption{
	"delegation-sync-parent": OptDelSyncParent,
	"delegation-sync-child":  OptDelSyncChild,
	"allow-updates":          OptAllowUpdates,
	"allow-child-updates":    OptAllowChildUpdates,
	"allow-combine":          OptAllowCombine,
	"fold-case":              OptFoldCase,
	"black-lies":             OptBlackLies,
	"dont-publish-key":       OptDontPublishKey,
	"online-signing":         OptOnlineSigning,
	"multisigner":            OptMultiSigner, // OBE?
	"dirty":                  OptDirty,
	"frozen":                 OptFrozen,
	"automatic-zone":         OptAutomaticZone,
	"add-transport-signal":   OptAddTransportSignal,
}

type AppType uint8

const (
	AppTypeServer AppType = iota + 1
	AppTypeAgent
	AppTypeCombiner
	AppTypeImr // simplified recursor
	AppTypeCli
)

var AppTypeToString = map[AppType]string{
	AppTypeServer:   "server",
	AppTypeAgent:    "agent",
	AppTypeCombiner: "combiner",
	AppTypeImr:      "imr",
	AppTypeCli:      "cli",
}

var StringToAppType = map[string]AppType{
	"server": AppTypeServer,
	"agent":  AppTypeAgent,
	//"msa":      AppTypeMSA,
	"combiner": AppTypeCombiner,
}

type ErrorType uint8

const (
	NoError ErrorType = iota
	ConfigError
	RefreshError
	AgentError
	DnssecError
)

var ErrorTypeToString = map[ErrorType]string{
	ConfigError:  "config",
	RefreshError: "refresh",
	AgentError:   "agent",
	DnssecError:  "DNSSEC",
}

func (zd *ZoneData) SetError(errtype ErrorType, errmsg string, args ...interface{}) {
	if errtype == NoError {
		zd.Error = false
		zd.ErrorType = NoError
		zd.ErrorMsg = ""
	} else {
		zd.Error = true
		zd.ErrorType = errtype
		zd.ErrorMsg = fmt.Sprintf(errmsg, args...)
	}
	Zones.Set(zd.ZoneName, zd)
}
