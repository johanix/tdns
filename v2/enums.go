/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "fmt"

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
	OptCatalogZone
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
	OptCatalogZone:        "catalog-zone",
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
	"catalog-zone":           OptCatalogZone,
}

type ImrOption uint8

const (
	ImrOptRevalidateNS ImrOption = iota + 1
	ImrOptQueryForTransport
	ImrOptAlwaysQueryForTransport
	ImrOptTransportSignalType
	ImrOptQueryForTransportTLSA
	ImrOptUseTransportSignals
)

var ImrOptionToString = map[ImrOption]string{
	ImrOptRevalidateNS:            "revalidate-ns",
	ImrOptQueryForTransport:       "query-for-transport",
	ImrOptAlwaysQueryForTransport: "always-query-for-transport",
	ImrOptTransportSignalType:     "transport-signal-type",
	ImrOptQueryForTransportTLSA:   "query-for-transport-tlsa",
	ImrOptUseTransportSignals:     "use-transport-signals",
}

var StringToImrOption = map[string]ImrOption{
	"revalidate-ns":              ImrOptRevalidateNS,
	"query-for-transport":        ImrOptQueryForTransport,
	"always-query-for-transport": ImrOptAlwaysQueryForTransport,
	"transport-signal-type":      ImrOptTransportSignalType,
	"query-for-transport-tlsa":   ImrOptQueryForTransportTLSA,
	"use-transport-signals":      ImrOptUseTransportSignals,
}

type AuthOption uint8

const (
	AuthOptParentUpdate AuthOption = iota + 1
)

var AuthOptionToString = map[AuthOption]string{
	AuthOptParentUpdate: "parent-update",
}

var StringToAuthOption = map[string]AuthOption{
	"parent-update": AuthOptParentUpdate,
}

type AppType uint8

const (
	AppTypeAuth AppType = iota + 1
	AppTypeAgent
	AppTypeCombiner
	AppTypeImr // simplified recursor
	AppTypeCli
	AppTypeReporter
	AppTypeScanner
	AppTypeKdc // Key Distribution Center
	AppTypeKrs // Key Receiving Service (edge receiver)
	AppTypeEdgeSigner // NYI
)

var AppTypeToString = map[AppType]string{
	AppTypeAuth:       "auth",
	AppTypeAgent:      "agent",
	AppTypeCombiner:   "combiner",
	AppTypeImr:        "imr",
	AppTypeCli:        "cli",
	AppTypeReporter:   "reporter",
	AppTypeScanner:    "scanner",
	AppTypeKdc:        "kdc",
	AppTypeKrs:        "krs",
	AppTypeEdgeSigner: "edgeSigner", // NYI
}

var StringToAppType = map[string]AppType{
	"auth":       AppTypeAuth,
	"agent":      AppTypeAgent,
	"combiner":   AppTypeCombiner,
	"imr":        AppTypeImr,
	"cli":        AppTypeCli,
	"reporter":   AppTypeReporter,
	"scanner":    AppTypeScanner,
	"kdc":        AppTypeKdc,
	"krs":        AppTypeKrs,
	"edgeSigner": AppTypeEdgeSigner, // NYI
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
