/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

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
	OptMultiSigner
	OptDirty
	OptFrozen
	OptAutomaticZone
	OptAgent // XXX: Hmm. Is this needed?
)

var ZoneOptionToString = map[ZoneOption]string{
	OptDelSyncParent:     "delegation-sync-parent",
	OptDelSyncChild:      "delegation-sync-child",
	OptAllowUpdates:      "allow-updates",
	OptAllowChildUpdates: "allow-child-updates",
	OptFoldCase:          "fold-case",
	OptBlackLies:         "black-lies",
	OptDontPublishKey:    "dont-publish-key",
	OptOnlineSigning:     "online-signing",
	OptMultiSigner:       "multisigner",
	OptDirty:             "dirty",
	OptFrozen:            "frozen",
	OptAutomaticZone:     "automatic-zone",
	OptAgent:             "agent",
	OptAllowCombine:      "allow-combine", // Dynamically et if app=combiner and zone contains a HSYNC RRset
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
	"multisigner":            OptMultiSigner,
	"dirty":                  OptDirty,
	"frozen":                 OptFrozen,
	"automatic-zone":         OptAutomaticZone,
	"agent":                  OptAgent,
}

type AppType uint8

const (
	AppTypeServer AppType = iota + 1
	AppTypeAgent
	AppTypeMSA
	AppTypeCombiner
)

var AppTypeToString = map[AppType]string{
	AppTypeServer:   "server",
	AppTypeAgent:    "agent",
	AppTypeMSA:      "msa",
	AppTypeCombiner: "combiner",
}

var StringToAppType = map[string]AppType{
	"server":   AppTypeServer,
	"agent":    AppTypeAgent,
	"msa":      AppTypeMSA,
	"combiner": AppTypeCombiner,
}
