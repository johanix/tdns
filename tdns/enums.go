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
	OptFoldCase
	OptBlackLies
	OptDontPublishKey
	OptOnlineSigning
	OptMultiSigner
	OptDirty
	OptFrozen
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
	OptAgent:             "agent",
}

var StringToZoneOption = map[string]ZoneOption{
	"delegation-sync-parent": OptDelSyncParent,
	"delegation-sync-child":  OptDelSyncChild,
	"allow-updates":          OptAllowUpdates,
	"allow-child-updates":    OptAllowChildUpdates,
	"fold-case":              OptFoldCase,
	"black-lies":             OptBlackLies,
	"dont-publish-key":       OptDontPublishKey,
	"online-signing":         OptOnlineSigning,
	"multisigner":            OptMultiSigner,
	"dirty":                  OptDirty,
	"frozen":                 OptFrozen,
	"agent":                  OptAgent,
}
