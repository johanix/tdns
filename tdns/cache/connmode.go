/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
 package cache

type ConnMode uint8

const (
	ConnModeLegacy ConnMode = iota
	ConnModeOpportunistic
	ConnModeValidated
	ConnModeStrict
)

var ConnModeToString = map[ConnMode]string{
	ConnModeLegacy:        "legacy",
	ConnModeOpportunistic: "opportunistic",
	ConnModeValidated:     "validated",
	ConnModeStrict:        "strict",
}

var StringToConnMode = map[string]ConnMode{
	"legacy":        ConnModeLegacy,
	"opportunistic": ConnModeOpportunistic,
	"validated":     ConnModeValidated,
	"strict":        ConnModeStrict,
}