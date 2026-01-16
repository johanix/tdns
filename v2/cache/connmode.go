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

var connModeToString = map[ConnMode]string{
	ConnModeLegacy:        "legacy",
	ConnModeOpportunistic: "opportunistic",
	ConnModeValidated:     "validated",
	ConnModeStrict:        "strict",
}

var stringToConnMode = map[string]ConnMode{
	"legacy":        ConnModeLegacy,
	"opportunistic": ConnModeOpportunistic,
	"validated":     ConnModeValidated,
	"strict":        ConnModeStrict,
}

func (m ConnMode) String() string {
	if s, ok := connModeToString[m]; ok {
		return s
	}
	return "unknown"
}

func ParseConnMode(s string) (ConnMode, bool) {
	m, ok := stringToConnMode[s]
	return m, ok
}
