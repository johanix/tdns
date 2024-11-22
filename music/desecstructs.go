/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package music

import (
	"time"
)

type DesecLPost struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// The response to a (successful) login:
type DesecLResponse struct {
	ID               string
	Created          time.Time
	LastUsed         time.Time `json:"last_used"`
	MaxAgeRaw        string    `json:"max_age"`
	MaxAge           time.Duration
	MaxUnusedRaw     string `json:"max_unused_period"`
	MaxUnused        time.Duration
	Name             string
	PermManageTokens bool     `json:"perm_manage_tokens"`
	AllowedSubnets   []string `json:"allowed_subnets"`
	Valid            bool     `json:"is_valid"`
	Token            string
}

type ZoneName struct {
	Name string `json:"name"`
}

// This is what is returned per zone when listing them:
type DesecZone struct {
	Created    time.Time
	Published  time.Time
	Name       string
	MinimumTTL int `json:"minimum_ttl"`
	Touched    time.Time
}
