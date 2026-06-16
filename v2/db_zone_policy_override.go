/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Per-zone DNSSEC policy overrides set dynamically at runtime (via
 * `zone set-policy`), persisted in the ZonePolicyOverride table so a live
 * policy change survives restart without rewriting the operator's YAML.
 * The effective policy for a zone is the override if present, else the
 * policy named in the zone's config.
 */

package tdns

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// SetZonePolicyOverride records (or replaces) the dynamic DNSSEC policy for a
// zone. The zone name is normalized to FQDN.
func SetZonePolicyOverride(kdb *KeyDB, zone, policy string) error {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	policy = strings.TrimSpace(policy)
	if zone == "." || policy == "" {
		return fmt.Errorf("SetZonePolicyOverride: empty zone or policy")
	}
	const q = `
INSERT INTO ZonePolicyOverride (zone, policy, set_at)
VALUES (?, ?, datetime('now'))
ON CONFLICT(zone) DO UPDATE SET
  policy = excluded.policy,
  set_at = excluded.set_at`
	_, err := kdb.DB.Exec(q, zone, policy)
	return err
}

// ClearZonePolicyOverride removes a zone's dynamic policy override (if any),
// so the zone falls back to its config-base policy. Removing a non-existent
// override is not an error.
func ClearZonePolicyOverride(kdb *KeyDB, zone string) error {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	_, err := kdb.DB.Exec(`DELETE FROM ZonePolicyOverride WHERE zone = ?`, zone)
	return err
}

// GetZonePolicyOverride returns the dynamic policy name for a zone and whether
// one is set. ok is false (and name "") when the zone has no override.
func GetZonePolicyOverride(kdb *KeyDB, zone string) (name string, ok bool, err error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	var v sql.NullString
	err = kdb.DB.QueryRow(`SELECT policy FROM ZonePolicyOverride WHERE zone = ?`, zone).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !v.Valid || strings.TrimSpace(v.String) == "" {
		return "", false, nil
	}
	return v.String, true, nil
}

// EffectiveDnssecPolicyName resolves the policy NAME that should apply to a
// zone: the dynamic override if one is set, otherwise the config-base name.
// A DB error is treated as "no override" (fall back to config) and reported to
// the caller for logging; the zone should still load on its config base rather
// than fail because of a transient DB issue.
func EffectiveDnssecPolicyName(kdb *KeyDB, zone, configName string) (effective string, overridden bool, err error) {
	if kdb == nil {
		return configName, false, nil
	}
	name, ok, gerr := GetZonePolicyOverride(kdb, zone)
	if gerr != nil {
		return configName, false, gerr
	}
	if ok {
		return name, true, nil
	}
	return configName, false, nil
}
