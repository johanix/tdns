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
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("SetZonePolicyOverride: nil keystore")
	}
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

// ClearZonePolicyOverride removes a zone's dynamic policy override (if any), so
// the zone falls back to its config-base policy. It clears ONLY the override
// (intent) columns — `policy` and `set_at` — and leaves the last-applied record
// (applied_*) in the same row intact: the override and the applied record are
// independent (a config-only zone can carry applied_* with no override). It
// therefore UPDATEs the row to an empty override rather than DELETEing it, so an
// applied_* record is never collaterally erased. An empty `policy` reads as "no
// override" via GetZonePolicyOverride. Clearing a non-existent override (no row)
// is not an error.
func ClearZonePolicyOverride(kdb *KeyDB, zone string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("ClearZonePolicyOverride: nil keystore")
	}
	zone = dns.Fqdn(strings.TrimSpace(zone))
	_, err := kdb.DB.Exec(`UPDATE ZonePolicyOverride SET policy = '', set_at = NULL WHERE zone = ?`, zone)
	return err
}

// GetZonePolicyOverride returns the dynamic policy name for a zone and whether
// one is set. ok is false (and name "") when the zone has no override.
func GetZonePolicyOverride(kdb *KeyDB, zone string) (name string, ok bool, err error) {
	if kdb == nil || kdb.DB == nil {
		return "", false, fmt.Errorf("GetZonePolicyOverride: nil keystore")
	}
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

// --- Last-applied policy (P0-2 / Plan B) ---------------------------------
//
// The applied_* columns record what a zone was LAST SUCCESSFULLY SIGNED under,
// independent of the CLI `policy` override (INTENT). They live in the same
// ZonePolicyOverride row so a single lookup covers both, but the two are
// semantically distinct: a config-only zone can have applied_* set with an
// empty `policy` (no override), and clearing the override does not erase the
// last-applied record.

// SetZoneAppliedPolicy records the policy a zone was last successfully signed
// under (source 'config' | 'command'), stamping applied_at. It never touches
// the CLI override `policy`: a fresh row is inserted with an empty override
// (config-only zone), and an existing row keeps whatever override it had.
func SetZoneAppliedPolicy(kdb *KeyDB, zone, policy, source string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("SetZoneAppliedPolicy: nil keystore")
	}
	zone = dns.Fqdn(strings.TrimSpace(zone))
	policy = strings.TrimSpace(policy)
	source = strings.TrimSpace(source)
	if zone == "." || policy == "" {
		return fmt.Errorf("SetZoneAppliedPolicy: empty zone or policy")
	}
	if source != "config" && source != "command" {
		return fmt.Errorf("SetZoneAppliedPolicy: invalid source %q (want 'config' or 'command')", source)
	}
	// On INSERT the override column is '' (this zone has no CLI override); on
	// CONFLICT we update ONLY the applied_* columns, leaving `policy` intact.
	const q = `
INSERT INTO ZonePolicyOverride (zone, policy, applied_policy, applied_source, applied_at)
VALUES (?, '', ?, ?, datetime('now'))
ON CONFLICT(zone) DO UPDATE SET
  applied_policy = excluded.applied_policy,
  applied_source = excluded.applied_source,
  applied_at     = excluded.applied_at`
	_, err := kdb.DB.Exec(q, zone, policy, source)
	return err
}

// GetZoneAppliedPolicy returns the last-applied policy name and source for a
// zone. ok is false (and name/source "") when the zone has no applied record,
// whether because it has no row at all or the applied_policy column is unset.
func GetZoneAppliedPolicy(kdb *KeyDB, zone string) (name string, source string, ok bool, err error) {
	if kdb == nil || kdb.DB == nil {
		return "", "", false, fmt.Errorf("GetZoneAppliedPolicy: nil keystore")
	}
	zone = dns.Fqdn(strings.TrimSpace(zone))
	var p, s sql.NullString
	err = kdb.DB.QueryRow(
		`SELECT applied_policy, applied_source FROM ZonePolicyOverride WHERE zone = ?`, zone,
	).Scan(&p, &s)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	if !p.Valid || strings.TrimSpace(p.String) == "" {
		return "", "", false, nil
	}
	return strings.TrimSpace(p.String), strings.TrimSpace(s.String), true, nil
}

// GetZoneAppliedPolicyDetail is like GetZoneAppliedPolicy but also returns the
// applied_at timestamp (as stored by SQLite datetime('now'): 'YYYY-MM-DD
// HH:MM:SS' in UTC). It is a read-only accessor for display (the `zone desc`
// CLI); appliedAt is "" when the column is NULL. ok is false (and all strings
// "") when the zone has no applied record.
func GetZoneAppliedPolicyDetail(kdb *KeyDB, zone string) (name, source, appliedAt string, ok bool, err error) {
	if kdb == nil || kdb.DB == nil {
		return "", "", "", false, fmt.Errorf("GetZoneAppliedPolicyDetail: nil keystore")
	}
	zone = dns.Fqdn(strings.TrimSpace(zone))
	var p, s, a sql.NullString
	err = kdb.DB.QueryRow(
		`SELECT applied_policy, applied_source, applied_at FROM ZonePolicyOverride WHERE zone = ?`, zone,
	).Scan(&p, &s, &a)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	if !p.Valid || strings.TrimSpace(p.String) == "" {
		return "", "", "", false, nil
	}
	return strings.TrimSpace(p.String), strings.TrimSpace(s.String), strings.TrimSpace(a.String), true, nil
}

// ClearZoneAppliedPolicy clears a zone's last-applied record (applied_* → NULL)
// while leaving the CLI override row intact. Used by the `policy-reset` escape
// hatch (§6.7) so a forced re-sign starts from a clean last-applied slate.
// Clearing a zone with no row is not an error.
func ClearZoneAppliedPolicy(kdb *KeyDB, zone string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("ClearZoneAppliedPolicy: nil keystore")
	}
	zone = dns.Fqdn(strings.TrimSpace(zone))
	_, err := kdb.DB.Exec(
		`UPDATE ZonePolicyOverride
SET applied_policy = NULL, applied_source = NULL, applied_at = NULL
WHERE zone = ?`, zone)
	return err
}
