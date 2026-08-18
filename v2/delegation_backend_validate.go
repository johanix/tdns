/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import "fmt"

// Which delegation backend makes sense for which kind of zone.
//
// The backends are not interchangeable and never were. Each answers a different
// question about WHERE approved child delegation data should end up:
//
//   - direct   -- into this zone, which this instance serves and owns.
//   - db       -- into a table, for whoever generates the zone to pick up.
//   - zonefile -- into files beside the zone, for the same reader.
//
// All three have real deployments. A tdns-agent running beside a BIND9 primary
// cannot use `direct` -- it does not serve the zone -- and its entire job is to
// verify and approve child updates and then hand them to whatever builds the
// zone. That is what db and zonefile are for.
//
// What has been missing is any check that the backend matches the zone. The
// only rule until now was "allow-child-updates requires SOME backend", so a
// combination that cannot work was accepted in silence and failed later as
// missing data rather than as a config error.

// validateDelegationBackendCombination rejects zone configurations whose
// delegation backend cannot do what the rest of the zone's settings ask for.
//
// Called from activateUpdatePolicy, after the conflict-resolution options have
// been materialised, because one of the rules below depends on which of them is
// in force.
func validateDelegationBackendCombination(zconf *ZoneConf, options map[ZoneOption]bool) error {
	backend := zconf.DelegationBackend
	if backend == "" {
		return nil // "no backend" is governed by the allow-child-updates rule.
	}

	isPrimary := zconf.Type == "primary"
	isSecondary := zconf.Type == "secondary"

	// (1) `direct` mutates the zone it is given and writes that zone's file. On
	// a SECONDARY the content belongs to the primary and is replaced wholesale
	// at the next transfer, so those edits do not survive.
	//
	// Deliberately NOT gated on the app type, unlike zoneMayOriginateContent.
	// That gate answers a different question -- "may this app author content
	// for this zone?" -- which is a permissions question and legitimately
	// app-specific, since a derived app may edit secondaries as its whole job.
	// This one asks whether the edits will still be there afterwards, and the
	// answer is no whoever makes them: a transfer overwrites the zone either
	// way. Gating it per app would also make one config valid or invalid
	// depending on which binary read it, which is a poor property for a rule
	// about a combination.
	if isSecondary && backend == "direct" {
		return fmt.Errorf(
			"zone %s is a secondary and delegationbackend is %q: a secondary's content belongs"+
				" to its primary, so direct's edits would be overwritten at the next transfer."+
				" Use delegationbackend: db (or a zonefile backend) to hand approved child"+
				" updates to whatever generates the zone",
			zconf.Name, backend)
	}

	// (2) A primary whose DB wins conflicts must own its delegation data too.
	//
	// on-conflict-db-wins says: when this zone's file and this zone's journal
	// disagree, the journal is right. A db or zonefile backend says the
	// opposite -- that approved child updates are handed OUT for someone else
	// to fold into the zone file, which makes that someone else the author of
	// the content. Both cannot be true. The child update would be recorded for
	// an external generator whose output this zone has already declared it will
	// overrule.
	//
	// The two settings describe the same deployment fact from different angles,
	// so the fix is whichever angle the operator actually meant, and the error
	// names both.
	if isPrimary && options[OptOnConflictDBWins] && backend != "direct" {
		return fmt.Errorf(
			"zone %s is a primary with on-conflict-db-wins and delegationbackend %q:"+
				" these contradict each other. db-wins says this server's own data beats the"+
				" zone file; a %q backend says approved child updates are handed to whoever"+
				" generates that zone file. Either set delegationbackend: direct (this server"+
				" owns the zone), or set the on-conflict-zonefile-wins option (the zone file is"+
				" generated elsewhere and wins)",
			zconf.Name, backend, backend)
	}

	return nil
}

// delegationBackendContract returns the line to log at startup for a zone whose
// child updates do NOT reach the served zone, or "" when they do.
//
// This is not a warning. The deployment is legitimate -- it is the whole reason
// db and zonefile exist -- but the consequence is easy to be surprised by: a
// child's delegation update lands in a table or a file, and the zone goes on
// serving the old delegation until something else regenerates it. Whether that
// something exists is a property of the deployment, not of the config, so it
// cannot be validated. It can be stated.
func delegationBackendContract(zconf *ZoneConf, options map[ZoneOption]bool) string {
	if zconf.DelegationBackend == "" || zconf.DelegationBackend == "direct" {
		return ""
	}
	if !options[OptAllowChildUpdates] {
		return ""
	}
	return fmt.Sprintf(
		"child updates for %s are recorded via the %q delegation backend and will NOT appear"+
			" in the served zone until whatever generates it picks them up",
		zconf.Name, zconf.DelegationBackend)
}

// delegationBackendUnusedWarning reports a backend that is configured but can
// never run, which usually means the operator believes child updates are
// enabled when they are not.
func delegationBackendUnusedWarning(zconf *ZoneConf, options map[ZoneOption]bool) string {
	if zconf.DelegationBackend == "" || options[OptAllowChildUpdates] {
		return ""
	}
	return fmt.Sprintf(
		"zone %s sets delegationbackend %q but not the allow-child-updates option,"+
			" so the backend is never used and no child update will be accepted",
		zconf.Name, zconf.DelegationBackend)
}
