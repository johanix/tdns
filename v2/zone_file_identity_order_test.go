package tdns

import "testing"

// The recorded file identity decides what the NEXT load does, so when it is
// written matters as much as what it holds.
//
// Writing it before the merge means a merge that fails still leaves the
// identity naming the new file. The next load then compares equal, calls the
// file unchanged, and takes the replay path -- which refuses, because the
// journal is anchored to the file BEFORE this one. The merge is never retried,
// and the journalled changes sit behind a file that looks settled.

const identityZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 9 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
old.example.	3600	IN	TXT	"remove me"
`

// A journal DEL of a record the replacement file still holds is a conflict, so
// the merge must write an artefact naming the loser. Taking the zone file path
// away leaves it nowhere to write, and the merge refuses rather than resolving
// the conflict silently -- the failure this test needs.
func failingMergeZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	zd := mergeTestZone(t, kdb, identityZone, nil, []string{"www.example. 3600 IN A 192.0.2.1"})
	zd.mu.Lock()
	zd.fileDigest, zd.fileSerial = "digest-of-the-replacement", 9
	zd.mu.Unlock()
	return zd
}

func TestFailedMergeLeavesTheRecordedIdentityAlone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := failingMergeZone(t, kdb)

	// What the previous load recorded. A different digest is what makes this
	// load see the file as CHANGED and take the merge path at all.
	if err := kdb.SetZoneFileState("example.", 8, "digest-of-the-previous-file"); err != nil {
		t.Fatalf("SetZoneFileState: %v", err)
	}
	zd.Zonefile = "" // nowhere to write the artefact -> the merge refuses

	replayZoneDeltasOnLoad(zd)

	id, have, err := kdb.GetZoneFileState("example.")
	if err != nil || !have {
		t.Fatalf("GetZoneFileState: %v (have=%v)", err, have)
	}
	if id.Digest != "digest-of-the-previous-file" || id.Serial != 8 {
		t.Fatalf("a failed merge overwrote the recorded identity (now serial %d digest %q);"+
			" the next load will call this file unchanged and never retry the merge",
			id.Serial, id.Digest)
	}
}

// The other direction, so the fix cannot be "never record": a merge that
// succeeds MUST re-point the identity at the file it just merged, or every
// later load merges the same file again.
func TestSuccessfulMergeRecordsTheNewIdentity(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := failingMergeZone(t, kdb)

	if err := kdb.SetZoneFileState("example.", 8, "digest-of-the-previous-file"); err != nil {
		t.Fatalf("SetZoneFileState: %v", err)
	}
	// Zonefile is left in place this time, so the artefact writes and the
	// merge completes.

	replayZoneDeltasOnLoad(zd)

	id, have, err := kdb.GetZoneFileState("example.")
	if err != nil || !have {
		t.Fatalf("GetZoneFileState: %v (have=%v)", err, have)
	}
	if id.Digest != "digest-of-the-replacement" || id.Serial != 9 {
		t.Fatalf("a successful merge did not record the merged file's identity"+
			" (serial %d digest %q); the next load would merge it all over again",
			id.Serial, id.Digest)
	}
}
