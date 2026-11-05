# Tombstones for child SIG(0) keys the child deleted

**Date:** 2026-11-05. Based on main `0cc79ba3`.
**Status:** implemented (branch `fix/sig0-truststore-tombstone`).

## 1. Problem

A parent keeps its children's SIG(0) public keys in `Sig0TrustStore`. A
child rolls its key with two UPDATEs: an ADD of the new key signed by the
old one, then a delete (class NONE) of the old key signed by the new one.
The delete removed the old key's row, and with it everything the parent
knew about that key.

The parent also accepts a key it does not know: a self-signed upload (the
plain one-KEY upload, or the DEL-ANY-KEY + ADD-KEY ceremony), or a key it
finds in the child's DNS while validating a signed UPDATE. It verifies the
key against the child's DNS and then trusts it.

So whoever still held the old private half could bring the old key back
while any copy of its KEY was still published: at the child's apex, in a
cache, on a lagging secondary, at a signal name. In a multi-provider zone
the key is rolled when a provider leaves, precisely because the leaver holds
the private half; the leaver could undo the roll. Nothing on the child side
can stop that, because the leaver needs nothing from the child to send its
own bootstrap. Only the parent can refuse.

## 2. What changed

When a child's trusted UPDATE deletes one of its keys, the parent writes a
tombstone for the key in the same transaction as the delete.

- **Table.** `Sig0TrustStoreTombstone`: child name (canonical), keyid,
  algorithm, public key, the KEY record, `deleted_at`, source. It is a new
  table, created at start-up like any other; there is no migration.
- **Match.** On the child, the algorithm and the public key bytes, not the
  key tag. A new key that shares a tag with a retired one is a different key
  and bootstraps as usual.
- **Refusal.** Every truststore add of a tombstoned key is refused, whatever
  its source: `child-update` (uploads, and a trusted UPDATE's ADD), `dns`
  (discovery), `file` (an operator's add) and `keystore`. The UPDATE
  approval refuses the upload first, with REFUSED and the new private EDE
  546, `EDESig0KeyRetired`, so the child is told why. A key found in DNS is
  not recorded, and no verification starts for it.
- **Unchanged.** The `Sig0TrustStore` row is still deleted, so no reader of
  that table can take a retired key for a trusted one. Only a child's
  trusted UPDATE writes a tombstone. An operator's `truststore sig0 delete`,
  the keystore's own delete and the bootstrap ceremony's deferred
  DEL-ANY-KEY cleanup remove the row as before. Keys in the
  `validator.sig0.trusted.file` config are the operator's own authority and
  are not checked.

## 3. Clearing a tombstone

An operator clears one deliberately, through the management API and the
CLI:

```
truststore sig0 tombstone list
truststore sig0 tombstone clear --child <child> --keyid <keyid>
```

The API's `/truststore` endpoint takes `child-sig0-mgmt` with the
subcommands `tombstone-list` and `tombstone-clear`. Clearing removes the
tombstone and nothing else; the key can then be added like any new key.

## 4. No expiry

Tombstones do not expire. The parent cannot know when the private half is
gone, or when the last copy of the KEY has left caches, secondaries and
signal names. A tombstone blocks only that one key, so keeping it costs a
child nothing: a new key is never affected.

## 5. Open points

- The bootstrap ceremony's deferred DEL-ANY-KEY also removes keys, once the
  new key is trusted. It leaves no tombstone here, since it is not a trusted
  UPDATE when it arrives. Whether it should is a separate decision.
- A trusted UPDATE that adds back a key the same child deleted is refused
  too. If a flow needs that, the operator clears the tombstone first.
- The KeyState inquiry reports a tombstoned key as unknown, as it reports
  any key that is not in `Sig0TrustStore`.
