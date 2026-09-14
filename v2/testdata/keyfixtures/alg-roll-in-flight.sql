-- keystore fixture written 2026-09-14 by TestWriteKeyFixtures; do not edit
CREATE TABLE 'DnssecKeyStore' (
id		  INTEGER PRIMARY KEY,
zonename	  TEXT,
state		  TEXT,
keyid		  INTEGER,
flags		  INTEGER,
algorithm	  TEXT,
creator	  	  TEXT,
privatekey	  TEXT,
keyrr		  TEXT,
comment		  TEXT,
published_at              TEXT DEFAULT '',
active_at                 TEXT DEFAULT '',
retired_at                TEXT DEFAULT '',
active_seq                INTEGER,
	UNIQUE (zonename, keyid)
);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (1, 'algroll.example.', 'active', 43853, 257, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINEVFbS8DeacJIVnKY87Umm0kjn/yOktaX8ozNwJ4cJD
-----END PRIVATE KEY-----
', 'algroll.example.	3600	IN	DNSKEY	257 3 15 S4Vzxy71nIIFRDUjq7MOSjdm5UZh1volHzLEKaSFJ4k=', NULL, '', '2026-09-14T14:19:55Z', '', NULL);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (2, 'algroll.example.', 'active', 63179, 256, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKmA6lTcOwslikX/DUvtNwbZpThKbmxrIxhpY0UL+NOb
-----END PRIVATE KEY-----
', 'algroll.example.	3600	IN	DNSKEY	256 3 15 c1zIoECLadFqaRxzjET4n7r+02GFJSQUKTY6YWzN+KI=', NULL, '', '2026-09-14T14:19:55Z', '', NULL);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (3, 'algroll.example.', 'active', 41981, 257, 'ECDSAP256SHA256', 'fixture', '-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2b4GkXjv+5/CSD8y
Mn3Gh0dTl6g4rpPssQ0IsNlDm0qhRANCAAQ5HxiXrVdhT2FTp6/klpDcM0oYPmz2
bblqpqNxggSJD5whcPqeHQZrEO4/3BTq/YFnSXgzQEewfNPJjH1rQNET
-----END PRIVATE KEY-----
', 'algroll.example.	3600	IN	DNSKEY	257 3 13 OR8Yl61XYU9hU6ev5JaQ3DNKGD5s9m25aqajcYIEiQ+cIXD6nh0GaxDuP9wU6v2BZ0l4M0BHsHzTyYx9a0DREw==', NULL, '', '2026-09-14T14:19:55Z', '', NULL);
CREATE TABLE 'RolloverZoneState' (
		zone                           TEXT NOT NULL PRIMARY KEY,
		last_ds_submitted_index_low    INTEGER,
		last_ds_submitted_index_high    INTEGER,
		last_ds_submitted_at           TEXT,
		last_ds_confirmed_index_low    INTEGER,
		last_ds_confirmed_index_high    INTEGER,
		last_ds_confirmed_at           TEXT,
		rollover_phase                 TEXT NOT NULL DEFAULT 'idle',
		rollover_phase_at              TEXT,
		rollover_in_progress           INTEGER NOT NULL DEFAULT 0,
		next_rollover_index            INTEGER NOT NULL DEFAULT 0,
		manual_rollover_requested_at   TEXT,
		manual_rollover_earliest       TEXT,
		observe_started_at             TEXT,
		observe_next_poll_at           TEXT,
		observe_backoff_seconds        INTEGER,
		hardfail_count                 INTEGER NOT NULL DEFAULT 0,
		next_push_at                   TEXT,
		last_softfail_at               TEXT,
		last_softfail_category         TEXT,
		last_softfail_detail           TEXT,
		last_success_at                TEXT,
		last_attempt_started_at        TEXT,
		last_poll_at                   TEXT,
		last_attempt_scheme            TEXT,
		last_published_cds_index_low   INTEGER,
		last_published_cds_index_high  INTEGER,
		last_ds_observed_keyids        TEXT,
		last_ds_observed_at            TEXT,
		parent_advertises_update       INTEGER,
		parent_advertises_notify       INTEGER,
		alg_roll_from_alg              INTEGER,
		alg_roll_to_alg                INTEGER,
		alg_roll_started_at            TEXT,
		alg_roll_new_head_keyid        INTEGER,
		alg_roll_old_head_keyid        INTEGER,
		alg_roll_old_head_retire_at    TEXT
	);
INSERT INTO RolloverZoneState (zone, last_ds_submitted_index_low, last_ds_submitted_index_high, last_ds_submitted_at, last_ds_confirmed_index_low, last_ds_confirmed_index_high, last_ds_confirmed_at, rollover_phase, rollover_phase_at, rollover_in_progress, next_rollover_index, manual_rollover_requested_at, manual_rollover_earliest, observe_started_at, observe_next_poll_at, observe_backoff_seconds, hardfail_count, next_push_at, last_softfail_at, last_softfail_category, last_softfail_detail, last_success_at, last_attempt_started_at, last_poll_at, last_attempt_scheme, last_published_cds_index_low, last_published_cds_index_high, last_ds_observed_keyids, last_ds_observed_at, parent_advertises_update, parent_advertises_notify, alg_roll_from_alg, alg_roll_to_alg, alg_roll_started_at, alg_roll_new_head_keyid, alg_roll_old_head_keyid, alg_roll_old_head_retire_at) VALUES ('algroll.example.', NULL, NULL, NULL, NULL, NULL, NULL, 'idle', NULL, 1, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 15, 13, '2026-09-14T14:19:55Z', 41981, 43853, NULL);
CREATE TABLE 'RolloverKeyState' (
		zone                 TEXT NOT NULL,
		keyid                INTEGER NOT NULL,
		rollover_index       INTEGER NOT NULL,
		rollover_method      TEXT,
		rollover_state_at    TEXT,
		ds_submitted_at      TEXT,
		ds_observed_at       TEXT,
		published_at         TEXT,
		standby_at           TEXT,
		active_at            TEXT,
		active_seq           INTEGER,
		last_rollover_error  TEXT,
		PRIMARY KEY (zone, keyid)
	);
INSERT INTO RolloverKeyState (zone, keyid, rollover_index, rollover_method, rollover_state_at, ds_submitted_at, ds_observed_at, published_at, standby_at, active_at, active_seq, last_rollover_error) VALUES ('algroll.example.', 43853, 0, 'double-signature', '2026-09-14T14:19:55Z', NULL, NULL, NULL, NULL, '2026-09-14T14:19:55Z', 0, NULL);
INSERT INTO RolloverKeyState (zone, keyid, rollover_index, rollover_method, rollover_state_at, ds_submitted_at, ds_observed_at, published_at, standby_at, active_at, active_seq, last_rollover_error) VALUES ('algroll.example.', 41981, 1, 'double-signature', '2026-09-14T14:19:55Z', NULL, NULL, NULL, NULL, NULL, NULL, NULL);
