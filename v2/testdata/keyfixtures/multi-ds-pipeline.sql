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
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (1, 'multids.example.', 'active', 13947, 257, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDuRgIwm96qXy8Sx3s4PDKNviS7lfmH69bVKPGgVJEnt
-----END PRIVATE KEY-----
', 'multids.example.	3600	IN	DNSKEY	257 3 15 UW1k9CxTqmru2Xje7TPg129sSGVlyEV7Nwjm7dQYGmM=', NULL, '', '2026-09-14T14:19:55Z', '', NULL);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (2, 'multids.example.', 'active', 45301, 256, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIN4eJigQOJpi7d/Q479bu2RSOmjKgj/62jP6QAky4F7L
-----END PRIVATE KEY-----
', 'multids.example.	3600	IN	DNSKEY	256 3 15 cdRXUMI0XGu+6ICqNQDVfc6gGGvBf6WS+1+Z9s5uySw=', NULL, '', '2026-09-14T14:19:55Z', '', NULL);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (3, 'multids.example.', 'ds-published', 17723, 257, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILSD+WE7Hi+dBKJVCSbLFo/o9PYF7BfmOwhopAPw4I7i
-----END PRIVATE KEY-----
', 'multids.example.	3600	IN	DNSKEY	257 3 15 Xvnb+qODohP+UANk6rtJHezvRSQpKlMwiqc/NkV6zUo=', NULL, '', '', '', NULL);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (4, 'multids.example.', 'published', 52507, 257, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIHryGCJwOHe8w4lm5Im1OitKSTzzJpwUvNYhTPuV+y1
-----END PRIVATE KEY-----
', 'multids.example.	3600	IN	DNSKEY	257 3 15 W8Y8tF0sBkwAhTExiA5OFQYii1nbLBJXhCIL499j1tU=', NULL, '2026-09-14T14:19:55Z', '', '', NULL);
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
INSERT INTO RolloverZoneState (zone, last_ds_submitted_index_low, last_ds_submitted_index_high, last_ds_submitted_at, last_ds_confirmed_index_low, last_ds_confirmed_index_high, last_ds_confirmed_at, rollover_phase, rollover_phase_at, rollover_in_progress, next_rollover_index, manual_rollover_requested_at, manual_rollover_earliest, observe_started_at, observe_next_poll_at, observe_backoff_seconds, hardfail_count, next_push_at, last_softfail_at, last_softfail_category, last_softfail_detail, last_success_at, last_attempt_started_at, last_poll_at, last_attempt_scheme, last_published_cds_index_low, last_published_cds_index_high, last_ds_observed_keyids, last_ds_observed_at, parent_advertises_update, parent_advertises_notify, alg_roll_from_alg, alg_roll_to_alg, alg_roll_started_at, alg_roll_new_head_keyid, alg_roll_old_head_keyid, alg_roll_old_head_retire_at) VALUES ('multids.example.', NULL, NULL, NULL, NULL, NULL, NULL, 'idle', NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
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
INSERT INTO RolloverKeyState (zone, keyid, rollover_index, rollover_method, rollover_state_at, ds_submitted_at, ds_observed_at, published_at, standby_at, active_at, active_seq, last_rollover_error) VALUES ('multids.example.', 13947, 0, 'multi-ds', '2026-09-14T14:19:55Z', NULL, NULL, NULL, NULL, '2026-09-14T14:19:55Z', 0, NULL);
INSERT INTO RolloverKeyState (zone, keyid, rollover_index, rollover_method, rollover_state_at, ds_submitted_at, ds_observed_at, published_at, standby_at, active_at, active_seq, last_rollover_error) VALUES ('multids.example.', 17723, 1, 'multi-ds', '2026-09-14T14:19:55Z', NULL, NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO RolloverKeyState (zone, keyid, rollover_index, rollover_method, rollover_state_at, ds_submitted_at, ds_observed_at, published_at, standby_at, active_at, active_seq, last_rollover_error) VALUES ('multids.example.', 52507, 2, 'multi-ds', '2026-09-14T14:19:55Z', NULL, NULL, NULL, NULL, NULL, NULL, NULL);
