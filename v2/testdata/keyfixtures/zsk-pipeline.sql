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
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (1, 'zsk.example.', 'active', 35380, 257, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDQucs1ydPTkVYTIUqIXQORtHVT+lzT2Y1z4wC9L6rnp
-----END PRIVATE KEY-----
', 'zsk.example.	3600	IN	DNSKEY	257 3 15 9jburYsup2L7pJAQ4TdDjuk5CNDFPaSOYeKL7917lw4=', NULL, '', '2026-09-14T14:19:55Z', '', NULL);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (2, 'zsk.example.', 'retired', 62903, 256, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIINOUVl9JUYHdvR7zZVK254zamqG90VeT0ZnBlubmx8Z
-----END PRIVATE KEY-----
', 'zsk.example.	3600	IN	DNSKEY	256 3 15 WyfoETQKwR9DOMiGMTtCzpYd2GwYqlJY5wGuba4EHHw=', NULL, '', '2026-09-14T14:19:55Z', '2026-09-14T14:19:55Z', NULL);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (3, 'zsk.example.', 'active', 53131, 256, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJUMFQBzpE1ltfr6V09GcR9K5swW+tKBIKVmUMpD9STW
-----END PRIVATE KEY-----
', 'zsk.example.	3600	IN	DNSKEY	256 3 15 ksAS3EMDqZNFJ+lEZQ0LZb4RspVfJ5+3DfaiM4xX7mI=', NULL, '2026-09-14T14:19:55Z', '2026-09-14T14:19:55Z', '', 0);
INSERT INTO DnssecKeyStore (id, zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, active_at, retired_at, active_seq) VALUES (4, 'zsk.example.', 'standby', 545, 256, 'ED25519', 'fixture', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAnKT0N7Zw5UJLgC50qJjfLvdbqTnWfbiBkLaOzgDJ0O
-----END PRIVATE KEY-----
', 'zsk.example.	3600	IN	DNSKEY	256 3 15 4PJa2MBdX4uzq6aTxGX+Z9MAYiyjl6ypdBP0TIu8C8U=', NULL, '2026-09-14T14:19:55Z', '', '', NULL);
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
