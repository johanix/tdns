/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	_ "github.com/mattn/go-sqlite3"
)

var DefaultTables = map[string]string{

	"ChildDnskeys": `CREATE TABLE IF NOT EXISTS 'ChildDnskeys' (
id		  INTEGER PRIMARY KEY,
parent	  TEXT,
child	  TEXT,
keyid	  INTEGER,
trusted	  INTEGER,
keyrr	  TEXT,
comment	  TEXT,
UNIQUE (parent, child, keyid)
)`,

	"ChildDelegationData": `CREATE TABLE IF NOT EXISTS 'ChildDelegationData' (
id		  INTEGER PRIMARY KEY,
parent	  TEXT,
child	  TEXT,
owner	  TEXT,
rrtype	  TEXT,
rr		  TEXT,
UNIQUE (owner,rr)
)`,

	// The Sig0TrustStore contains public SIG(0) keys that we use to validate
	// signed DNS Updates received (from child zones)
	"Sig0TrustStore": `CREATE TABLE IF NOT EXISTS 'Sig0TrustStore' (
id		  		  INTEGER PRIMARY KEY,
zonename	  	  TEXT,
keyid		      INTEGER,
validated	      INTEGER DEFAULT 0,
trusted		      INTEGER DEFAULT 0,
autokeyboot	      INTEGER DEFAULT 0,
dnssecvalidated	  INTEGER DEFAULT 0,
source		      TEXT,
keyrr		      TEXT,
comment		      TEXT,
UNIQUE (zonename, keyid)
)`,

	// The Sig0KeyStore should contain both the private and public SIG(0) keys for
	// each zone that we're managing parent sync for.
	"Sig0KeyStore": `CREATE TABLE IF NOT EXISTS 'Sig0KeyStore' (
id		  INTEGER PRIMARY KEY,
zonename	  TEXT,
state		  TEXT,
parentstate	  INTEGER,
keyid		  INTEGER,
algorithm	  TEXT,
creator	  	  TEXT,
privatekey	  TEXT,
keyrr		  TEXT,
comment		  TEXT,
UNIQUE (zonename, keyid)
)`,

	// The DnssecKeyStore should contain both the private and public DNSSEC keys for
	// each zone that we're managing signing for.
	// State is the normal series of key states for DNSSEC keys (created, published, active, retired, removed), but with
	// one added pissible state: "foreign". Foreign keys are keys that we've received from another signer and are only
	// kept in the DNSKEY RRset but never used for signing and never rolled. Foreign keys obviously do not have the private key here.
	"DnssecKeyStore": `CREATE TABLE IF NOT EXISTS 'DnssecKeyStore' (
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
UNIQUE (zonename, keyid)
)`,
}

// Note that there is no DNSSEC TrustStore, because whatever DNSSEC keys we have
// looked up and validated are only cached in memory and not in the database as this data will expire.
