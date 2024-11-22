/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"log"
	"time"

	"github.com/mattn/go-sqlite3"
)

func DbUpdater(conf *Config) {

	log.Printf("dbUpdater: Starting DB Update Service.")

	mdb := conf.Internal.MusicDB

	dbupdateC := make(chan DBUpdate, 5)
	mdb.UpdateC = dbupdateC

	const ZSMsql = `INSERT OR REPLACE INTO metadata (zone, key, time, value)
	      	        VALUES (?, ?, datetime('now'), ?)`
	const DSsql = "UPDATE zones SET fsmstatus='blocked' WHERE name=?"
	const IZNS = `INSERT OR IGNORE INTO zone_nses (zone, ns, signer) VALUES (?, ?, ?)`

	ticker := time.NewTicker(2 * time.Second)

	queue := []DBUpdate{}
	var update DBUpdate

	RunDBQueue := func() {
		for {
			if len(queue) == 0 {
				// log.Printf("RunDBQueue: DBQueue is empty")
				break
			}
			u := queue[0]
			t := u.Type

			tx, err := mdb.StartTransactionNG()
			if err != nil {
				log.Printf("RunDBQueue: Error from mdb.Begin(): %v", err)
				log.Printf("RunDBQueue: This may be a fatal error?", err)
			}

			switch t {
			case "STOPREASON":
				_, err := tx.Exec(ZSMsql, u.Zone, u.Key, u.Value)
				if err != nil {
					if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrLocked {
						// database is locked by other connection
						log.Printf("RunDBQueue: UPDATE db locked. will try again. queue: %d",
							len(queue))
						tx.Rollback()
						return // let's try again later
					} else {
						log.Printf("RunDBQueue: UPDATE Error from sqlupdate.Exec: %v",
							err)
						return
					}
				}
				_, err = tx.Exec(DSsql, u.Zone)
				if err != nil {
					if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrLocked {
						// database is locked by other connection
						log.Printf("RunDBQueue: UPDATE db locked. will try again. queue: %d",
							len(queue))
						tx.Rollback()
						return // let's try again later
					} else {
						log.Printf("RunDBQueue: UPDATE Error from sqlupdate.Exec: %v",
							err)
						return
					}
				}

			case "INSERT-ZONE-NS":
				for s, sl := range u.SignerNsNames {
					for _, ns := range sl {
						_, err := tx.Exec(IZNS, u.Zone, ns, s)
						if err != nil {
							if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrLocked {
								// database is locked by other connection
								log.Printf("RunDBQueue: INSERT-ZONE-NS db locked. will try again. queue: %d",
									len(queue))
								tx.Rollback()
								return // let's try again later
							} else {
								log.Printf("RunDBQueue: INSERT-ZONE-NS Error from tx.Exec(%s): %v",
									IZNS, err)
								return
							}
						} else {
							log.Printf("RunDBQueue: INSERT-ZONE-NS successful")
						}
					}
				}

			case "INSERT-ZONE-DNSKEY":
				for s, sl := range u.SignerNsNames {
					for _, ns := range sl {
						_, err := tx.Exec(IZNS, u.Zone, ns, s)
						if err != nil {
							if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrLocked {
								// database is locked by other connection
								log.Printf("RunDBQueue: INSERT-ZONE-NS db locked. will try again. queue: %d",
									len(queue))
								tx.Rollback()
								return // let's try again later
							} else {
								log.Printf("RunDBQueue: INSERT-ZONE-NS Error from tx.Exec(%s): %v",
									IZNS, err)
								return
							}
						} else {
							log.Printf("RunDBQueue: INSERT-ZONE-NS successful")
						}
					}
				}

			default:
				log.Printf("RunDBQueue: Unknown update type: '%s'. Ignoring.", t)
				// queue = queue[1:] // drop this item
			}

			err = tx.Commit()
			if err != nil {
				log.Printf("dbUpdater: RunQueue: Error from tx.Commit: %v", err)
			} else {
				log.Printf("dbUpdater: Update %s committed", t)
				queue = queue[1:] // only drop item after successful commit
			}
		}
	}

	for {
		select {
		case update = <-dbupdateC:
			queue = append(queue, update)
			RunDBQueue()

		case <-ticker.C:
			RunDBQueue()
		}
	}
}
