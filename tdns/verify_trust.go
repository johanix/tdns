package tdns

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (kdb *KeyDB) VerifyTrustEngine(stopchan chan struct{}) error {
	updatetrustq := kdb.UpdateTrustQ
	var utr UpdateTrustRequest

	verifications := make(map[string]*VerificationInfo)

	log.Printf("VerifyTrustEngine: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopchan:
				log.Println("VerifyTrustEngine: Received stop signal")
				return
			case utr = <-updatetrustq:
				switch utr.Cmd {
				case "PING":
					log.Printf("VerifyTrustEngine: PING received. PONG!")
				case "VERIFY": //Start the verification process
					log.Printf("VerifyTrustEngine: Received verification request for domain %s", utr.ZoneName)

					// Hämta antalet försök från konfigurationen
					attempts := viper.GetInt("verifyengine.attempts")
					if attempts == 0 {
						attempts = 3 // Standardvärde om det inte är definierat
					}

					verifications[utr.KeyName] = &VerificationInfo{
						Key:            utr.Key,
						ZoneName:       utr.ZoneName,
						AttemptsLeft:   attempts,
						NextCheckTime:  time.Now(),
						ZoneData:       utr.ZoneData,
						KeyName:        utr.KeyName,
						Keyid:          utr.Keyid,
						FailedAttempts: 0,
					}
					go kdb.VerifyKey(utr.KeyName, utr.Key, utr.ZoneData, updatetrustq)
				case "VERIFIED":
					log.Printf("VerifyTrustEngine: Received verification result for domain %s", utr.KeyName)
					if info, exists := verifications[utr.KeyName]; exists {
						log.Printf("VerifyTrustEngine: Verification info for domain %s: %v", utr.KeyName, info)
						info.AttemptsLeft--
						retryInterval := viper.GetInt("verifyengine.retry_interval")
						if retryInterval == 0 {
							retryInterval = 60
						}
						info.NextCheckTime = time.Now().Add(time.Duration(retryInterval) * time.Second)
						if info.AttemptsLeft <= 0 {
							log.Printf("VerifyTrustEngine: Verification for %s completed. Verified: %v", utr.KeyName, utr.Verified)
							delete(verifications, utr.KeyName)
							utr.Verified = true
							// Uppdatera motsvarande nyckel i TrustStore och sätt trusted till true
							tx, err := kdb.Begin("VerifyTrustEngine")
							if err != nil {
								log.Printf("Error starting transaction: %v", err)
							} else {
								tppost := TruststorePost{
									SubCommand: "trust",
									Keyname:    info.KeyName,
									Keyid:      info.Keyid,
								}
								_, err := kdb.Sig0TrustMgmt(tx, tppost)
								if err != nil {
									log.Printf("Error updating TrustStore: %v", err)
									tx.Rollback()
								} else {
									err = tx.Commit()
									if err != nil {
										log.Printf("Error committing transaction: %v", err)
									} else {
										log.Printf("TrustStore updated for %s. Trusted: %v", utr.KeyName, utr.Verified)
									}
								}
							}
							log.Printf("Verification for %s completed. Verified: %v", utr.KeyName, utr.Verified)
						} else {
							log.Printf("Scheduling next check for %s. Attempts left: %d", utr.KeyName, info.AttemptsLeft)
						}
					}
				case "RESTART":
					if info, exists := verifications[utr.KeyName]; exists {

						log.Printf("Verification failed for  %s, restarting process", utr.KeyName)

						attempts := viper.GetInt("verifyengine.attempts")
						if attempts == 0 {
							attempts = 3 // Standardvärde om det inte är definierat
						}

						info.FailedAttempts++
						info.AttemptsLeft = attempts
						info.NextCheckTime = time.Now().Add(time.Duration(info.FailedAttempts) * time.Minute)

						/*
							// Ta bort nyckeln från TrustStore
							tx, err := kdb.Begin("VerifyTrustEngine")
							if err != nil {
								log.Printf("Error starting transaction: %v", err)
							} else {
								tppost := TruststorePost{
									SubCommand: "delete",
									Keyname:    info.KeyName,
									Keyid:      info.Keyid,
								}
								_, err := kdb.Sig0TrustMgmt(tx, tppost)
								if err != nil {
									log.Printf("Error removing key from TrustStore: %v", err)
									tx.Rollback()
								} else {
									err = tx.Commit()
									if err != nil {
										log.Printf("Error committing transaction: %v", err)
									} else {
										delete(verifications, utr.KeyName)
										log.Printf("Key for %s removed from TrustStore", utr.KeyName)
									}
								}
							}*/

					}
				default:
					log.Printf("VerifyTrustEngine: Unknown command: '%s'. Ignoring.", utr.Cmd)
				}
			case <-ticker.C:
				now := time.Now()
				for _, info := range verifications {
					if now.After(info.NextCheckTime) {
						go kdb.VerifyKey(info.KeyName, info.Key, info.ZoneData, updatetrustq)
					}
				}
			}
		}
	}()
	wg.Wait()

	log.Println("VerifyTrustEngine: terminating")
	return nil
}

func (kdb *KeyDB) VerifyKey(KeyName string, key string, zd *ZoneData, updatetrustq chan<- UpdateTrustRequest) {
	log.Printf("Verifying key for domain %s", KeyName)

	nameservers, err := getNameservers(KeyName, zd)
	if err != nil {
		log.Printf("Error getting nameservers for %s: %v", KeyName, err)
		updatetrustq <- UpdateTrustRequest{Cmd: "DELETE", KeyName: KeyName}
		return
	}

	log.Printf("BERRA: Verifying key for domain %s. Nameservers: %v", KeyName, nameservers)

	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = 5 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(KeyName), dns.TypeKEY)
	m.RecursionDesired = false

	allVerified := true
	for _, ns := range nameservers {
		r, _, err := c.Exchange(m, ns+":53")
		if err != nil {
			log.Printf("Error querying nameserver %s for %s: %v", ns, KeyName, err)
			allVerified = false
			continue
		}

		nsVerified := false
		for _, ans := range r.Answer {
			if keyRR, ok := ans.(*dns.KEY); ok {
				if keyRR.String() == key {
					nsVerified = true
					log.Printf("Key verified for domain %s on nameserver %s", KeyName, ns)
					break
				}
			}
		}

		if !nsVerified {
			log.Printf("Key not verified for domain %s on nameserver %s", KeyName, ns)
			allVerified = false
		}
	}

	log.Printf("BERRA: Verification for %s completed. Verified: %v", KeyName, allVerified)

	if allVerified {
		updatetrustq <- UpdateTrustRequest{Cmd: "VERIFIED", KeyName: KeyName}
	} else {
		updatetrustq <- UpdateTrustRequest{Cmd: "DELETE", KeyName: KeyName}
	}
}

func getNameservers(KeyName string, zd *ZoneData) ([]string, error) {

	cdd := zd.FindDelegation(KeyName, true)
	if cdd == nil || cdd.NS_rrset == nil {
		return nil, fmt.Errorf("no delegation found for domain %s", KeyName)
	}

	var nameservers []string
	for _, rr := range cdd.NS_rrset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nameservers = append(nameservers, ns.Ns)
		}
	}

	if len(nameservers) == 0 {
		return nil, fmt.Errorf("no nameservers found for domain %s", KeyName)
	}

	return nameservers, nil
}
