package tdns

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v0.x/core"
	"github.com/johanix/tdns/v0.x/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const (
	kbCmdBootstrap        = "BOOTSTRAP_KEY"
	kbCmdVerificationStep = "VERIFICATION_STEP"
	kbCmdRestart          = "RESTART_VERIFICATION"
	kbCmdDelete           = "DELETE_KEY"
	kbCmdPing             = "PING"
	kbCmdInfo             = "INFO"
	kbCmdUpdateKeyState   = "UPDATE_KEYSTATE"
)

func (kdb *KeyDB) KeyBootstrapper(ctx context.Context) error {
	keybootstrapperq := kdb.KeyBootstrapperQ
	var utr KeyBootstrapperRequest

	verifications := make(map[string]*VerificationInfo)

	log.Printf("KeyBootstrapper: starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Println("KeyBootstrapper: Received context done signal")
				return
			// XXX: stopchan is being deprecated
			//			case <-stopchan:
			//				log.Println("KeyBootstrapper: Received stop signal")
			//				return
			case utr = <-keybootstrapperq:

				fmt.Printf("KeyBootstrapper: Received request: %v\n", utr)
				fmt.Printf("KeyBootstrapper: Request details:\n")
				fmt.Printf("KeyBootstrapper: Cmd: %s\n", utr.Cmd)
				fmt.Printf("KeyBootstrapper: KeyName: %s\n", utr.KeyName)
				fmt.Printf("KeyBootstrapper: ZoneName: %s\n", utr.ZoneName)
				fmt.Printf("KeyBootstrapper: Keyid: %d\n", utr.Keyid)
				fmt.Printf("KeyBootstrapper: Key: %v\n", utr.Key)
				fmt.Printf("KeyBootstrapper: ZoneData: %v\n", utr.ZoneData)
				if utr.ResponseChan != nil {
					fmt.Printf("KeyBootstrapper: ResponseChan: [exists]\n")
				} else {
					fmt.Printf("KeyBootstrapper: ResponseChan: [missing]\n")
				}

				switch utr.Cmd {
				case kbCmdPing:
					log.Printf("KeyBootstrapper: PING received. PONG!")
				case kbCmdInfo:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					fmt.Printf("KeyBootstrapper: INFO received. KeyName: %s, Keyid: %d\n", utr.KeyName, utr.Keyid)

					if utr.ResponseChan != nil {
						if info, exists := verifications[mapKey]; exists {
							fmt.Printf("KeyBootstrapper: INFO found info for key. Sending response.\n")
							fmt.Printf("KeyBootstrapper: INFO info: %d %d\n", info.FailedAttempts, info.AttemptsLeft)
							utr.ResponseChan <- info
						} else {
							fmt.Printf("KeyBootstrapper: INFO no info found for key. Sending nil response.\n")
							utr.ResponseChan <- nil
						}
					}
				case kbCmdBootstrap: //Start the verification process
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					log.Printf("KeyBootstrapper: Received verification request for domain %s", utr.ZoneName)

					// Hämta antalet försök från konfigurationen
					attempts := viper.GetInt("verifyengine.attempts")
					if attempts == 0 {
						attempts = 3 // Standardvärde om det inte är definierat
					}

					verifications[mapKey] = &VerificationInfo{
						Key:            utr.Key,
						ZoneName:       utr.ZoneName,
						AttemptsLeft:   attempts,
						NextCheckTime:  time.Now(),
						ZoneData:       utr.ZoneData,
						KeyName:        utr.KeyName,
						Keyid:          utr.Keyid,
						FailedAttempts: 0,
					}
					go VerifyKey(utr.KeyName, utr.Key, utr.Keyid, utr.ZoneData, keybootstrapperq)
				case kbCmdVerificationStep:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					log.Printf("KeyBootstrapper: Received verification result for domain %s, keyid %d", utr.KeyName, utr.Keyid)
					if info, exists := verifications[mapKey]; exists {
						log.Printf("KeyBootstrapper: Verification info for domain %s: %v", utr.KeyName, info)
						info.AttemptsLeft--
						retryInterval := viper.GetInt("verifyengine.retry_interval")
						if retryInterval == 0 {
							retryInterval = 60
						}
						info.NextCheckTime = time.Now().Add(time.Duration(retryInterval) * time.Second)
						if info.AttemptsLeft <= 0 {
							log.Printf("KeyBootstrapper: Verification for %s completed. Verified: %v", utr.KeyName, utr.Verified)
							delete(verifications, mapKey)
							utr.Verified = true
							// Uppdatera motsvarande nyckel i TrustStore och sätt trusted till true
							tx, err := kdb.Begin("VerifyTrustEngine")
							if err != nil {
								log.Printf("Error starting transaction: %v", err)
							} else {
								tppost := TruststorePost{
									SubCommand: "trust",
									Keyname:    info.KeyName,
									Keyid:      int(info.Keyid),
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
				case kbCmdRestart:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					if info, exists := verifications[mapKey]; exists {

						log.Printf("Verification failed for  %s, restarting process", utr.KeyName)

						attempts := viper.GetInt("verifyengine.attempts")
						if attempts == 0 {
							attempts = 3 // Standardvärde om det inte är definierat
						}

						info.FailedAttempts++
						info.AttemptsLeft = attempts
						info.NextCheckTime = time.Now().Add(time.Duration(info.FailedAttempts) * time.Minute)

					}
				default:
					log.Printf("KeyBootstrapper: Unknown command: '%s'. Ignoring.", utr.Cmd)
				}
			case <-ticker.C:
				now := time.Now()
				for _, info := range verifications {
					if now.After(info.NextCheckTime) {
						go VerifyKey(info.KeyName, info.Key, info.Keyid, info.ZoneData, keybootstrapperq)
					}
				}

				kp := KeystorePost{
					Command:    "sig0-mgmt",
					SubCommand: "list",
				}
				tx, _ := kdb.Begin("KeyBootstrapper")
				resp, _ := kdb.Sig0KeyMgmt(tx, kp)
				tx.Commit()

				for k, v := range resp.Sig0keys {
					tmp := strings.Split(k, "::")
					keyname := tmp[0]
					keyid, _ := strconv.ParseUint(tmp[1], 10, 16)
					fmt.Printf("KeyBootstrapper: Updating key state for %s, keyid %d\n", keyname, keyid)

					go func() {
						err := kdb.UpdateKeyState(ctx, keyname, uint16(keyid), keybootstrapperq, dns.StringToAlgorithm[v.Algorithm])
						if err != nil {
							log.Printf("KeyBootstrapper:Error updating key state for %s, keyid %d: %v", keyname, keyid, err)
						}
					}()
				}

				// Uppdatera keystate för alla aktiva nycklar
				sak, err := kdb.GetSig0Keys(Globals.Zonename, Sig0StateActive)
				if err != nil {
					log.Printf("Error getting active keys: %v", err)
					continue
				}

				for _, key := range sak.Keys {
					go func() {
						err := kdb.UpdateKeyState(ctx, key.KeyRR.Header().Name, uint16(key.KeyRR.KeyTag()), keybootstrapperq, key.Algorithm)
						if err != nil {
							log.Printf("KeyBootstrapper: Error updating key state for %s, keyid %d: %v", key.KeyRR.Header().Name, key.KeyRR.KeyTag(), err)
						}
					}()
				}
			}
		}
	}()
	wg.Wait()

	log.Println("KeyBootstrapper: terminating")
	return nil
}

func VerifyKey(KeyName string, key string, keyid uint16, zd *ZoneData, updatetrustq chan<- KeyBootstrapperRequest) {
	log.Printf("Verifying key for domain %s", KeyName)

	nameservers, err := GetNameservers(KeyName, zd)
	if err != nil {
		log.Printf("Error getting nameservers for %s: %v", KeyName, err)
		updatetrustq <- KeyBootstrapperRequest{Cmd: kbCmdRestart, KeyName: KeyName, Keyid: keyid}
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
		updatetrustq <- KeyBootstrapperRequest{Cmd: kbCmdVerificationStep, KeyName: KeyName, Keyid: keyid}
	} else {
		updatetrustq <- KeyBootstrapperRequest{Cmd: kbCmdRestart, KeyName: KeyName, Keyid: keyid}
	}
}

func GetNameservers(KeyName string, zd *ZoneData) ([]string, error) {

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

func (kdb *KeyDB) UpdateKeyState(ctx context.Context, KeyName string, keyid uint16, kkeybootstrapperq chan<- KeyBootstrapperRequest, algorithm uint8) error {
	dsync_target, err := Globals.ImrEngine.LookupDSYNCTarget(ctx, KeyName, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return fmt.Errorf("could not find DSYNC target: %v", err)
	}

	// Create DNS message with EDNS(0) KeyState option
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(KeyName), dns.TypeANY)

	// Add EDNS(0) option with KeyState
	edns0.AttachKeyStateToResponse(m, &edns0.KeyStateOption{
		KeyID:     keyid,
		KeyState:  edns0.KeyStateInquiryKey,
		ExtraText: "",
	})

	// Get active key for signing
	sak, err := kdb.GetSig0Keys(KeyName, Sig0StateActive)
	if err != nil {
		return fmt.Errorf("could not get active SIG(0) key: %v", err)
	}

	if len(sak.Keys) == 0 {
		return fmt.Errorf("no active SIG(0) key available for %s", KeyName)
	}

	// Sign the message
	signedMsg, err := SignMsg(*m, KeyName, sak)
	if err != nil {
		return fmt.Errorf("could not sign the message: %v", err)
	}

	// Send the signed message
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	if len(dsync_target.Addresses) == 0 {
		return fmt.Errorf("DSYNC target has no addresses for %s", KeyName)
	}
	r, _, err := c.Exchange(signedMsg, dsync_target.Addresses[0])
	if err != nil {
		return fmt.Errorf("could not send DNS request: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS request failed with code: %v", dns.RcodeToString[r.Rcode])
	}

	// Extract KeyState option from response using the new pattern
	opt := r.IsEdns0()
	if opt == nil {
		return fmt.Errorf("could not extract KeyState from response: no EDNS(0) OPT RR in response")
	}
	keystate, found := edns0.ExtractKeyStateOption(opt)
	if !found {
		return fmt.Errorf("could not extract KeyState from response: KeyState option missing in response")
	}

	//mapKey := fmt.Sprintf("%s::%d", KeyName, keyid)
	//log.Printf("KeyBootstrapper: Updating parent state for key %s to %d", mapKey, utr.ParentState)

	tx, err := kdb.Begin("UpdateKeyState")
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		return err
	}

	kpparent := KeystorePost{
		Command:     "sig0-mgmt",
		SubCommand:  "setparentstate",
		Keyname:     KeyName,
		Keyid:       keyid,
		ParentState: keystate.KeyState,
	}

	resp, err := kdb.Sig0KeyMgmt(tx, kpparent)
	if err != nil {
		log.Printf("Error updating parent state: %v", err)
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("Error committing transaction: %v", err)
		return err
	}

	log.Printf("KeyBootstrapper: Parent state updated: %s", resp.Msg)

	// If the key is unknown, bootstrap it with parent
	if keystate.KeyState == edns0.KeyStateUnknown {

		zd, ok := FindZone(KeyName)
		if !ok {
			log.Printf("Keybootstrapper: Error getting zone data for %s: %v", KeyName, err)
			return fmt.Errorf("could not get zone data for %s: %v", KeyName, err)
		}

		if zd == nil {
			log.Printf("Keybootstrapper: Zone data not found for %s", KeyName)
			return fmt.Errorf("zone data not found for %s", KeyName)
		}

		_, _, err = zd.BootstrapSig0KeyWithParent(ctx, algorithm)
		if err != nil {
			log.Printf("Keybootstrapper: Error bootstrapping key for %s: %v", KeyName, err)
			return fmt.Errorf("could not bootstrap key for %s: %v", KeyName, err)
		}
	}

	return nil
}
