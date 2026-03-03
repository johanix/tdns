package tdns

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
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

	lgSigner.Info("KeyBootstrapper starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				lgSigner.Info("KeyBootstrapper received context done signal")
				return
			// XXX: stopchan is being deprecated
			//			case <-stopchan:
			//				log.Println("KeyBootstrapper: Received stop signal")
			//				return
			case utr = <-keybootstrapperq:

				lgSigner.Debug("KeyBootstrapper received request", "cmd", utr.Cmd, "keyname", utr.KeyName, "zone", utr.ZoneName, "keyid", utr.Keyid, "has_response_chan", utr.ResponseChan != nil)

				switch utr.Cmd {
				case kbCmdPing:
					lgSigner.Debug("KeyBootstrapper PING received, PONG!")
				case kbCmdInfo:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					lgSigner.Debug("KeyBootstrapper INFO received", "keyname", utr.KeyName, "keyid", utr.Keyid)

					if utr.ResponseChan != nil {
						if info, exists := verifications[mapKey]; exists {
							lgSigner.Debug("KeyBootstrapper INFO found info for key", "failed_attempts", info.FailedAttempts, "attempts_left", info.AttemptsLeft)
							utr.ResponseChan <- info
						} else {
							lgSigner.Debug("KeyBootstrapper INFO no info found for key")
							utr.ResponseChan <- nil
						}
					}
				case kbCmdBootstrap: //Start the verification process
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					lgSigner.Info("received verification request", "zone", utr.ZoneName)

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
					lgSigner.Info("received verification result", "keyname", utr.KeyName, "keyid", utr.Keyid)
					if info, exists := verifications[mapKey]; exists {
						lgSigner.Debug("verification info", "keyname", utr.KeyName, "info", info)
						info.AttemptsLeft--
						retryInterval := viper.GetInt("verifyengine.retry_interval")
						if retryInterval == 0 {
							retryInterval = 60
						}
						info.NextCheckTime = time.Now().Add(time.Duration(retryInterval) * time.Second)
						if info.AttemptsLeft <= 0 {
							lgSigner.Info("verification completed", "keyname", utr.KeyName, "verified", utr.Verified)
							delete(verifications, mapKey)
							utr.Verified = true
							// Uppdatera motsvarande nyckel i TrustStore och sätt trusted till true
							tx, err := kdb.Begin("VerifyTrustEngine")
							if err != nil {
								lgSigner.Error("failed to start transaction", "err", err)
							} else {
								tppost := TruststorePost{
									SubCommand: "trust",
									Keyname:    info.KeyName,
									Keyid:      int(info.Keyid),
								}
								_, err := kdb.Sig0TrustMgmt(tx, tppost)
								if err != nil {
									lgSigner.Error("failed to update TrustStore", "err", err)
									tx.Rollback()
								} else {
									err = tx.Commit()
									if err != nil {
										lgSigner.Error("failed to commit transaction", "err", err)
									} else {
										lgSigner.Info("TrustStore updated", "keyname", utr.KeyName, "verified", utr.Verified)
									}
								}
							}
							lgSigner.Info("verification for key completed", "keyname", utr.KeyName, "verified", utr.Verified)
						} else {
							lgSigner.Debug("scheduling next check", "keyname", utr.KeyName, "attempts_left", info.AttemptsLeft)
						}
					}
				case kbCmdRestart:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					if info, exists := verifications[mapKey]; exists {

						lgSigner.Info("verification failed, restarting", "keyname", utr.KeyName)

						attempts := viper.GetInt("verifyengine.attempts")
						if attempts == 0 {
							attempts = 3 // Standardvärde om det inte är definierat
						}

						info.FailedAttempts++
						info.AttemptsLeft = attempts
						info.NextCheckTime = time.Now().Add(time.Duration(info.FailedAttempts) * time.Minute)

					}
				default:
					lgSigner.Warn("KeyBootstrapper unknown command, ignoring", "cmd", utr.Cmd)
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
					lgSigner.Debug("updating key state", "keyname", keyname, "keyid", keyid)

					go func() {
						err := kdb.UpdateKeyState(ctx, keyname, uint16(keyid), keybootstrapperq, dns.StringToAlgorithm[v.Algorithm])
						if err != nil {
							lgSigner.Error("failed to update key state", "keyname", keyname, "keyid", keyid, "err", err)
						}
					}()
				}

				// Uppdatera keystate för alla aktiva nycklar
				sak, err := kdb.GetSig0Keys(Globals.Zonename, Sig0StateActive)
				if err != nil {
					lgSigner.Error("failed to get active SIG(0) keys", "err", err)
					continue
				}

				for _, key := range sak.Keys {
					go func() {
						err := kdb.UpdateKeyState(ctx, key.KeyRR.Header().Name, uint16(key.KeyRR.KeyTag()), keybootstrapperq, key.Algorithm)
						if err != nil {
							lgSigner.Error("failed to update key state", "keyname", key.KeyRR.Header().Name, "keyid", key.KeyRR.KeyTag(), "err", err)
						}
					}()
				}
			}
		}
	}()
	wg.Wait()

	lgSigner.Info("KeyBootstrapper terminating")
	return nil
}

func VerifyKey(KeyName string, key string, keyid uint16, zd *ZoneData, updatetrustq chan<- KeyBootstrapperRequest) {
	lgSigner.Info("verifying key", "keyname", KeyName)

	nameservers, err := GetNameservers(KeyName, zd)
	if err != nil {
		lgSigner.Error("failed to get nameservers", "keyname", KeyName, "err", err)
		updatetrustq <- KeyBootstrapperRequest{Cmd: kbCmdRestart, KeyName: KeyName, Keyid: keyid}
		return
	}

	lgSigner.Debug("verifying key against nameservers", "keyname", KeyName, "nameservers", nameservers)

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
			lgSigner.Error("failed to query nameserver", "ns", ns, "keyname", KeyName, "err", err)
			allVerified = false
			continue
		}

		nsVerified := false
		for _, ans := range r.Answer {
			if keyRR, ok := ans.(*dns.KEY); ok {
				if keyRR.String() == key {
					nsVerified = true
					lgSigner.Debug("key verified on nameserver", "keyname", KeyName, "ns", ns)
					break
				}
			}
		}

		if !nsVerified {
			lgSigner.Warn("key not verified on nameserver", "keyname", KeyName, "ns", ns)
			allVerified = false
		}
	}

	lgSigner.Info("key verification completed", "keyname", KeyName, "verified", allVerified)

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
		lgSigner.Error("failed to start transaction", "err", err)
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
		lgSigner.Error("failed to update parent state", "err", err)
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		lgSigner.Error("failed to commit transaction", "err", err)
		return err
	}

	lgSigner.Info("parent state updated", "msg", resp.Msg)

	// If the key is unknown, bootstrap it with parent
	if keystate.KeyState == edns0.KeyStateUnknown {

		zd, ok := FindZone(KeyName)
		if !ok {
			lgSigner.Error("failed to get zone data", "keyname", KeyName, "err", err)
			return fmt.Errorf("could not get zone data for %s: %v", KeyName, err)
		}

		if zd == nil {
			lgSigner.Error("zone data not found", "keyname", KeyName)
			return fmt.Errorf("zone data not found for %s", KeyName)
		}

		_, _, err = zd.BootstrapSig0KeyWithParent(ctx, algorithm)
		if err != nil {
			lgSigner.Error("failed to bootstrap key", "keyname", KeyName, "err", err)
			return fmt.Errorf("could not bootstrap key for %s: %v", KeyName, err)
		}
	}

	return nil
}
