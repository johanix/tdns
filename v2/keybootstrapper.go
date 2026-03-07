package tdns

import (
	"context"
	"fmt"
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

	var verifications sync.Map
	// retryTimers tracks per-key timers so they can be cancelled on context done.
	var retryTimers sync.Map // map[string]*time.Timer

	// scheduleRetry sets a per-key timer that re-runs VerifyKey after the given delay.
	scheduleRetry := func(info *VerificationInfo, delay time.Duration) {
		mapKey := fmt.Sprintf("%s::%d", info.KeyName, info.Keyid)
		// Cancel any existing timer for this key.
		if old, ok := retryTimers.LoadAndDelete(mapKey); ok {
			old.(*time.Timer).Stop()
		}
		t := time.AfterFunc(delay, func() {
			retryTimers.Delete(mapKey)
			go VerifyKey(info.KeyName, info.Key, info.Keyid, info.ZoneData, keybootstrapperq)
		})
		retryTimers.Store(mapKey, t)
	}

	lgSigner.Info("KeyBootstrapper starting")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				lgSigner.Info("KeyBootstrapper received context done signal")
				// Cancel all pending retry timers.
				retryTimers.Range(func(key, value any) bool {
					value.(*time.Timer).Stop()
					retryTimers.Delete(key)
					return true
				})
				return
			case utr := <-keybootstrapperq:

				lgSigner.Debug("KeyBootstrapper received request", "cmd", utr.Cmd, "keyname", utr.KeyName, "zone", utr.ZoneName, "keyid", utr.Keyid, "has_response_chan", utr.ResponseChan != nil)

				switch utr.Cmd {
				case kbCmdPing:
					lgSigner.Debug("KeyBootstrapper PING received, PONG!")
				case kbCmdInfo:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					lgSigner.Debug("KeyBootstrapper INFO received", "keyname", utr.KeyName, "keyid", utr.Keyid)

					if utr.ResponseChan != nil {
						if val, exists := verifications.Load(mapKey); exists {
							info := val.(*VerificationInfo)
							lgSigner.Debug("KeyBootstrapper INFO found info for key", "failed_attempts", info.FailedAttempts, "attempts_left", info.AttemptsLeft)
							utr.ResponseChan <- info
						} else {
							lgSigner.Debug("KeyBootstrapper INFO no info found for key")
							utr.ResponseChan <- nil
						}
					}
				case kbCmdBootstrap:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					lgSigner.Info("received verification request", "zone", utr.ZoneName)

					// Get number of verification attempts from config
					attempts := viper.GetInt("verifyengine.attempts")
					if attempts == 0 {
						attempts = 3 // default if not configured
					}

					verifications.Store(mapKey, &VerificationInfo{
						Key:            utr.Key,
						ZoneName:       utr.ZoneName,
						AttemptsLeft:   attempts,
						NextCheckTime:  time.Now(),
						ZoneData:       utr.ZoneData,
						KeyName:        utr.KeyName,
						Keyid:          utr.Keyid,
						FailedAttempts: 0,
					})
					go VerifyKey(utr.KeyName, utr.Key, utr.Keyid, utr.ZoneData, keybootstrapperq)

				case kbCmdVerificationStep:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					lgSigner.Info("received verification result", "keyname", utr.KeyName, "keyid", utr.Keyid)
					if val, exists := verifications.Load(mapKey); exists {
						info := val.(*VerificationInfo)
						lgSigner.Debug("verification info", "keyname", utr.KeyName, "info", info)
						info.AttemptsLeft--
						if info.AttemptsLeft <= 0 {
							lgSigner.Info("verification completed", "keyname", utr.KeyName)
							tx, err := kdb.Begin("VerifyTrustEngine")
							if err != nil {
								lgSigner.Error("failed to start transaction, will retry", "err", err)
							} else {
								tppost := TruststorePost{
									SubCommand: "trust",
									Keyname:    info.KeyName,
									Keyid:      int(info.Keyid),
								}
								_, err := kdb.Sig0TrustMgmt(tx, tppost)
								if err != nil {
									lgSigner.Error("failed to update TrustStore, will retry", "err", err)
									tx.Rollback()
								} else {
									err = tx.Commit()
									if err != nil {
										lgSigner.Error("failed to commit transaction, will retry", "err", err)
									} else {
										verifications.Delete(mapKey)
										utr.Verified = true
										lgSigner.Info("TrustStore updated, verification complete", "keyname", utr.KeyName)
									}
								}
							}
							lgSigner.Info("verification for key completed", "keyname", utr.KeyName, "verified", utr.Verified)
						} else {
							// Schedule next verification attempt via per-key timer.
							retryInterval := viper.GetInt("verifyengine.retry_interval")
							if retryInterval == 0 {
								retryInterval = 60
							}
							delay := time.Duration(retryInterval) * time.Second
							lgSigner.Debug("scheduling next verification", "keyname", utr.KeyName, "attempts_left", info.AttemptsLeft, "delay", delay)
							scheduleRetry(info, delay)
						}
					}

				case kbCmdRestart:
					mapKey := fmt.Sprintf("%s::%d", utr.KeyName, utr.Keyid)
					if val, exists := verifications.Load(mapKey); exists {
						info := val.(*VerificationInfo)

						lgSigner.Info("verification failed, restarting", "keyname", utr.KeyName)

						attempts := viper.GetInt("verifyengine.attempts")
						if attempts == 0 {
							attempts = 3 // default if not configured
						}

						info.FailedAttempts++
						info.AttemptsLeft = attempts
						// Exponential backoff: wait FailedAttempts minutes before retrying.
						delay := time.Duration(info.FailedAttempts) * time.Minute
						lgSigner.Debug("scheduling retry after failure", "keyname", utr.KeyName, "failed_attempts", info.FailedAttempts, "delay", delay)
						scheduleRetry(info, delay)
					}

				case kbCmdUpdateKeyState:
					// Event-driven key state update: triggered after delegation sync,
					// key bootstrap, or explicit CLI/API request.
					lgSigner.Info("updating key state", "keyname", utr.KeyName, "keyid", utr.Keyid)
					imr := utr.Imr
					algorithm := utr.Algorithm
					keyName := utr.KeyName
					keyid := utr.Keyid
					go func() {
						err := kdb.UpdateKeyState(ctx, keyName, keyid, imr, algorithm)
						if err != nil {
							lgSigner.Error("failed to update key state", "keyname", keyName, "keyid", keyid, "err", err)
						}
					}()

				default:
					lgSigner.Warn("KeyBootstrapper unknown command, ignoring", "cmd", utr.Cmd)
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

// UpdateKeyState sends a KeyState inquiry to the DSYNC target for the given key
// and updates the local key store with the parent's response. If the parent
// reports the key as unknown, triggers a bootstrap.
func (kdb *KeyDB) UpdateKeyState(ctx context.Context, keyName string, keyid uint16, imr *Imr, algorithm uint8) error {
	if imr == nil {
		return fmt.Errorf("UpdateKeyState: no IMR engine provided")
	}

	dsyncTarget, err := imr.LookupDSYNCTarget(ctx, keyName, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return fmt.Errorf("could not find DSYNC target: %v", err)
	}

	// Create DNS message with EDNS(0) KeyState option
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(keyName), dns.TypeANY)

	edns0.AttachKeyStateToResponse(m, &edns0.KeyStateOption{
		KeyID:    keyid,
		KeyState: edns0.KeyStateInquiryKey,
	})

	// Get active key for signing
	sak, err := kdb.GetSig0Keys(keyName, Sig0StateActive)
	if err != nil {
		return fmt.Errorf("could not get active SIG(0) key: %v", err)
	}

	if len(sak.Keys) == 0 {
		return fmt.Errorf("no active SIG(0) key available for %s", keyName)
	}

	// Sign the message
	signedMsg, err := SignMsg(*m, keyName, sak)
	if err != nil {
		return fmt.Errorf("could not sign the message: %v", err)
	}

	// Send the signed message
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	if len(dsyncTarget.Addresses) == 0 {
		return fmt.Errorf("DSYNC target has no addresses for %s", keyName)
	}
	r, _, err := c.Exchange(signedMsg, dsyncTarget.Addresses[0])
	if err != nil {
		return fmt.Errorf("could not send DNS request: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS request failed with code: %v", dns.RcodeToString[r.Rcode])
	}

	// Extract KeyState option from response
	opt := r.IsEdns0()
	if opt == nil {
		return fmt.Errorf("no EDNS(0) OPT RR in response")
	}
	keystate, found := edns0.ExtractKeyStateOption(opt)
	if !found {
		return fmt.Errorf("KeyState option missing in response")
	}

	tx, err := kdb.Begin("UpdateKeyState")
	if err != nil {
		lgSigner.Error("failed to start transaction", "err", err)
		return err
	}

	kpparent := KeystorePost{
		Command:     "sig0-mgmt",
		SubCommand:  "setparentstate",
		Keyname:     keyName,
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
		zd, ok := FindZone(keyName)
		if !ok {
			return fmt.Errorf("could not find zone for %s", keyName)
		}

		_, _, err = zd.BootstrapSig0KeyWithParent(ctx, algorithm)
		if err != nil {
			lgSigner.Error("failed to bootstrap key", "keyname", keyName, "err", err)
			return fmt.Errorf("could not bootstrap key for %s: %v", keyName, err)
		}
	}

	return nil
}
