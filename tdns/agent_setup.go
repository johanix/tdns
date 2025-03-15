/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/miekg/dns"
)

func createDeferredUpdate(zoneName, description string, action func() error) DeferredUpdate {
	return DeferredUpdate{
		Cmd:          "DEFERRED-UPDATE",
		ZoneName:     zoneName,
		AddTime:      time.Now(),
		Description:  description,
		PreCondition: ZoneIsReady(zoneName),
		Action:       action,
	}
}

func (conf *Config) SetupAgentAutoZone(zonename string) (*ZoneData, error) {
	log.Printf("SetupAgentAutoZone: Zone %q not found, creating a minimal auto zone", zonename)

	addrs, err := conf.FindDnsEngineAddrs()
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to find nameserver addresses: %v", err)
	}

	// dump.P(addrs)
	zd, err := conf.Internal.KeyDB.CreateAutoZone(zonename, addrs)
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to create minimal auto zone for agent identity %q: %v", zonename, err)
	}
	zd.Options[OptAllowUpdates] = true
	zd.SyncQ = conf.Internal.SyncQ

	// Check for local notify configuration and set downstream targets
	if conf.Agent.Local.Notify != nil && len(conf.Agent.Local.Notify) > 0 {
		zd.Downstreams = conf.Agent.Local.Notify
		if Globals.Debug {
			log.Printf("SetupAgentAutoZone: Setting downstream notify targets for zone %s: %v", zonename, zd.Downstreams)
		}
	}

	// Agent auto zone needs to be signed
	zd.Options[OptOnlineSigning] = true
	if tmp, exists := conf.Internal.DnssecPolicies["default"]; !exists {
		return nil, fmt.Errorf("SetupAgentAutoZone: DnssecPolicy 'default' not defined")
	} else {
		zd.DnssecPolicy = &tmp
	}
	err = zd.SetupZoneSigning(conf.Internal.ResignQ)
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to set up zone signing: %v", err)
	}

	return zd, nil
}

func (conf *Config) SetupApiTransport() error {
	identity := conf.Agent.Identity

	du := createDeferredUpdate(
		identity,
		fmt.Sprintf("Publish HTTPS transport records for agent %q", identity),
		func() error {
			zd, ok := Zones.Get(identity)
			if !ok {
				return fmt.Errorf("SetupApiTransport: zone data for agent identity %q not found", identity)
			}
			log.Printf("SetupApiTransport: publishing URI record for agent %q, api transport", identity)

			// Publish _https._tcp URI record
			uristr := strings.Replace(conf.Agent.Api.BaseUrl, "{TARGET}", identity, 1)
			uristr = strings.Replace(uristr, "{PORT}", fmt.Sprintf("%d", conf.Agent.Api.Port), 1)
			uri, err := url.Parse(uristr)
			if err != nil {
				return fmt.Errorf("SetupApiTransport: failed to parse base URL: %q", uristr)
			}
			// Split host and port since url.Parse doesn't handle dns:// URLs properly
			host, _, err := net.SplitHostPort(uri.Host)
			if err != nil {
				host = uri.Host // No port specified
			}
			log.Printf("SetupApiTransport: publishing _https._tcp URI record for agent %q with target %q", identity, host)

			// Publish _https._tcp URI record
			err = zd.PublishUriRR("_https._tcp."+identity, identity, conf.Agent.Api.BaseUrl, conf.Agent.Api.Port)
			if err != nil {
				return fmt.Errorf("SetupApiTransport: failed to publish URI record: %v", err)
			}
			log.Printf("SetupApiTransport: successfully published URI record for agent %q", identity)

			// Publish address records for the URI target
			for _, addr := range conf.Agent.Api.Addresses.Publish {
				err = zd.PublishAddrRR(host, addr)
				if err != nil {
					return fmt.Errorf("SetupApiTransport: failed to publish address record for %s %s: %v", host, addr, err)
				}
			}
			log.Printf("SetupApiTransport: successfully published address records for agent %q", identity)

			// Publish TLSA record
			err = zd.PublishTlsaRR(host, conf.Agent.Api.Port, conf.Agent.Api.CertData)
			if err != nil {
				return fmt.Errorf("SetupApiTransport: failed to publish TLSA record: %v", err)
			}
			log.Printf("SetupApiTransport: successfully published TLSA record for agent %q", identity)
			// Publish SVCB record with addresses
			var value []dns.SVCBKeyValue
			var ipv4hint, ipv6hint []net.IP

			for _, addr := range conf.Agent.Api.Addresses.Publish {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					ipv4hint = append(ipv4hint, ip)
				} else {
					ipv6hint = append(ipv6hint, ip)
				}
			}

			if conf.Agent.Api.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: conf.Agent.Api.Port})
			}
			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}
			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			err = zd.PublishSvcbRR(host, conf.Agent.Api.Port, value)
			if err != nil {
				return fmt.Errorf("SetupApiTransport: failed to publish SVCB record: %v", err)
			}
			log.Printf("SetupApiTransport: successfully published SVCB record for agent %q", identity)

			return nil
		},
	)
	conf.Internal.DeferredUpdateQ <- du
	return nil
}

func (conf *Config) SetupDnsTransport() error {
	identity := dns.Fqdn(conf.Agent.Identity)

	du := createDeferredUpdate(
		identity,
		fmt.Sprintf("Publish DNS transport records for agent %q", identity),
		func() error {
			zd, ok := Zones.Get(identity)
			if !ok {
				return fmt.Errorf("SetupDnsTransport: zone data for agent identity %q not found", identity)
			}
			log.Printf("SetupDnsTransport: publishing DNS transport records for agent %q", identity)

			uristr := strings.Replace(conf.Agent.Dns.BaseUrl, "{TARGET}", identity, 1)
			uristr = strings.Replace(uristr, "{PORT}", fmt.Sprintf("%d", conf.Agent.Dns.Port), 1)
			uri, err := url.Parse(uristr)
			if err != nil {
				return fmt.Errorf("SetupDnsTransport: failed to parse base URL: %q", uristr)
			}

			log.Printf("*** SetupDnsTransport: DEBUG: uri: %q, uri.Host: %q", uri, uri.Host)
			// Split host and port since url.Parse doesn't handle dns:// URLs properly
			host, _, err := net.SplitHostPort(uri.Host)
			if err != nil {
				host = uri.Host // No port specified
			}
			log.Printf("*** SetupDnsTransport: publishing _dns._tcp URI record for agent %q with target %q", identity, host)

			// Publish _dns._tcp URI record
			err = zd.PublishUriRR("_dns._tcp."+identity, identity, conf.Agent.Dns.BaseUrl, conf.Agent.Dns.Port)
			if err != nil {
				return fmt.Errorf("SetupDnsTransport: failed to publish URI record: %v", err)
			}
			log.Printf("SetupDnsTransport: successfully published URI record for agent %q", identity)

			// Publish address records for the URI target
			for _, addr := range conf.Agent.Dns.Addresses.Publish {
				err = zd.PublishAddrRR(host, addr)
				if err != nil {
					return fmt.Errorf("SetupDnsTransport: failed to publish address record for %s %s: %v", host, addr, err)
				}
			}
			log.Printf("SetupApiTransport: successfully published address records for agent %q", identity)

			// Publish KEY record for SIG(0)
			err = zd.AgentSig0KeyPrep(host, zd.KeyDB)
			if err != nil {
				return fmt.Errorf("SetupDnsTransport: failed to publish KEY record: %v", err)
			}
			log.Printf("SetupDnsTransport: successfully published KEY record for agent %q", identity)

			// Publish SVCB record with addresses
			var value []dns.SVCBKeyValue
			var ipv4hint, ipv6hint []net.IP

			for _, addr := range conf.Agent.Dns.Addresses.Publish {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					ipv4hint = append(ipv4hint, ip)
				} else {
					ipv6hint = append(ipv6hint, ip)
				}
			}

			if conf.Agent.Dns.Port != 0 {
				value = append(value, &dns.SVCBPort{Port: conf.Agent.Dns.Port})
			}
			if len(ipv4hint) > 0 {
				value = append(value, &dns.SVCBIPv4Hint{Hint: ipv4hint})
			}
			if len(ipv6hint) > 0 {
				value = append(value, &dns.SVCBIPv6Hint{Hint: ipv6hint})
			}

			err = zd.PublishSvcbRR(host, conf.Agent.Dns.Port, value)
			if err != nil {
				return fmt.Errorf("SetupDnsTransport: failed to publish SVCB record: %v", err)
			}
			log.Printf("SetupDnsTransport: successfully published SVCB record for agent %q", identity)

			return nil
		},
	)
	conf.Internal.DeferredUpdateQ <- du
	return nil
}

func (conf *Config) SetupAgent(all_zones []string) error {
	if Globals.Debug {
		log.Printf("SetupAgent: enter. all_zones: %v", all_zones)
	}

	if len(conf.Agent.Api.Addresses.Listen) == 0 && len(conf.Agent.Dns.Addresses.Listen) == 0 {
		dump.P(conf.Agent)
		return errors.New("SetupAgent: neither API nor DNS addresses set in config file")
	}

	// Ensure identity is FQDN
	conf.Agent.Identity = dns.Fqdn(conf.Agent.Identity)

	// Create auto zone for agent identity if needed
	if !slices.Contains(all_zones, conf.Agent.Identity) {
		_, err := conf.SetupAgentAutoZone(conf.Agent.Identity)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to create auto zone for agent identity %q: %v",
				conf.Agent.Identity, err)
		}
	}

	// Setup API transport if configured
	if len(conf.Agent.Api.Addresses.Publish) > 0 {
		// Load and verify API certificate
		certFile := conf.Agent.Api.CertFile
		keyFile := conf.Agent.Api.KeyFile

		if certFile == "" || keyFile == "" {
			return errors.New("SetupAgent: API transport defined, but cert or key file not set")
		}

		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("SetupAgent: error reading cert file: %v", err)
		}

		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("SetupAgent: error reading key file: %v", err)
		}

		conf.Agent.Api.CertData = string(certPEM)
		conf.Agent.Api.KeyData = string(keyPEM)

		// Verify certificate CN matches agent identity
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to parse certificate: %v", err)
		}

		if cert.Subject.CommonName != conf.Agent.Identity {
			return fmt.Errorf("SetupAgent: certificate CN %q does not match agent identity %q",
				cert.Subject.CommonName, conf.Agent.Identity)
		}

		// Add this before setting up the HTTP client
		log.Printf("Client certificate loaded: Subject=%s",
			cert.Subject.CommonName)

		log.Printf("Client certificate valid from %s to %s",
			cert.NotBefore, cert.NotAfter)

		err = conf.SetupApiTransport()
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to setup API transport: %v", err)
		}
	}

	// Setup DNS transport if configured
	if len(conf.Agent.Dns.Addresses.Publish) > 0 {
		err := conf.SetupDnsTransport()
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to setup DNS transport: %v", err)
		}
	}

	if Globals.Debug {
		log.Printf("SetupAgent: exit")
	}
	return nil
}

func (zd *ZoneData) AgentSig0KeyPrep(name string, kdb *KeyDB) error {
	alg, err := parseKeygenAlgorithm("agent.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		log.Printf("AgentSig0KeyPrep: Zone %s: Error from parseKeygenAlgorithm(): %v", zd.ZoneName, err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, kdb)
}

func (agent *Agent) NewAgentSyncApiClient(localagent *LocalAgentConf) error {
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}

	var details AgentDetails
	if _, exists := agent.Details["API"]; exists {
		agent.mu.Lock()
		details = agent.Details["API"]
		agent.mu.Unlock()
	}

	if !agent.Methods["API"] || details.TlsaRR == nil {
		return fmt.Errorf("agent %s does not support the API Method", agent.Identity)
	}

	if localagent.Api.CertFile == "" || localagent.Api.KeyFile == "" {
		return fmt.Errorf("local agent config missing either cert or key file")
	}

	if Globals.Debug {
		log.Printf("NewAgentSyncApiClient: enter. identity: %s, baseurl: %s",
			agent.Identity, details.BaseUri)
	}
	api := AgentApi{
		ApiClient: NewClient(agent.Identity, details.BaseUri, "", "", "tlsa"),
	}

	//	func NewClientConfig(caFile string, keyFile string, certFile string) (*tls.Config, error) {
	//        caCertPool, err := loadCertPool(caFile)
	//        if err != nil {
	// return nil, err
	//        }

	cert, err := tls.LoadX509KeyPair(localagent.Api.CertFile, localagent.Api.KeyFile)
	if err != nil {
		return err
	}

	//        config := &tls.Config{
	//                Certificates: []tls.Certificate{cert},
	//                RootCAs:      caCertPool,
	//        }

	//        return config, nil
	//}

	tlsconfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	//	if rootcafile == "insecure" {
	//		tlsconfig.InsecureSkipVerify = true
	//	} else if rootcafile == "tlsa" {
	// use TLSA RR for verification; InsecureSkipVerify must still be true
	tlsconfig.InsecureSkipVerify = true
	// use TLSA RR for verification
	tlsconfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		log.Printf("VerifyPeerCertificate called for %q (have TLSA: %s)", agent.Identity,
			agent.Details["API"].TlsaRR.String())
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %v", err)
			}
			if cert.Subject.CommonName != agent.Identity {
				return fmt.Errorf("unexpected certificate common name (should have been %s)", agent.Identity)
			}

			err = VerifyCertAgainstTlsaRR(agent.Details["API"].TlsaRR, rawCert)
			if err != nil {
				return fmt.Errorf("failed to verify certificate against TLSA record: %v", err)
			}
			log.Printf("VerifyPeerCertificate: successfully verified cert for %q", agent.Identity)
		}
		// log.Printf("NewMusicSyncApiClient: VerifyPeerCertificate returning nil (all good)")
		return nil
	}
	//	} else {
	//		rootCAPool := x509.NewCertPool()
	//		// rootCA, err := ioutil.ReadFile(viper.GetString("musicd.rootCApem"))
	//		rootCA, err := os.ReadFile(rootcafile)
	//		if err != nil {
	//			log.Fatalf("reading cert failed : %v", err)
	//		}
	//		if Globals.Debug {
	//			fmt.Printf("NewClient: Creating '%s' API client based on root CAs in file '%s'\n",
	//				name, rootcafile)
	//		}

	//		rootCAPool.AppendCertsFromPEM(rootCA)
	//		tlsconfig.RootCAs = rootCAPool
	//	}

	// api.Client = &http.Client{}
	api.ApiClient.Client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsconfig},
	}

	api.ApiClient.Debug = Globals.Debug
	api.ApiClient.Verbose = Globals.Verbose
	// log.Printf("client is a: %T\n", api.Client)

	// dump.P(tlsconfig)

	if Globals.Debug {
		fmt.Printf("Setting up AGENT-TO-AGENT Sync API client: %s\n", agent.Identity)
		fmt.Printf("* baseurl is: %s \n* authmethod is: %s \n", api.ApiClient.BaseUrl, api.ApiClient.AuthMethod)
	}
	agent.Api = &api

	return nil
}
