/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/v2/crypto/jose"
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
	lgAgent.Info("creating a minimal auto zone", "zone", zonename)

	var zd *ZoneData
	var err error
	if len(conf.Agent.Local.Nameservers) > 0 {
		nsNames := make([]string, len(conf.Agent.Local.Nameservers))
		for i, ns := range conf.Agent.Local.Nameservers {
			nsNames[i] = dns.Fqdn(ns)
		}
		zd, err = conf.Internal.KeyDB.CreateAutoZone(zonename, nil, nsNames)
	} else {
		addrs, findErr := conf.FindDnsEngineAddrs()
		if findErr != nil {
			return nil, fmt.Errorf("SetupAgentAutoZone: failed to find nameserver addresses: %v", findErr)
		}
		zd, err = conf.Internal.KeyDB.CreateAutoZone(zonename, addrs, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to create minimal auto zone for agent identity %q: %v", zonename, err)
	}
	zd.Options[OptAllowUpdates] = true
	zd.SyncQ = conf.Internal.SyncQ

	// Check for local notify configuration and set downstream targets
	if len(conf.Agent.Local.Notify) > 0 {
		zd.Downstreams = NormalizeAddresses(conf.Agent.Local.Notify)
		lgAgent.Debug("setting downstream notify targets", "zone", zonename, "downstreams", zd.Downstreams)
	}

	// Agent auto zone needs to be signed
	zd.Options[OptOnlineSigning] = true
	if tmp, exists := conf.Internal.DnssecPolicies["default"]; !exists {
		return nil, fmt.Errorf("SetupAgentAutoZone: DnssecPolicy 'default' not defined")
	} else {
		zd.DnssecPolicy = &tmp
	}

	_, err = zd.SignZone(conf.Internal.KeyDB, true)
	if err != nil {
		return nil, fmt.Errorf("SetupAgentAutoZone: failed to sign zone: %v", err)
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
			lgAgent.Info("publishing URI record for API transport", "agent", identity)

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
			lgAgent.Debug("publishing _https._tcp URI record", "agent", identity, "target", host)

			// Publish _https._tcp URI record
			err = zd.PublishUriRR("_https._tcp."+identity, identity, conf.Agent.Api.BaseUrl, conf.Agent.Api.Port)
			if err != nil {
				return fmt.Errorf("SetupApiTransport: failed to publish URI record: %v", err)
			}
			lgAgent.Debug("published URI record", "agent", identity)

			// Publish address records for the URI target
			for _, addr := range conf.Agent.Api.Addresses.Publish {
				err = zd.PublishAddrRR(host, addr)
				if err != nil {
					return fmt.Errorf("SetupApiTransport: failed to publish address record for %s %s: %v", host, addr, err)
				}
			}
			lgAgent.Debug("published address records", "agent", identity)

			// Publish TLSA record
			err = zd.PublishTlsaRR(host, conf.Agent.Api.Port, conf.Agent.Api.CertData)
			if err != nil {
				return fmt.Errorf("SetupApiTransport: failed to publish TLSA record: %v", err)
			}
			lgAgent.Debug("published TLSA record", "agent", identity)
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
			lgAgent.Debug("published SVCB record for API transport", "agent", identity)

			return nil
		},
	)

	// Non-blocking send: if channel is full, return error instead of blocking
	select {
	case conf.Internal.DeferredUpdateQ <- du:
		// Successfully queued
	default:
		return fmt.Errorf("SetupApiTransport: deferred update queue is full, cannot queue API transport setup for agent %q", identity)
	}
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
			lgAgent.Info("publishing DNS transport records", "agent", identity)

			uristr := strings.Replace(conf.Agent.Dns.BaseUrl, "{TARGET}", identity, 1)
			uristr = strings.Replace(uristr, "{PORT}", fmt.Sprintf("%d", conf.Agent.Dns.Port), 1)
			uri, err := url.Parse(uristr)
			if err != nil {
				return fmt.Errorf("SetupDnsTransport: failed to parse base URL: %q", uristr)
			}

			lgAgent.Debug("parsed DNS transport URI", "uri", uri, "host", uri.Host)
			// Split host and port since url.Parse doesn't handle dns:// URLs properly
			host, _, err := net.SplitHostPort(uri.Host)
			if err != nil {
				host = uri.Host // No port specified
			}
			lgAgent.Debug("publishing _dns._tcp URI record", "agent", identity, "target", host)

			// Publish _dns._tcp URI record
			err = zd.PublishUriRR("_dns._tcp."+identity, identity, conf.Agent.Dns.BaseUrl, conf.Agent.Dns.Port)
			if err != nil {
				return fmt.Errorf("SetupDnsTransport: failed to publish URI record: %v", err)
			}
			lgAgent.Debug("published DNS URI record", "agent", identity)

			// Publish address records for the URI target
			for _, addr := range conf.Agent.Dns.Addresses.Publish {
				err = zd.PublishAddrRR(host, addr)
				if err != nil {
					return fmt.Errorf("SetupDnsTransport: failed to publish address record for %s %s: %v", host, addr, err)
				}
			}
			lgAgent.Debug("published address records", "agent", identity)

			// Publish KEY record for SIG(0)
			err = zd.AgentSig0KeyPrep(host, zd.KeyDB)
			if err != nil {
				return fmt.Errorf("SetupDnsTransport: failed to publish KEY record: %v", err)
			}
			lgAgent.Debug("published KEY record", "agent", identity)

			// Publish JWK record for JOSE/HPKE keys at dns.<identity>
			// This is separate from SIG(0) KEY records - JWK is for payload crypto
			publishName := "dns." + identity
			err = zd.AgentJWKKeyPrep(publishName, zd.KeyDB)
			if err != nil {
				lgAgent.Warn("failed to publish JWK record, continuing without JWK", "err", err)
				// Don't fail setup if JWK publication fails - it's optional
			} else {
				lgAgent.Debug("published JWK record", "name", publishName)
			}

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
			lgAgent.Debug("published SVCB record for DNS transport", "agent", identity)

			return nil
		},
	)
	// Non-blocking send: if channel is full, return error instead of blocking
	select {
	case conf.Internal.DeferredUpdateQ <- du:
		// Successfully queued
	default:
		return fmt.Errorf("SetupDnsTransport: deferred update queue is full, cannot queue DNS transport setup for agent %q", identity)
	}
	return nil
}

func (conf *Config) SetupAgent(all_zones []string) error {
	lgAgent.Debug("SetupAgent enter", "zones", all_zones)

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

	// Setup API transport if configured AND supported
	apiSupported := slices.Contains(conf.Agent.SupportedMechanisms, "api")
	if apiSupported && len(conf.Agent.Api.Addresses.Publish) > 0 {
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
		lgAgent.Info("client certificate loaded", "subject", cert.Subject.CommonName,
			"notBefore", cert.NotBefore, "notAfter", cert.NotAfter)

		err = conf.SetupApiTransport()
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to setup API transport: %v", err)
		}
	}

	// Setup DNS transport if configured AND supported
	dnsSupported := slices.Contains(conf.Agent.SupportedMechanisms, "dns")
	if dnsSupported && len(conf.Agent.Dns.Addresses.Publish) > 0 {
		err := conf.SetupDnsTransport()
		if err != nil {
			return fmt.Errorf("SetupAgent: failed to setup DNS transport: %v", err)
		}
	}

	lgAgent.Debug("SetupAgent exit")
	return nil
}

func (zd *ZoneData) AgentSig0KeyPrep(name string, kdb *KeyDB) error {
	alg, err := parseKeygenAlgorithm("agent.update.keygen.algorithm", dns.ED25519)
	if err != nil {
		lgAgent.Error("parseKeygenAlgorithm failed", "zone", zd.ZoneName, "err", err)
		return err
	}

	return zd.Sig0KeyPreparation(name, alg, kdb)
}

// AgentJWKKeyPrep publishes a JWK record for the agent's JOSE/HPKE long-term public keys.
// This provides RFC 7517 compliant public key discovery for payload encryption/signing.
//
// NOTE: This is separate from SIG(0) keys (which use KEY records). JOSE/HPKE keys are used
// for CHUNK payload encryption/signing, not DNS UPDATE authentication.
//
// Parameters:
//   - publishname: The name where the JWK record will be published (typically "dns.<identity>")
//   - kdb: The key database (unused, kept for interface compatibility)
func (zd *ZoneData) AgentJWKKeyPrep(publishname string, kdb *KeyDB) error {
	lgAgent.Info("publishing JWK record", "zone", zd.ZoneName, "name", publishname)

	// Check if JWK publication is disabled
	if zd.Options[OptDontPublishJWK] {
		lgAgent.Debug("JWK publication disabled by dont-publish-jwk option", "zone", zd.ZoneName)
		return nil
	}

	// Load JOSE private key from config
	privKeyPath := strings.TrimSpace(Conf.Agent.LongTermJosePrivKey)
	if privKeyPath == "" {
		return fmt.Errorf("AgentJWKKeyPrep: no JOSE key path configured")
	}

	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("AgentJWKKeyPrep: JOSE key file not found: %q", privKeyPath)
		}
		return fmt.Errorf("AgentJWKKeyPrep: failed to read JOSE key: %w", err)
	}

	// Strip comments from key file
	privKeyData = StripKeyFileComments(privKeyData)

	// Use JOSE backend to parse the key
	backend := jose.NewBackend()
	privKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to parse JOSE private key: %w", err)
	}

	// Derive public key from private key
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return fmt.Errorf("AgentJWKKeyPrep: backend is not JOSE")
	}
	josePubKey, err := joseBackend.PublicFromPrivate(privKey)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to derive public key: %w", err)
	}

	// Serialize the JOSE public key to JWK JSON to extract the underlying key
	pubKeyData, err := backend.SerializePublicKey(josePubKey)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to serialize public key: %w", err)
	}

	// Parse the JWK JSON to extract the underlying ECDSA public key
	var jwk struct {
		Key *ecdsa.PublicKey `json:"-"` // Will be populated by custom unmarshaling
		Kty string           `json:"kty"`
		Crv string           `json:"crv"`
		X   string           `json:"x"`
		Y   string           `json:"y"`
	}
	if err := json.Unmarshal(pubKeyData, &jwk); err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to parse JWK: %w", err)
	}

	// Manually decode the ECDSA coordinates from the JWK
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to decode X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to decode Y coordinate: %w", err)
	}

	// Reconstruct the ECDSA public key
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Check if HPKE key exists (future support)
	// For now, we only have JOSE key (P-256)
	// TODO: Check for HPKE X25519 key when implemented

	// Determine "use" field:
	// - If only P-256 key: NO "use" field (used for both sign and encrypt)
	// - If both P-256 and X25519: add "use":"sig" for P-256, "use":"enc" for X25519
	hasHPKEKey := false // TODO: Check if HPKE key exists
	use := ""
	if hasHPKEKey {
		use = "sig" // P-256 is for signing when HPKE present
	}
	// else: leave empty (dual-use)

	// Publish the JWK record at the publishname (dns.<identity>)
	err = zd.PublishJWKRR(publishname, ecdsaPubKey, use)
	if err != nil {
		return fmt.Errorf("AgentJWKKeyPrep: failed to publish JWK record: %w", err)
	}

	lgAgent.Info("published JWK record", "name", publishname)
	return nil
}

func (agent *Agent) NewAgentSyncApiClient(localagent *LocalAgentConf) error {
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}

	// Check if API method is supported and TLSA record exists
	if agent.ApiDetails == nil {
		return fmt.Errorf("agent %s: ApiDetails not initialized", agent.Identity)
	}
	if !agent.ApiMethod || agent.ApiDetails.TlsaRR == nil {
		return fmt.Errorf("agent %s does not support the API Method", agent.Identity)
	}

	// Verify local agent has necessary certificates
	if localagent.Api.CertFile == "" || localagent.Api.KeyFile == "" {
		return fmt.Errorf("local agent config missing either cert or key file")
	}

	lgAgent.Debug("creating API client", "identity", agent.Identity, "baseurl", agent.ApiDetails.BaseUri)

	// Create API client
	api := AgentApi{
		ApiClient: NewClient(string(agent.Identity), agent.ApiDetails.BaseUri, "", "", "tlsa"),
	}

	// Load client certificate
	cert, err := tls.LoadX509KeyPair(localagent.Api.CertFile, localagent.Api.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Configure TLS with client certificate
	tlsconfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Configure certificate verification using TLSA record
	tlsconfig.InsecureSkipVerify = true
	tlsconfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// log.Printf("VerifyPeerCertificate called for %q (have TLSA: %s)", agent.Identity,
		// 	agent.ApiDetails.TlsaRR.String())

		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %v", err)
			}

			if cert.Subject.CommonName != string(agent.Identity) {
				return fmt.Errorf("unexpected certificate common name (should have been %s)", agent.Identity)
			}

			err = VerifyCertAgainstTlsaRR(agent.ApiDetails.TlsaRR, rawCert)
			if err != nil {
				return fmt.Errorf("failed to verify certificate against TLSA record: %v", err)
			}

			lgAgent.Debug("verified cert against TLSA record", "agent", agent.Identity)
		}

		return nil
	}

	// Create HTTP client with TLS config
	api.ApiClient.Client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsconfig},
	}

	// Set debug flags
	api.ApiClient.Debug = Globals.Debug
	api.ApiClient.Verbose = Globals.Verbose

	// Configure API addresses if available
	if len(agent.ApiDetails.Addrs) > 0 {
		lgAgent.Debug("remote agent API addresses", "agent", agent.Identity, "addrs", agent.ApiDetails.Addrs)
		var addressesWithPort []string
		port := strconv.Itoa(int(agent.ApiDetails.Port))

		for _, addr := range agent.ApiDetails.Addrs {
			addressesWithPort = append(addressesWithPort, net.JoinHostPort(addr, port))
		}

		api.ApiClient.Addresses = addressesWithPort
	}

	lgAgent.Debug("setting up agent-to-agent sync API client",
		"agent", agent.Identity, "baseurl", api.ApiClient.BaseUrl, "authmethod", api.ApiClient.AuthMethod)

	// Assign the API client to the agent
	agent.Api = &api

	return nil
}
