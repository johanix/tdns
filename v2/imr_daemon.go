/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	imrcore "github.com/johanix/tdns/v2/imr"

	"github.com/spf13/viper"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// InitImrEngine builds the Imr from conf.Imr (NewImr) and wires it into
// conf.Internal.RRsetCache, conf.Internal.ImrEngine and Globals.ImrEngine. This is
// safe to call synchronously before other engines start, guaranteeing that the
// Imr is available by the time transport bridges and agent registries are created.
//
// It does not prime: NewImr sends nothing, and ImrEngine starts the resolver
// (imr.Start primes, retrying until that works) and publishes ImrReady once it
// is primed. Until then the Imr's Query waits for it; its other lookups do not.
// An app that calls InitImrEngine itself waits on conf.Internal.ImrReady before
// its first lookup.
//
// Apps that need the IMR available early (e.g. mpagent) call this before
// StartEngine("ImrEngine", ...). Apps that don't need early availability can
// just call ImrEngine() which calls InitImrEngine() internally if needed.
//
// Idempotent: if conf.Internal.ImrEngine is already set, returns nil without
// touching any state. The IMR is a process singleton by intent — its priming
// cache, root hints, and validation state are expensive to construct and
// would diverge between two instances. The guard at the top of this function
// makes that singleton property hold by construction, regardless of which
// application initialises the IMR or in what order. First-init wins.
//
// IMPORTANT: tdns-mp depends on this split. The mpagent calls InitImrEngine()
// synchronously at startup so that conf.Internal.ImrEngine is guaranteed
// non-nil before transport bridges and agent registries are created. Without
// this, the *tdnsmp.Imr embedding wraps a nil *tdns.Imr and promoted method
// calls panic. Do not fold InitImrEngine back into ImrEngine without updating
// tdns-mp/v2/start_agent.go.
//
// ctx is NewImr's: it ends the data clock of imrengine.testing. tdns-mp pins a
// published tdns/v2 and so is unaffected until it bumps the dependency; when it
// does, its two call sites (tdns-mp/v2/start_agent.go:35, start_auditor.go:41)
// must pass their already-in-scope ctx, and no quiet flag: InitImrEngine(ctx),
// and ImrEngine(ctx).
func (conf *Config) InitImrEngine(ctx context.Context) error {
	// Idempotency guard: IMR is a process singleton. Subsequent calls are
	// no-ops; first-init wins.
	if conf.Internal.ImrEngine != nil {
		lgResolver.Debug("InitImrEngine: already initialized, returning existing instance")
		return nil
	}

	// NewImr fills the tuning defaults into its own copy of conf.Imr; the
	// daemon's imr-dump-tuning reads them from conf.
	LoadImrTuningDefaults(&conf.Imr.Tuning)
	opts := ImrOptions{
		LargeAlgorithms: conf.imrLargeAlgorithms(),
		DNSKEYTransport: conf.Internal.DNSKEYTransport,
		PendingOwnZone:  func(zone string) bool { return ownZonePending(conf, zone) },
		OwnZones:        hostedZones{},
	}
	// Not the nil pointer in a non-nil interface: NewImr takes nil for "none".
	if conf.Internal.ServerErrors != nil {
		opts.Errors = conf.Internal.ServerErrors
	}
	// Only tdns-imr turns imrengine.options into Options (parseImrOptions).
	// The resolver in the other daemons runs on the defaults, as it always
	// has; NewImr refuses option strings with no Options.
	ic := conf.Imr
	if ic.Options == nil {
		ic.Options = map[ImrOption]string{}
	}
	imr, err := NewImr(ctx, ic, opts)
	if err != nil {
		return err
	}
	// The daemon's resolver debugs and is verbose on --debug and --verbose
	// too, not only on imrengine.debug and imrengine.verbose.
	imr.Debug = imr.Debug || Globals.Debug
	imr.Verbose = imr.Verbose || Globals.Verbose
	conf.Internal.RRsetCache = imr.Cache
	// Stored now, for the apps that take it before ImrEngine runs (tdns-mp).
	// ImrEngine announces it once it is primed (startImr, publishImr).
	conf.Internal.ImrEngine = imr
	Globals.ImrEngine = imr
	lgResolver.Info("InitImrEngine: IMR initialized")
	return nil
}

// publishImr stores the finished Imr and announces it, in that order.
//
// One function rather than three statements at the call site, because the order
// is the entire safety property and it is invisible: the stores must happen
// BEFORE the close, so that a goroutine which has received from ImrReady is
// guaranteed by the memory model to see a fully constructed Imr rather than a
// pointer it may or may not observe. Written inline, the announce is one stray
// edit away from moving above the stores, or from being dropped altogether --
// and neither mistake shows up in a test that builds an ImrReadiness directly.
func (conf *Config) publishImr(imr *Imr) {
	conf.Internal.ImrEngine = imr
	Globals.ImrEngine = imr
	conf.Internal.ImrReady.Publish()
}

func (conf *Config) ImrEngine(ctx context.Context) error {
	var recursorch = conf.Internal.RecursorCh

	// IMR is active by default unless explicitly set to false
	isActive := conf.Imr.Active == nil || *conf.Imr.Active

	if !isActive {
		lgResolver.Warn("ImrEngine is NOT active (imrengine.active explicitly set to false)")
		for {
			select {
			case <-ctx.Done():
				lgResolver.Info("terminating (inactive mode, context cancelled)")
				return nil
			case rrq, ok := <-recursorch:
				if !ok {
					return nil
				}
				lgResolver.Warn("not active but got a request", "qname", rrq.Qname)
				continue // ensure that we keep reading to keep the channel open
			}
		}
	} else {
		lgResolver.Info("ImrEngine starting")
	}

	// Initialize the Imr if not already done (e.g. by a prior InitImrEngine
	// call). That sends nothing, and fails only on the configuration: the
	// priming, which is what fails at boot, is Start's, and Start retries it.
	if conf.Internal.ImrEngine == nil {
		if err := conf.InitImrEngine(ctx); err != nil {
			conf.Internal.ServerErrors.SetImrPrimingError(fmt.Sprintf("IMR did not start (no DNS listeners): %v", err))
			return fmt.Errorf("ImrEngine: InitImrEngine failed: %w", err)
		}
	}
	imr := conf.Internal.ImrEngine

	if !conf.startImr(ctx, imr, func(ctx context.Context) {
		// The recursive nameserver responding to queries with RD bit set.
		imr.StartImrEngineListeners(ctx, conf)
	}) {
		lgResolver.Info("terminating (active mode, context cancelled)")
		return nil
	}

	imr.Serve(ctx, recursorch)
	if ctx.Err() != nil {
		lgResolver.Info("terminating (active mode, context cancelled)")
	}
	return nil
}

// startImr starts the resolver and, once it is Ready (primed, which Start
// retries until it works), announces it and calls listen in a goroutine of its
// own. Until then the engines waiting on ImrReady wait, there are no
// listeners, and `config status` says why. It reports whether the resolver got
// Ready before ctx ended. listen starts the listeners; it is a parameter so
// that a test can see when it is called.
func (conf *Config) startImr(ctx context.Context, imr *Imr, listen func(context.Context)) bool {
	imr.Start(ctx)
	select {
	case <-imr.Ready():
	case <-ctx.Done():
		return false
	}
	conf.publishImr(imr)
	go listen(ctx)
	return true
}

func appendCachedNegativeSOA(rrcache *cache.RRsetCacheT, qname string, qtype uint16, msgoptions *edns0.MsgOptions, m *dns.Msg) bool {
	if rrcache == nil || m == nil {
		return false
	}
	cached := rrcache.Get(qname, qtype)
	if cached == nil || cached.RRset == nil {
		return false
	}
	imrcore.AppendSOAToMessage(cached.RRset, msgoptions, m)
	if cached.State == cache.ValidationStateSecure {
		m.AuthenticatedData = true
	}
	return true
}

// loadImrListenerCert validates and loads the IMR's listener certificate for
// the encrypted transports. The checks are mutually exclusive and each
// failure yields ONE accurate reason (the DnsEngine shape from do53.go): an
// unconfigured pair, an inaccessible file — any stat error, not only
// non-existence — or a pair that does not parse. The reason string is what
// gets logged and registered as the Transport/Cert server error.
func loadImrListenerCert(certFile, keyFile string) (tls.Certificate, string, bool) {
	var zero tls.Certificate
	if certFile == "" || keyFile == "" {
		return zero, "certfile/keyfile not configured", false
	}
	if _, err := os.Stat(certFile); err != nil {
		return zero, fmt.Sprintf("certfile %s not accessible: %v", certFile, err), false
	}
	if _, err := os.Stat(keyFile); err != nil {
		return zero, fmt.Sprintf("keyfile %s not accessible: %v", keyFile, err), false
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return zero, fmt.Sprintf("loading certfile/keyfile: %v", err), false
	}
	return cert, "", true
}

func (imr *Imr) StartImrEngineListeners(ctx context.Context, conf *Config) error {
	// An EMBEDDED resolver (tdns-auth, tdns-agent, anything that is not
	// tdns-imr) is internal by design and binds NO service listeners — the
	// listeners: block belongs to the app's own DNS service (DnsEngine).
	// Its only window is the loopback-only listeners.imr-debug-address
	// (#446). tdns-imr itself IS the service and listens on listeners:.
	if Globals.App.Type != AppTypeImr {
		if dbg := conf.Listeners.ImrDebugAddress; dbg != "" {
			if _, err := imr.startImrDebugListener(ctx, dbg, conf); err != nil {
				lgResolver.Error("imr debug listener not started", "err", err)
			}
		} else {
			lgResolver.Debug("embedded resolver: internal only (set listeners.imr-debug-address for a loopback debug window)")
		}
		return nil
	}

	addresses := conf.Listeners.Addresses
	if len(addresses) == 0 {
		lgResolver.Info("no addresses provided, will only be an internal recursive resolver")
		return nil
	}

	ImrHandler := imr.createImrHandler(ctx, conf)

	// The per-client transport counters, when on, wrap each listener's handler
	// with one that knows its transport. When off, every listener gets
	// ImrHandler itself, exactly as before.
	if conf.Imr.ClientStats.Enabled {
		imr.ClientStats = newImrClientStats(conf.Imr.ClientStats.MaxClients)
		lgResolver.Info("per-client transport counters are on", "max-clients", imr.ClientStats.max)
	}
	handlers := listenerHandlers(ImrHandler, imr.ClientStats)

	// Create a local ServeMux for ImrEngine to avoid conflicts with other engines.
	// It truncates oversized UDP answers to the client's buffer size. The
	// DoT/DoH/DoQ engines below get handlers.dot/.doh/.doq without a mux:
	// ImrHandler itself when the counters are off, its counting wrappers when
	// they are on. UDP and TCP get muxes of their own only when their handlers
	// differ (the counters are on).
	imrMux := newImrDo53Mux(handlers.udp)
	imrMuxTCP := imrMux
	if imr.ClientStats != nil {
		imrMuxTCP = newImrDo53Mux(handlers.tcp)
	}

	if CaseFoldContains(conf.Listeners.Transports, "do53") {
		lgResolver.Info("starting Do53 listeners", "addresses", addresses)
		servers := make([]*dns.Server, 0, len(addresses)*2)

		for _, addr := range addresses {
			for _, net := range []string{"udp", "tcp"} {
				mux := imrMux
				if net == "tcp" {
					mux = imrMuxTCP
				}
				server := &dns.Server{
					Addr:    addr,
					Net:     net,
					Handler: mux, // Use local mux instead of global handler
					// MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				}
				servers = append(servers, server)
				go func(s *dns.Server, addr, net string) {
					lgResolver.Info("serving", "addr", addr, "net", net)
					// Must bump the buffer size of incoming UDP msgs, as updates
					// may be much larger then queries
					// s.UDPSize = dns.DefaultMsgSize // 4096
					if err := s.ListenAndServe(); err != nil {
						lgResolver.Error("failed to setup server", "net", net, "err", err)
					} else {
						lgResolver.Info("listening", "addr", addr, "net", net)
					}
				}(server, addr, net)
			}
		}
		// Graceful shutdown of Do53 servers
		go func() {
			<-ctx.Done()
			lgResolver.Info("shutting down Do53 servers", "count", len(servers))
			for _, s := range servers {
				done := make(chan struct{})
				go func(s *dns.Server) {
					defer close(done)
					if err := s.Shutdown(); err != nil {
						lgResolver.Error("error shutting down Do53 server", "addr", s.Addr, "net", s.Net, "err", err)
					}
				}(s)
				select {
				case <-done:
					// ok
				case <-time.After(5 * time.Second):
					lgResolver.Warn("timeout waiting for Do53 server shutdown", "addr", s.Addr, "net", s.Net)
				}
			}
		}()
	} else {
		lgResolver.Info("not serving on transport Do53")
	}

	// Encrypted listeners. Nothing below applies to a do53-only resolver, so
	// a missing certificate is only a condition worth reporting when dot,
	// doh or doq is actually configured — and then it IS reported: before
	// this, a cert/key failure silently dropped all three IMR listeners with
	// a warning as the only trace (#444), unlike the DnsEngine path which
	// registers the condition for `config status`.
	certFile := conf.Listeners.CertFile
	keyFile := conf.Listeners.KeyFile
	if !anyEncryptedTransport(conf.Listeners.Transports) {
		if certFile != "" || keyFile != "" {
			lgResolver.Info("certfile/keyfile configured but no encrypted transport is; not starting DoT/DoH/DoQ")
		}
		return nil
	}
	cert, certReason, certKey := loadImrListenerCert(certFile, keyFile)
	if !certKey {
		lgResolver.Warn("not starting the DoT/DoH/DoQ listeners", "reason", certReason)
		conf.Internal.ServerErrors.SetTransportCertError("imr: " + certReason)
	}

	if certKey {
		// Strip port numbers from addresses before proceeding to modern transports
		tmp := make([]string, len(addresses))
		for i, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				lgResolver.Warn("failed to parse address", "addr", addr, "err", err)
				tmp[i] = addr // Keep original if parsing fails
			} else {
				tmp[i] = host
			}
		}
		addresses = tmp

		if CaseFoldContains(conf.Listeners.Transports, "dot") {
			err := DnsDoTEngine(ctx, conf, addresses, portStrings(conf.Listeners.Ports.DoT), &cert, handlers.dot, false)
			if err != nil {
				lgResolver.Error("failed to setup DoT server", "err", err)
			}
		} else {
			lgResolver.Info("not serving on transport DoT")
		}

		if CaseFoldContains(conf.Listeners.Transports, "doh") {
			err := DnsDoHEngine(ctx, conf, addresses, portStrings(conf.Listeners.Ports.DoH), conf.Listeners.DoHPath, certFile, keyFile, handlers.doh)
			if err != nil {
				lgResolver.Error("failed to setup DoH server", "err", err)
			}
		} else {
			lgResolver.Info("not serving on transport DoH")
		}

		if CaseFoldContains(conf.Listeners.Transports, "doq") {
			err := DnsDoQEngine(ctx, conf, addresses, portStrings(conf.Listeners.Ports.DoQ), &cert, handlers.doq)
			if err != nil {
				lgResolver.Error("failed to setup DoQ server", "err", err)
			}
		} else {
			lgResolver.Info("not serving on transport DoQ")
		}
	}
	return nil
}

func (imr *Imr) createImrHandler(ctx context.Context, conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	//	dnsupdateq := conf.Internal.DnsUpdateQ
	//	dnsnotifyq := conf.Internal.DnsNotifyQ
	//	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		// The Do53 server rejects a query without exactly one question before
		// it gets here, but not every path in does: the debug listener hands
		// such a query straight to this handler. Answer FORMERR rather than
		// index an empty question section.
		if len(r.Question) != 1 {
			m := new(dns.Msg)
			m.Id, m.Response, m.Opcode = r.Id, true, r.Opcode
			m.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(m)
			return
		}
		qname := r.Question[0].Name
		// var dnssec_ok bool
		msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
		if err != nil {
			lgResolver.Error("error extracting EDNS0 options", "err", err)
		}

		qtype := r.Question[0].Qtype
		lgResolver.Debug("received query", "qname", qname, "qtype", dns.TypeToString[qtype], "from", w.RemoteAddr(), "opcode", dns.OpcodeToString[r.Opcode])

		switch r.Opcode {
		case dns.OpcodeNotify, dns.OpcodeUpdate:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			edns0.EnsureResponseOPT(m, r, dns.DefaultMsgSize)
			w.WriteMsg(m)
			return

		case dns.OpcodeQuery:
			lgResolver.Debug("lookup request", "qname", qname, "qtype", dns.TypeToString[qtype], "RD", msgoptions.RD, "DO", msgoptions.DO, "from", w.RemoteAddr())

			qname = core.CanonicalizeName(qname)
			if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
				DotServerQnameResponse(qname, w, r)
				return
			}
			// Any other CHAOS query is refused rather than resolved.
			// ImrResponder takes a qname and a qtype and no qclass at all, so
			// a CHAOS query that reaches it is resolved in class IN and
			// answered with IN data under a CHAOS question -- which is what
			// `dig version.bind txt chaos` was being answered with when it
			// reported a malformed message.
			//
			// CHAOS is server-local metadata; there is nothing to recurse for.
			// The names this server does answer are handled above.
			if r.Question[0].Qclass == dns.ClassCHAOS {
				lgResolver.Debug("refusing CHAOS query for a name this server does not serve", "qname", qname, "qtype", dns.TypeToString[qtype])
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				edns0.EnsureResponseOPT(m, r, dns.DefaultMsgSize)
				w.WriteMsg(m)
				return
			}

			// Run IMR client query hooks (dependency analysis, RPZ, etc.)
			hookCtx := ctx
			for _, hook := range getImrClientQueryHooks() {
				newCtx, response := hook(hookCtx, w, r, qname, qtype, msgoptions)
				if newCtx != nil {
					hookCtx = newCtx
				}
				if response != nil {
					w.WriteMsg(response)
					return
				}
			}
			imr.ImrResponder(hookCtx, w, r, qname, qtype, msgoptions)
			return

		default:
			lgResolver.Error("unable to handle message type", "opcode", dns.OpcodeToString[r.Opcode])
		}
	}
}

func DotServerQnameResponse(qname string, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	edns0.EnsureResponseOPT(m, r, dns.DefaultMsgSize)
	qname = core.CanonicalizeName(qname)
	// if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
	lgResolver.Debug("query for .server CH TLD", "qname", qname)
	switch qname {
	case "id.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.id")
		if v == "" {
			v = "tdns-imr - a recursive name server for experiments and POCs"
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600}, Txt: []string{v},
		})
	case "version.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.version")
		if v == "" {
			v = fmt.Sprintf("%s version %s", Globals.App.Name, Globals.App.Version)
		} else if strings.Contains(v, "{version}") {
			v = strings.Replace(v, "{version}", Globals.App.Version, -1)
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600}, Txt: []string{v},
		})
	case "authors.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600},
			Txt: []string{
				"Johan Stenstam <johan.stenstam@internetstiftelsen.se>",
				"Erik Bergström <erik.bergstrom@internetstiftelsen.se>",
				"Leon Fernandez <leon.fernandez@internetstiftelsen.se>",
			},
		})

	case "hostname.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.hostname")
		if v == "" {
			v = "a.random.internet.host."
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600}, Txt: []string{v},
		})
	default:
	}
	w.WriteMsg(m)
}
