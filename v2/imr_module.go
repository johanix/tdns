/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"log"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	imrcore "github.com/johanix/tdns/v2/imr"
	"github.com/miekg/dns"
)

// The resolver is the module github.com/johanix/tdns/v2/imr (#1073). This is
// the daemon's side of it: the Imr the daemon runs, and the names the
// resolver's types, constants and functions have always had here.

// Imr is the daemon's resolver: the module's, and what the daemon keeps
// beside it. The listeners, the debug listener and the management API are the
// daemon's, and so are their methods on Imr.
type Imr struct {
	*imrcore.Imr
	// ClientStats holds the per-client transport counters, or nil when they
	// are off (imrengine.client-stats). See imr_client_stats.go.
	ClientStats *ImrClientStats
}

// NewImr is imrcore.New, returning the daemon's Imr. Unless opts says
// otherwise, the resolver logs through the daemon's engine subsystem logger,
// and its lookups through the dns one.
func NewImr(ctx context.Context, ic ImrEngineConf, opts ImrOptions) (*Imr, error) {
	if opts.Logger == nil {
		opts.Logger = lgImr
	}
	if opts.LookupLogger == nil {
		opts.LookupLogger = lgDns
	}
	r, err := imrcore.New(ctx, ic, opts)
	if err != nil {
		return nil, err
	}
	return &Imr{Imr: r}, nil
}

var (
	lgImr = Logger("engine")
	lgDns = Logger("dns")
)

// core is the module's Imr, nil for a nil imr.
func (imr *Imr) core() *imrcore.Imr {
	if imr == nil {
		return nil
	}
	return imr.Imr
}

// These methods answer on a nil resolver, as conf.Internal.ImrEngine is when
// imrengine.active is false. Promoted from the embedded *imrcore.Imr, they
// would dereference the nil *Imr first.

func (imr *Imr) RefreshDnssecPolicy(largeAlgs map[uint8]bool, transport DNSKEYTransportPolicy) {
	imr.core().RefreshDnssecPolicy(largeAlgs, transport)
}

func (imr *Imr) StatusReport() *ImrStatus { return imr.core().StatusReport() }

func (imr *Imr) ReloadZones(stubconf []ImrStubConf, fwdconf []ImrForwardConf) (ImrZoneReloadResult, error) {
	return imr.core().ReloadZones(stubconf, fwdconf)
}

func (imr *Imr) RefreshRoot(ctx context.Context, hintsfile string) {
	imr.core().RefreshRoot(ctx, hintsfile)
}

func (imr *Imr) RootNSStatus() (present bool, expires time.Time, count int) {
	return imr.core().RootNSStatus()
}

func (imr *Imr) ForwardZoneList() []ImrForwardZoneInfo { return imr.core().ForwardZoneList() }

func (imr *Imr) StubZoneList() []ImrStubZoneInfo { return imr.core().StubZoneList() }

func (imr *Imr) StubZoneStatus() []ImrStubZoneStatus { return imr.core().StubZoneStatus() }

func (imr *Imr) TransportSignalRRType() uint16 { return imr.core().TransportSignalRRType() }

func (imr *Imr) TransportSignalCached(owner string) bool {
	return imr.core().TransportSignalCached(owner)
}

// ImrQuery and ImrQueryFresh are the module's Query and QueryFresh, under the
// names they have here. ImrQuery keeps the respch parameter for its callers in
// tdns-mp and tdns-transport, which pass nil; it is not used.

func (imr *Imr) ImrQuery(ctx context.Context, qname string, qtype uint16, qclass uint16, respch chan *ImrResponse) (*ImrResponse, error) {
	return imr.Imr.Query(ctx, qname, qtype, qclass)
}

func (imr *Imr) ImrQueryFresh(ctx context.Context, qname string, qtype uint16, qclass uint16) (*ImrResponse, error) {
	return imr.Imr.QueryFresh(ctx, qname, qtype, qclass)
}

// ImrResponder is the module's Responder, under the name it has here.
func (imr *Imr) ImrResponder(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, msgoptions *edns0.MsgOptions) {
	imr.Imr.Responder(ctx, w, r, qname, qtype, msgoptions)
}

// The resolver's names, as they have always been in this package.

type ImrEngineConf = imrcore.Config

type (
	AddressFamilyConf        = imrcore.AddressFamilyConf
	BackoffConf              = imrcore.BackoffConf
	DNSKEYTransportPolicy    = imrcore.DNSKEYTransportPolicy
	DiscoveryConf            = imrcore.DiscoveryConf
	DsyncResult              = imrcore.DsyncResult
	DsyncTarget              = imrcore.DsyncTarget
	ErrorCategory            = imrcore.ErrorCategory
	ErrorSink                = imrcore.ErrorSink
	ErrorSubtype             = imrcore.ErrorSubtype
	ForwardDiag              = imrcore.ForwardDiag
	ForwardUpstream          = imrcore.ForwardUpstream
	ForwardZone              = imrcore.ForwardZone
	ImrClientStatsConf       = imrcore.ClientStatsConf
	ImrForwardConf           = imrcore.ForwardConf
	ImrForwardProbeResult    = imrcore.ForwardProbeResult
	ImrForwardUpstreamInfo   = imrcore.ForwardUpstreamInfo
	ImrForwardZoneInfo       = imrcore.ForwardZoneInfo
	ImrForwardZoneStatus     = imrcore.ForwardZoneStatus
	ImrLoggingConf           = imrcore.LoggingConf
	ImrOption                = imrcore.Option
	ImrOptions               = imrcore.Options
	ImrOutboundQueryHookFunc = imrcore.OutboundQueryHookFunc
	ImrRequest               = imrcore.Request
	ImrResponse              = imrcore.Response
	ImrResponseHookFunc      = imrcore.ResponseHookFunc
	ImrStatus                = imrcore.Status
	ImrStubConf              = imrcore.StubConf
	ImrStubProbeResult       = imrcore.StubProbeResult
	ImrStubServerInfo        = imrcore.StubServerInfo
	ImrStubServerStatus      = imrcore.StubServerStatus
	ImrStubZoneInfo          = imrcore.StubZoneInfo
	ImrStubZoneStatus        = imrcore.StubZoneStatus
	ImrTestingConf           = imrcore.TestingConf
	ImrTuningConf            = imrcore.TuningConf
	ImrUpstreamConf          = imrcore.UpstreamConf
	ImrUpstreamStatus        = imrcore.UpstreamStatus
	ImrZoneReloadResult      = imrcore.ZoneReloadResult
	LargeKskDSAlgCount       = imrcore.LargeKskDSAlgCount
	LargeKskImrMetrics       = imrcore.LargeKskMetrics
	OwnZone                  = imrcore.OwnZone
	OwnZones                 = imrcore.OwnZones
	PrivacyUnavailableError  = imrcore.PrivacyUnavailableError
	ServerAddrXportTuple     = imrcore.ServerAddrXportTuple
	ServerError              = imrcore.ServerError
)

const (
	DNSKEYTransportForceEncrypted  = imrcore.DNSKEYTransportForceEncrypted
	DNSKEYTransportForceUDP        = imrcore.DNSKEYTransportForceUDP
	DNSKEYTransportTryEncrypted    = imrcore.DNSKEYTransportTryEncrypted
	DNSKEYTransportUseDSSignal     = imrcore.DNSKEYTransportUseDSSignal
	DefaultCacheMaxTTL             = imrcore.DefaultCacheMaxTTL
	DefaultImrClientStatsMax       = imrcore.DefaultClientStatsMax
	ErrCatConfig                   = imrcore.ErrCatConfig
	ErrCatOther                    = imrcore.ErrCatOther
	ErrCatTransport                = imrcore.ErrCatTransport
	ErrCatUpstream                 = imrcore.ErrCatUpstream
	ErrSubApiAccess                = imrcore.ErrSubApiAccess
	ErrSubApiSocket                = imrcore.ErrSubApiSocket
	ErrSubCert                     = imrcore.ErrSubCert
	ErrSubCertMissing              = imrcore.ErrSubCertMissing
	ErrSubImrForward               = imrcore.ErrSubImrForward
	ErrSubImrForwardUpstream       = imrcore.ErrSubImrForwardUpstream
	ErrSubImrForwardZone           = imrcore.ErrSubImrForwardZone
	ErrSubImrPriming               = imrcore.ErrSubImrPriming
	ErrSubPort                     = imrcore.ErrSubPort
	ImrOptAllowLoopbackNameservers = imrcore.OptAllowLoopbackNameservers
	ImrOptAlwaysQueryForTransport  = imrcore.OptAlwaysQueryForTransport
	ImrOptQueryForTransport        = imrcore.OptQueryForTransport
	ImrOptQueryForTransportTLSA    = imrcore.OptQueryForTransportTLSA
	ImrOptRevalidateNS             = imrcore.OptRevalidateNS
	ImrOptTransportSignalType      = imrcore.OptTransportSignalType
	ImrOptUseTransportSignals      = imrcore.OptUseTransportSignals
	SvcbTLSAKey                    = imrcore.SvcbTLSAKey
	TimeLayout                     = imrcore.TimeLayout
)

var (
	ErrNoUsableDsync      = imrcore.ErrNoUsableDsync
	ErrPrivacyUnavailable = imrcore.ErrPrivacyUnavailable
)

func AuthDNSQuery(qname string, lg *log.Logger, nameservers []string, rrtype uint16, verbose bool) (*core.RRset, int, error) {
	return imrcore.AuthDNSQuery(qname, lg, nameservers, rrtype, verbose)
}

func BuildImrForwards(conf []ImrForwardConf) ([]*ForwardZone, []ForwardDiag) {
	return imrcore.BuildForwards(conf)
}

func DNSSECAlgorithmLabel(alg uint8) string {
	return imrcore.DNSSECAlgorithmLabel(alg)
}

func GetAlpn(svcb *dns.SVCB) []string {
	return imrcore.GetAlpn(svcb)
}

func GetTransportParam(svcb *dns.SVCB) (map[string]uint8, bool, error) {
	return imrcore.GetTransportParam(svcb)
}

func GetTransportParamRaw(svcb *dns.SVCB) (map[string]uint8, bool, error) {
	return imrcore.GetTransportParamRaw(svcb)
}

func LargeKskImrMetricsSnapshot() LargeKskImrMetrics {
	return imrcore.LargeKskMetricsSnapshot()
}

func LoadImrTuningDefaults(t *ImrTuningConf) {
	imrcore.LoadTuningDefaults(t)
}

func MarshalTransport(transports map[string]uint8) string {
	return imrcore.MarshalTransport(transports)
}

func ParseAddressFamilies(list []string) (v4, v6 bool, err error) {
	return imrcore.ParseAddressFamilies(list)
}

func ParseTLSAString(s string) (*dns.TLSA, error) {
	return imrcore.ParseTLSAString(s)
}

func PrintMsgFull(m *dns.Msg, width int) string {
	return imrcore.PrintMsgFull(m, width)
}

func PrintMsgSection(header string, section []dns.RR, width int) string {
	return imrcore.PrintMsgSection(header, section, width)
}

func RegisterImrOutboundQueryHook(hook ImrOutboundQueryHookFunc) error {
	return imrcore.RegisterOutboundQueryHook(hook)
}

func RegisterImrResponseHook(hook ImrResponseHookFunc) error {
	return imrcore.RegisterResponseHook(hook)
}

func ValidateExplicitServerSVCB(svcb *dns.SVCB) error {
	return imrcore.ValidateExplicitServerSVCB(svcb)
}
