package tdns

import (
	core "github.com/johanix/tdns/tdns/core"
)

// Aliases for smooth migration to tdns/core. Remove after callers update imports.

// CacheContext and constants
type CacheContext = core.CacheContext

const (
	ContextAnswer     = core.ContextAnswer
	ContextHint       = core.ContextHint
	ContextPriming    = core.ContextPriming
	ContextReferral   = core.ContextReferral
	ContextNXDOMAIN   = core.ContextNXDOMAIN
	ContextNoErrNoAns = core.ContextNoErrNoAns
	ContextGlue       = core.ContextGlue
	ContextFailure    = core.ContextFailure
)

var CacheContextToString = core.CacheContextToString

// Transport and helpers
type Transport = core.Transport

const (
	TransportDo53 = core.TransportDo53
	TransportDoT  = core.TransportDoT
	TransportDoH  = core.TransportDoH
	TransportDoQ  = core.TransportDoQ
)

var TransportToString = core.TransportToString
var StringToTransport = core.StringToTransport

// Types
type RRset = core.RRset

// Helpers
var WithinValidityPeriod = core.WithinValidityPeriod


