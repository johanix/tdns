package tdns

import (
	"log/slog"
)

var lgAgent = Logger("agent")
var lgCombiner = Logger("combiner")
var lgGossip *slog.Logger = Logger("gossip")
var lgTransport = Logger("transport")
var lgConnRetry = Logger("conn-retry")
var lgEngine = Logger("engine")
var lgConnRetryEngine = Logger("conn-retry")
var lgElect = Logger("elect")
var lgProviderGroup = Logger("provider-group")
var lgSigner = Logger("signer")
var lgRollover = Logger("rollover")
