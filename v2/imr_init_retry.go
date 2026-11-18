/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"time"
)

// Priming needs an answer from a root server, and a daemon starts at the moment
// it is least likely to get one: every resolver on the network priming at once,
// or the root server on the same host not up yet. A failed InitImrEngine used to
// end the ImrEngine goroutine for good. The process stayed up with no resolver,
// the DelegationSyncher waited for it forever, and every DS change a parent had
// to check was refused as unverifiable -- one root timeout at boot cost a
// restart.

const (
	imrInitFirstRetry = 5 * time.Second
	imrInitMaxRetry   = 2 * time.Minute
)

// imrInitRetryDelay is the wait before init attempt attempt+2: 5s, doubling,
// capped at two minutes.
func imrInitRetryDelay(attempt int) time.Duration {
	d := imrInitFirstRetry
	for i := 0; i < attempt && d < imrInitMaxRetry; i++ {
		d *= 2
	}
	if d > imrInitMaxRetry {
		d = imrInitMaxRetry
	}
	return d
}

// initImrEngineRetrying runs init until it succeeds or ctx is done. While it
// keeps failing, `config status` shows DEGRADED with the latest reason; the
// entry is cleared once the resolver is up. Returns nil on success, and the last
// init error if ctx ends first.
func (conf *Config) initImrEngineRetrying(ctx context.Context, init func() error, delay func(attempt int) time.Duration) error {
	for attempt := 0; ; attempt++ {
		err := init()
		if err == nil {
			if attempt > 0 {
				conf.Internal.ServerErrors.ClearImrPrimingError()
				lgImr.Info("IMR started after failed attempts", "attempts", attempt+1)
			}
			return nil
		}
		wait := delay(attempt)
		conf.Internal.ServerErrors.SetImrPrimingError(
			fmt.Sprintf("IMR did not start (no DNS listeners), retrying in %s: %v", wait, err))
		lgImr.Warn("InitImrEngine failed; will retry", "attempt", attempt+1, "retry-in", wait, "err", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
	}
}
