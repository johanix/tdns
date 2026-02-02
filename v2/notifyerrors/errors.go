/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared errors for NOTIFY handlers so that handlers can signal "handled but
 * responded with error" (e.g. decryption failed) without the framework logging
 * "NOTIFY handled successfully".
 */

package notifyerrors

import "errors"

// ErrNotifyHandlerErrorResponse is returned by a NOTIFY handler when it has
// already sent an error response (e.g. RcodeFormatError) to the client.
// The framework should treat the NOTIFY as handled and must not try the next
// handler or log "handled successfully".
var ErrNotifyHandlerErrorResponse = errors.New("notify handler sent error response")
