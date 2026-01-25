/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Common types and errors for crypto abstraction layer
 */

package crypto

import (
	"errors"
	"fmt"
)

// Common errors
var (
	// ErrUnsupportedBackend indicates the requested backend is not registered
	ErrUnsupportedBackend = errors.New("unsupported crypto backend")

	// ErrInvalidKey indicates a key is malformed or invalid
	ErrInvalidKey = errors.New("invalid key")

	// ErrEncryptionFailed indicates encryption operation failed
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed indicates decryption operation failed
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrBackendMismatch indicates a key from one backend was used with another
	ErrBackendMismatch = errors.New("crypto backend mismatch")
)

// BackendError wraps backend-specific errors with context
type BackendError struct {
	Backend string
	Op      string // Operation that failed (e.g., "encrypt", "decrypt", "parse_key")
	Err     error
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("%s backend %s: %v", e.Backend, e.Op, e.Err)
}

func (e *BackendError) Unwrap() error {
	return e.Err
}

// NewBackendError creates a new BackendError
func NewBackendError(backend, op string, err error) error {
	return &BackendError{
		Backend: backend,
		Op:      op,
		Err:     err,
	}
}
