/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bootstrap-configure library: file I/O primitives.
 *
 * Atomic write with unconditional timestamped backup of any
 * existing file. Called from the orchestrator only after the
 * user has confirmed a previewed diff.
 *
 * App-level code generally does not call AtomicWrite directly —
 * the orchestrator in run.go does — but ReadFileIfExists and
 * ValidateYAML are useful primitives for apps that need to parse
 * existing configs to seed their interview.
 */
package configure

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ReadFileIfExists returns the file contents, or ("", nil) if
// the path does not exist. Other errors are returned as-is.
func ReadFileIfExists(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}

// ValidateYAML returns nil if the content parses as a YAML
// document. Used as a sanity gate before any atomic write.
func ValidateYAML(content string) error {
	var any interface{}
	return yaml.Unmarshal([]byte(content), &any)
}

// backupPath returns the timestamped backup path for a given
// config file. Format: foo.yaml.bak.2026-04-21T14-03-22.
func backupPath(path string, now time.Time) string {
	stamp := now.UTC().Format("2006-01-02T15-04-05")
	return path + ".bak." + stamp
}

// atomicWrite validates `content` as YAML, writes it to a
// tempfile in the same directory, then renames into place.
//
// If `path` already exists it is renamed to a timestamped backup
// first. Returns the backup path (empty if no prior file).
func atomicWrite(path, content string) (backup string, err error) {
	if parseErr := ValidateYAML(content); parseErr != nil {
		return "", fmt.Errorf("refuse to write invalid YAML to %s: %w", path, parseErr)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create tempfile in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write tempfile: %w", err)
	}
	if err = tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod tempfile: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("close tempfile: %w", err)
	}

	if _, statErr := os.Stat(path); statErr == nil {
		backup = backupPath(path, time.Now())
		if err = os.Rename(path, backup); err != nil {
			return "", fmt.Errorf("backup %s → %s: %w", path, backup, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("stat %s: %w", path, statErr)
	}

	if err = os.Rename(tmpName, path); err != nil {
		// Best-effort restore of the original file so a failed
		// write does not leave the path empty.
		if backup != "" {
			if restoreErr := os.Rename(backup, path); restoreErr != nil {
				return backup, fmt.Errorf("rename %s → %s: %w (also failed to restore from %s: %v)", tmpName, path, err, backup, restoreErr)
			}
			backup = ""
		}
		return backup, fmt.Errorf("rename %s → %s: %w", tmpName, path, err)
	}
	return backup, nil
}
