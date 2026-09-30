/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The resolver's data time, and a test clock for it.
 * docs/2026-09-28-imr-deckard-test-clock-and-switches.md §3.
 */
package cache

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The resolver reads the clock for two reasons, and only one of them may
// follow a test clock.
//
// Data time is compared with DNS data: an RRSIG's inception and expiration,
// a cache entry's expiry and the TTL served from it, the TTL cap to a
// signature's expiry, a verdict's age, a server address's expiry. It is read
// through Now.
//
// Elapsed time measures the resolver's own work: query timeouts, RTT samples,
// backoffs, cool-downs, timers, statistics. It stays on time.Now. A test that
// moves the clock an hour ahead must not time out every query in flight, nor
// lift every backoff at once.
//
// A data-time value must not be compared with a time.Now value: under a test
// clock the two are decades apart.

// dataClock is the test clock in use, or nil for real time.
var dataClock atomic.Pointer[FileClock]

// Now is the resolver's data time: time.Now, unless a test clock is set.
func Now() time.Time {
	if c := dataClock.Load(); c != nil {
		return c.Now()
	}
	return time.Now()
}

// Until is time.Until in data time.
func Until(t time.Time) time.Duration {
	return t.Sub(Now())
}

// SetDataClock makes c the source of data time. nil restores real time.
func SetDataClock(c *FileClock) {
	dataClock.Store(c)
}

// DataClock returns the test clock in use, or nil.
func DataClock() *FileClock {
	return dataClock.Load()
}

// faketimeLayout is the time in a libfaketime timestamp file after its "@".
const faketimeLayout = "2006-01-02 15:04:05"

// ParseFaketime parses the content of a libfaketime timestamp file in the one
// form Deckard writes: "@YYYY-MM-DD HH:MM:SS", in local time, with trailing
// whitespace allowed. Any other form is an error.
func ParseFaketime(s string) (time.Time, error) {
	s = strings.TrimRight(s, " \t\r\n")
	if !strings.HasPrefix(s, "@") {
		return time.Time{}, fmt.Errorf("faketime %q: want \"@YYYY-MM-DD HH:MM:SS\"", s)
	}
	t, err := time.ParseInLocation(faketimeLayout, s[1:], time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("faketime %q: want \"@YYYY-MM-DD HH:MM:SS\": %w", s, err)
	}
	return t, nil
}

// FileClock is data time read from a libfaketime timestamp file, the way a
// process under libfaketime's start-at ("@") mode sees it: the file's time
// plus the real time elapsed since the clock started. Deckard fakes the time
// of the resolver it tests this way, and libfaketime cannot reach a Go binary,
// so the resolver reads the file itself.
//
// The file is checked on every read and parsed again when it has changed.
// Deckard moves time forward by replacing it (TIME_PASSES): the new file time
// takes effect, and the real-time part runs on.
type FileClock struct {
	path  string
	start time.Time // real time when the clock started, with its monotonic reading

	mu     sync.Mutex
	base   time.Time   // the time in the file
	info   os.FileInfo // the file as it was when base was read
	failed bool        // a failure to re-read has been logged
}

// NewFileClock starts a clock from the timestamp file at path. The file must
// exist and parse.
func NewFileClock(path string) (*FileClock, error) {
	if path == "" {
		return nil, fmt.Errorf("no faketime timestamp file named")
	}
	c := &FileClock{path: path, start: time.Now()}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	base, err := readFaketime(path)
	if err != nil {
		return nil, err
	}
	c.base, c.info = base, info
	return c, nil
}

// Path is the timestamp file the clock reads.
func (c *FileClock) Path() string {
	return c.path
}

// Now is the file's time plus the real time elapsed since the clock started.
// It carries no monotonic reading, so it compares by the wall clock only.
func (c *FileClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked()
	return c.base.Add(time.Since(c.start)).Round(0)
}

// refreshLocked reads the file again if it has changed: another file in its
// place, or a new modification time or size. A file that can no longer be
// read or parsed leaves the last time in force, and is logged once.
func (c *FileClock) refreshLocked() {
	info, err := os.Stat(c.path)
	if err == nil && os.SameFile(info, c.info) && info.ModTime().Equal(c.info.ModTime()) && info.Size() == c.info.Size() {
		return
	}
	var base time.Time
	if err == nil {
		base, err = readFaketime(c.path)
	}
	if err != nil {
		if !c.failed {
			log.Printf("faketime: keeping %s: %v", c.base.Format(faketimeLayout), err)
			c.failed = true
		}
		return
	}
	c.base, c.info, c.failed = base, info, false
}

func readFaketime(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	return ParseFaketime(string(data))
}
