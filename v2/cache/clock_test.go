/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFaketime replaces the timestamp file the way Deckard does: a new file
// renamed into place.
func writeFaketime(t *testing.T, path string, at time.Time) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("@"+at.Format(faketimeLayout)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// useFaketime starts a test clock at at, as data time, until the test ends.
func useFaketime(t *testing.T, at time.Time) (*FileClock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".time")
	writeFaketime(t, path, at)
	c, err := NewFileClock(path)
	if err != nil {
		t.Fatalf("NewFileClock: %v", err)
	}
	SetDataClock(c)
	t.Cleanup(func() { SetDataClock(nil) })
	return c, path
}

// near reports whether got is want, or up to slack after it.
func near(got, want time.Time, slack time.Duration) bool {
	return !got.Before(want) && got.Sub(want) <= slack
}

var faketime2010 = time.Date(2010, 3, 4, 5, 6, 7, 0, time.Local)

func TestParseFaketime(t *testing.T) {
	for _, s := range []string{"@2010-03-04 05:06:07", "@2010-03-04 05:06:07\n", "@2010-03-04 05:06:07 \r\n"} {
		got, err := ParseFaketime(s)
		if err != nil || !got.Equal(faketime2010) {
			t.Errorf("ParseFaketime(%q) = %v, %v; want %v", s, got, err, faketime2010)
		}
	}
	for _, s := range []string{"", "2010-03-04 05:06:07", "@2010-03-04T05:06:07", "@2010-03-04", "+3600", "@yesterday"} {
		if got, err := ParseFaketime(s); err == nil {
			t.Errorf("ParseFaketime(%q) = %v; want an error", s, got)
		}
	}
}

// Without a test clock, data time is real time.
func TestNowIsRealTimeWithoutAClock(t *testing.T) {
	SetDataClock(nil)
	before := time.Now()
	got := Now()
	if !near(got, before, time.Second) {
		t.Errorf("Now() = %v, want real time near %v", got, before)
	}
}

// The clock is the file's time plus the real time since it started, a
// replaced file takes effect without a restart, and its times carry no
// monotonic reading.
func TestFileClockFollowsTheFile(t *testing.T) {
	c, path := useFaketime(t, faketime2010)
	if got := Now(); !near(got, faketime2010, 2*time.Second) {
		t.Fatalf("Now() = %v, want about %v", got, faketime2010)
	}
	if s := Now().String(); strings.Contains(s, "m=") {
		t.Errorf("Now() carries a monotonic reading: %s", s)
	}

	time.Sleep(50 * time.Millisecond)
	if got := Now(); !got.After(faketime2010) {
		t.Errorf("Now() = %v: real time elapsed is not added", got)
	}

	writeFaketime(t, path, faketime2010.Add(time.Hour))
	if got := c.Now(); !near(got, faketime2010.Add(time.Hour), 2*time.Second) {
		t.Errorf("after moving the file an hour on, Now() = %v, want about %v", got, faketime2010.Add(time.Hour))
	}
}

// A file rewritten in place is noticed as well, by its modification time.
func TestFileClockNoticesARewriteInPlace(t *testing.T) {
	_, path := useFaketime(t, faketime2010)
	later := faketime2010.Add(24 * time.Hour)
	if err := os.WriteFile(path, []byte("@"+later.Format(faketimeLayout)), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if got := Now(); !near(got, later, 2*time.Second) {
		t.Errorf("Now() = %v, want about %v", got, later)
	}
}

// A file that goes away or turns unreadable leaves the last time in force.
func TestFileClockKeepsItsTimeWhenTheFileGoesBad(t *testing.T) {
	_, path := useFaketime(t, faketime2010)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := Now(); !near(got, faketime2010, 2*time.Second) {
		t.Errorf("file removed: Now() = %v, want about %v", got, faketime2010)
	}
	if err := os.WriteFile(path, []byte("tomorrow"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Now(); !near(got, faketime2010, 2*time.Second) {
		t.Errorf("file unparseable: Now() = %v, want about %v", got, faketime2010)
	}
}

func TestNewFileClockNeedsAReadableFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("2010-03-04 05:06:07"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", filepath.Join(dir, "missing"), bad} {
		if _, err := NewFileClock(path); err == nil {
			t.Errorf("NewFileClock(%q): no error", path)
		}
	}
}
