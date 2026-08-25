package tdns

import (
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// bigZone builds a zone file large enough that parsing it is not instantaneous,
// so a cancelled parse has something to abandon.
func bigZone(records int) string {
	var b strings.Builder
	b.WriteString("big.example.\t3600 IN SOA ns.big.example. hostmaster.big.example. 1 7200 1800 604800 7200\n")
	b.WriteString("big.example.\t3600 IN NS ns.big.example.\n")
	b.WriteString("ns.big.example.\t3600 IN A 192.0.2.1\n")
	for i := 0; i < records; i++ {
		b.WriteString("host")
		b.WriteString(strings.Repeat("x", 3))
		b.WriteString(itoa(i))
		b.WriteString(".big.example.\t3600 IN A 192.0.2.2\n")
	}
	return b.String()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}

func parseTestZone(t *testing.T) *ZoneData {
	t.Helper()
	return &ZoneData{
		ZoneName:  "big.example.",
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
	}
}

// Parsing a zone file is the longest uninterruptible stretch of a refresh, so a
// cancelled one must not sit in the parser until the file runs out.
func TestParseZoneFromReaderHonoursCancellation(t *testing.T) {
	zone := bigZone(20000)

	t.Run("already-cancelled context aborts the parse", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		zd := parseTestZone(t)
		done := make(chan error, 1)
		go func() {
			_, _, err := zd.ParseZoneFromReader(ctx, strings.NewReader(zone), true, "big.example")
			done <- err
		}()

		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a cancelled parse returned no error; it ran to completion")
			}
			if !strings.Contains(err.Error(), "abandoned") {
				t.Errorf("unexpected error: %v", err)
			}
			if !strings.Contains(err.Error(), "context canceled") {
				t.Errorf("the error does not carry the cancellation cause: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the parse did not return within 10s of a cancelled context")
		}
	})

	// The check must not cost a valid parse its result.
	t.Run("live context parses to completion", func(t *testing.T) {
		zd := parseTestZone(t)
		_, _, err := zd.ParseZoneFromReader(context.Background(), strings.NewReader(zone), true, "big.example")
		if err != nil {
			t.Fatalf("an uncancelled parse failed: %v", err)
		}
		if zd.Data.IsEmpty() {
			t.Error("an uncancelled parse produced no records")
		}
	})
}
