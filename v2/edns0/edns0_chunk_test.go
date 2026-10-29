package edns0

import (
	"bytes"
	"errors"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// chunkTestData is n bytes of base64 text, like the transport's payloads.
func chunkTestData(n int) []byte {
	return bytes.Repeat([]byte("QUJD"), n/4+1)[:n]
}

// TestChunkOptionRefusesDataItCannotHold: data that one option cannot hold
// gets ErrChunkOptionTooLarge. The first four sizes are payloads that went
// out cut (#987): 69132 bytes of data were sent as their first 3596.
func TestChunkOptionRefusesDataItCannotHold(t *testing.T) {
	for _, n := range []int{69132, 66700, 66288, 66292, 65536, maxChunkOptionLen - 5 + 1} {
		opt, err := CreateChunkOption(2, nil, chunkTestData(n))
		if !errors.Is(err, ErrChunkOptionTooLarge) {
			got := -1
			if opt != nil {
				got = len(opt.Data)
			}
			t.Errorf("%d bytes of data: err %v, an option of %d bytes; want ErrChunkOptionTooLarge", n, err, got)
		}
	}

	hmac := make([]byte, 32)
	if _, err := CreateChunkOption(2, hmac, chunkTestData(maxChunkOptionLen-5-len(hmac)+1)); !errors.Is(err, ErrChunkOptionTooLarge) {
		t.Errorf("data and HMAC one byte over: err %v; want ErrChunkOptionTooLarge", err)
	}
}

// TestChunkOptionCarriesAllItsData: data up to the limit comes back whole,
// with and without an HMAC.
func TestChunkOptionCarriesAllItsData(t *testing.T) {
	hmac := bytes.Repeat([]byte{0xab}, 32)
	for _, c := range []struct {
		hmac []byte
		n    int
	}{
		{nil, 0},
		{nil, 64396},
		{nil, maxChunkOptionLen - 5},
		{hmac, maxChunkOptionLen - 5 - len(hmac)},
	} {
		data := chunkTestData(c.n)
		opt, err := CreateChunkOption(2, c.hmac, data)
		if err != nil {
			t.Fatalf("%d bytes of data, %d of HMAC: %v", c.n, len(c.hmac), err)
		}
		got, err := ParseChunkOption(opt)
		if err != nil {
			t.Fatalf("%d bytes of data, %d of HMAC: parse: %v", c.n, len(c.hmac), err)
		}
		if got.Format != 2 || !bytes.Equal(got.HMAC, c.hmac) || !bytes.Equal(got.Data, data) {
			t.Errorf("%d bytes of data, %d of HMAC: got format %d, %d bytes of HMAC, %d of data",
				c.n, len(c.hmac), got.Format, len(got.HMAC), len(got.Data))
		}
	}
}

// TestChunkOptionInAMessage: a NOTIFY carrying the largest payload that
// arrived whole (64396 bytes) packs and unpacks with all of it.
func TestChunkOptionInAMessage(t *testing.T) {
	data := chunkTestData(64396)
	opt, err := CreateChunkOption(2, nil, data)
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetNotify("6ae3a583.agent.example.")
	m.Question = []dns.Question{{Name: "6ae3a583.agent.example.", Qtype: core.TypeCHUNK, Qclass: dns.ClassINET}}
	m.SetEdns0(4096, true)
	m.IsEdns0().Option = append(m.IsEdns0().Option, opt)

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	got, ok := ExtractChunkOption(r.IsEdns0())
	if !ok {
		t.Fatal("no CHUNK option in the unpacked message")
	}
	if !bytes.Equal(got.Data, data) {
		t.Errorf("got %d bytes of data, want %d", len(got.Data), len(data))
	}
}
