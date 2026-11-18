/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// The client handler answers a query without a question with FORMERR instead
// of reading an empty question section.
func TestImrHandlerAnswersFormerrWithoutQuestion(t *testing.T) {
	imr := verdictImr(t, false)
	h := imr.createImrHandler(context.Background(), &Config{})
	cw := &captureWriter{}
	r := new(dns.Msg)
	r.Id = 4711
	h(cw, r)
	if cw.got == nil {
		t.Fatal("the handler wrote nothing")
	}
	if cw.got.Rcode != dns.RcodeFormatError || cw.got.Id != 4711 || !cw.got.Response {
		t.Fatalf("got rcode %s id %d response %v, want FORMERR to id 4711",
			dns.RcodeToString[cw.got.Rcode], cw.got.Id, cw.got.Response)
	}
}
