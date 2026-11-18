/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package imr

import (
	"context"
	"fmt"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func (imr *Imr) SendRfc9567ErrorReport(ctx context.Context, qname string, qtype uint16, ede_code uint16, msgoptions *edns0.MsgOptions) error {
	if msgoptions == nil || !msgoptions.HasEROption || msgoptions.ErAgentDomain == "" {
		lgImr.Debug("no ER option or agent domain, cannot send error report")
		return nil
	}
	if imr != nil {
		go func() {
			select {
			case <-ctx.Done():
				lgImr.Debug("context cancelled before sending error report")
				return
			default:
			}
			report_qname := fmt.Sprintf("_er.%d.%s%d._er.%s", qtype, qname, ede_code, msgoptions.ErAgentDomain)
			lgImr.Debug("sending RFC 9567 error report query", "qname", report_qname)
			ir, err := imr.imrQuery(ctx, report_qname, dns.TypeTXT, dns.ClassINET, nil, false)
			if err != nil {
				lgImr.Error("error from ImrQuery for error report", "err", err)
			} else {
				lgImr.Debug("received response from error report ImrQuery", "response", ir)
			}
		}()
		return nil
	}
	lgImr.Warn("ImrEngine not active, cannot send error report")
	return fmt.Errorf("imrEngine not active, cannot send error report")
}
