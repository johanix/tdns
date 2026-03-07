/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"fmt"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func (imr *Imr) SendRfc9567ErrorReport(ctx context.Context, qname string, qtype uint16, ede_code uint16, msgoptions *edns0.MsgOptions) error {
	if msgoptions == nil || !msgoptions.HasEROption || msgoptions.ErAgentDomain == "" {
		lgHandler.Debug("no ER option or agent domain, cannot send error report")
		return nil
	}
	if imr != nil {
		go func() {
			select {
			case <-ctx.Done():
				lgHandler.Debug("context cancelled before sending error report")
				return
			default:
			}
			report_qname := fmt.Sprintf("_er.%d.%s%d._er.%s", qtype, qname, ede_code, msgoptions.ErAgentDomain)
			lgHandler.Debug("sending RFC 9567 error report query", "qname", report_qname)
			ir, err := imr.ImrQuery(ctx, report_qname, dns.TypeTXT, dns.ClassINET, nil)
			if err != nil {
				lgHandler.Error("error from ImrQuery for error report", "err", err)
			} else {
				lgHandler.Debug("received response from error report ImrQuery", "response", ir)
			}
		}()
		return nil
	}
	lgHandler.Warn("ImrEngine not active, cannot send error report")
	return fmt.Errorf("imrEngine not active, cannot send error report")
}
