package stupidns

import (
	"fmt"
	"github.com/miekg/dns"
	"sync"
)

type StupiDNS struct {
	srv           dns.Server
	responseQueue []*dns.Msg
	wg            sync.WaitGroup
}

func (s *StupiDNS) handler(w dns.ResponseWriter, r *dns.Msg) {
	if len(s.responseQueue) == 0 {
		panic("No responses left in queue")
	}

	m := s.responseQueue[0]

	/* Make sure response has the same Message Id as the request */
	m.MsgHdr.Id = r.MsgHdr.Id

	/* include question */
	m.Question = r.Question

	err := w.WriteMsg(m)
	if err != nil {
		panic(fmt.Sprintf("Error while responding: %s", err))
	}

	/* Discard first message, it has been sent */
	s.responseQueue = s.responseQueue[1:]
}

func Create(addr string) StupiDNS {
	var s StupiDNS
	s.srv = dns.Server{}
	s.srv.Net = "tcp"
	s.srv.Addr = addr

	s.responseQueue = make([]*dns.Msg, 0)

	return s
}

func (s *StupiDNS) Serve() {
	/* Updates to "s" will not affect "Handler" beyond this point. */
	s.srv.Handler = dns.HandlerFunc(s.handler)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := s.srv.ListenAndServe()

		if err != nil {
			panic(fmt.Sprintf("Error while serving: %s", err))
		}
	}()
}

func (s *StupiDNS) AddToQueue(rrs ...string) {
	m := new(dns.Msg)
	m.Answer = make([]dns.RR, len(rrs))

	for i, r := range rrs {
		rr, err := dns.NewRR(r)
		if err != nil {
			panic("Oh no, could not create list!")
		}
		m.Answer[i] = rr
	}

	m.Response = true
	m.Opcode = 0

	s.responseQueue = append(s.responseQueue, m)
}

func (s *StupiDNS) Shutdown() {
	s.responseQueue = nil
	s.srv.Shutdown()
	s.wg.Wait()
}
