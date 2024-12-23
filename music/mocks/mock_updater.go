// Install testify if you haven't already
// go get github.com/stretchr/testify

package mocks

import (
	"github.com/johanix/tdns/music"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
)

// MockUpdater is a mock implementation of the Updater interface
type MockUpdater struct {
	mock.Mock
}

// Verify that MockUpdater implements music.Updater (from CodeRabbit)
var _ music.Updater = (*MockUpdater)(nil)

func (m *MockUpdater) FetchRRset(signer *music.Signer, zoneName, owner string, rrtype uint16) (error, []dns.RR) {
	args := m.Called(signer, zoneName, owner, rrtype)
	var rrs []dns.RR
	if rr := args.Get(1); rr != nil {
		rrs = rr.([]dns.RR)
	}
	return args.Error(0), rrs
}

func (m *MockUpdater) RemoveRRset(signer *music.Signer, zoneName, owner string, rrsets [][]dns.RR) error {
	args := m.Called(signer, zoneName, owner, rrsets)
	return args.Error(0)
}

func (m *MockUpdater) Update(signer *music.Signer, zoneName, owner string, inserts, removes *[][]dns.RR) error {
	args := m.Called(signer, zoneName, owner, inserts, removes)
	return args.Error(0)
}

func (m *MockUpdater) SetChannels(fetch, update chan music.SignerOp) {
	m.Called(fetch, update)
}

func (m *MockUpdater) SetApi(api music.Api) {
	m.Called(api)
}

func (m *MockUpdater) GetApi() music.Api {
	if api := m.Called().Get(0); api != nil {
		return api.(music.Api)
	}
	return nil
}
