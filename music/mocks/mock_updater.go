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

func (m *MockUpdater) FetchRRset(signer *music.Signer, zoneName, owner string, rrtype uint16) (error, []dns.RR) {
	args := m.Called(signer, zoneName, owner, rrtype)
	return args.Error(0), args.Get(1).([]dns.RR)
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
	return m.Called().Get(0).(music.Api)
}
