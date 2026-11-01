package vpn

import (
	"testing"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	wgfake "github.com/angelfreak/net/pkg/wgconfig/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wgKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// skovenConfig mirrors the real-world split-tunnel config that motivated this:
// MTU and DNS under [Interface] were previously parsed and silently dropped.
const skovenConfig = `[Interface]
PrivateKey = ` + wgKey + `
MTU = 1380
DNS = 10.77.0.1, orisonnet

[Peer]
PublicKey = ` + wgKey + `
Endpoint = 192.0.2.1:51830
AllowedIPs = 10.77.0.0/24, 10.78.0.0/16
PersistentKeepalive = 25
`

func newWGTestManager(t *testing.T, links *fake.LinkManager, net types.NetworkManager) *Manager {
	t.Helper()
	return &Manager{
		routeMgr:   newFakeRoutes(),
		addrMgr:    newFakeAddrs(),
		linkMgr:    links,
		networkMgr: net,
		wgConfig:   wgfake.New(),
		executor:   &mockSystemExecutor{commands: map[string]string{}},
		logger:     &mockLogger{},
		runtimeDir: t.TempDir(),
	}
}

func TestConnectWireGuard_AppliesMTU(t *testing.T) {
	links := newFakeLinks()
	m := newWGTestManager(t, links, &fakeNetworkManager{})

	err := m.connectWireGuard(&types.VPNConfig{
		Config: skovenConfig, Interface: "wg0", Address: "10.77.0.13/32",
	}, "192.168.1.1", "eth0")
	require.NoError(t, err)

	require.Len(t, links.SetMTUCalls, 1, "MTU from the config block must reach the link")
	assert.Equal(t, "wg0", links.SetMTUCalls[0].Iface)
	assert.Equal(t, 1380, links.SetMTUCalls[0].MTU)
}

// The MTU must be set while the link is still down, before SetUp, so the
// interface never carries traffic at the wrong MTU.
func TestConnectWireGuard_MTUSetBeforeLinkUp(t *testing.T) {
	links := newFakeLinks()
	m := newWGTestManager(t, links, &fakeNetworkManager{})

	require.NoError(t, m.connectWireGuard(&types.VPNConfig{
		Config: skovenConfig, Interface: "wg0",
	}, "192.168.1.1", "eth0"))

	require.Len(t, links.SetMTUCalls, 1)
	require.Len(t, links.Upped, 1, "link must be brought up exactly once")
	assert.Equal(t, []string{"wg0"}, links.AddedWG, "MTU applies to the created link")
}

// A config without MTU must behave byte-identically to before: no SetMTU call.
func TestConnectWireGuard_NoMTUKeyIsNoOp(t *testing.T) {
	links := newFakeLinks()
	m := newWGTestManager(t, links, &fakeNetworkManager{})

	require.NoError(t, m.connectWireGuard(&types.VPNConfig{
		Config:    "[Interface]\nPrivateKey = " + wgKey + "\n\n[Peer]\nPublicKey = " + wgKey + "\nAllowedIPs = 0.0.0.0/0\n",
		Interface: "wg0",
	}, "192.168.1.1", "eth0"))

	assert.Empty(t, links.SetMTUCalls, "no MTU key must mean no MTU call")
}

// A failing SetMTU must not leave a half-configured interface behind, matching
// how the sibling address/up failures clean up.
func TestConnectWireGuard_MTUFailureCleansUp(t *testing.T) {
	links := newFakeLinks()
	links.SetMTUErr = assert.AnError
	m := newWGTestManager(t, links, &fakeNetworkManager{})

	err := m.connectWireGuard(&types.VPNConfig{
		Config: skovenConfig, Interface: "wg0",
	}, "192.168.1.1", "eth0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "MTU")
	assert.Equal(t, []string{"wg0"}, links.Deleted, "failed connect must delete the interface")
}

// An invalid MTU is a config error and must fail before touching the link.
func TestConnectWireGuard_InvalidMTUFailsEarly(t *testing.T) {
	links := newFakeLinks()
	m := newWGTestManager(t, links, &fakeNetworkManager{})

	err := m.connectWireGuard(&types.VPNConfig{
		Config:    "[Interface]\nPrivateKey = " + wgKey + "\nMTU = 70000\n\n[Peer]\nPublicKey = " + wgKey + "\nAllowedIPs = 0.0.0.0/0\n",
		Interface: "wg0",
	}, "192.168.1.1", "eth0")

	require.Error(t, err)
	assert.Empty(t, links.AddedWG, "invalid config must fail before creating the link")
}

// fakeNetworkManager records DNS calls and satisfies types.NetworkManager.
// Only the DNS methods are exercised here; the rest are unused stubs.
type fakeNetworkManager struct {
	current   []string   // what GetDNS reports
	SetCalls  [][]string // every SetDNS invocation, in order
	GetErr    error
	SetDNSErr error
}

func (f *fakeNetworkManager) SetDNS(servers []string) error {
	if f.SetDNSErr != nil {
		return f.SetDNSErr
	}
	f.SetCalls = append(f.SetCalls, servers)
	f.current = servers
	return nil
}

func (f *fakeNetworkManager) GetDNS() ([]string, error) {
	if f.GetErr != nil {
		return nil, f.GetErr
	}
	return f.current, nil
}

func (f *fakeNetworkManager) ClearDNS() error                                     { return nil }
func (f *fakeNetworkManager) ClearDNSIfOwned() (bool, error)                      { return false, nil }
func (f *fakeNetworkManager) LockDNS()                                            {}
func (f *fakeNetworkManager) SetMAC(iface, mac string) error                      { return nil }
func (f *fakeNetworkManager) GetMAC(iface string) (string, error)                 { return "", nil }
func (f *fakeNetworkManager) SetIP(iface, addr, gateway string, metric int) error { return nil }
func (f *fakeNetworkManager) AddRoute(iface, destination, gateway string) error   { return nil }
func (f *fakeNetworkManager) FlushRoutes(iface string) error                      { return nil }
func (f *fakeNetworkManager) StartDHCP(iface string, hostname string) error       { return nil }
func (f *fakeNetworkManager) DHCPRenew(iface string, hostname string) error       { return nil }
func (f *fakeNetworkManager) ConnectToConfiguredNetwork(config *types.NetworkConfig, password string, wifiMgr types.WiFiManager) error {
	return nil
}
func (f *fakeNetworkManager) GetConnectionInfo(iface string) (*types.Connection, error) {
	return nil, nil
}
func (f *fakeNetworkManager) Disconnect(iface string) error { return nil }
func (f *fakeNetworkManager) DisconnectAll() []string       { return nil }

var _ types.NetworkManager = (*fakeNetworkManager)(nil)
