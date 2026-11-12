package vpn

import (
	"context"
	"os"
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
func (f *fakeNetworkManager) UnlockDNS() error                                    { return nil }
func (f *fakeNetworkManager) PinDNSRoutes(iface string)                           {}
func (f *fakeNetworkManager) SetMAC(iface, mac string) error                      { return nil }
func (f *fakeNetworkManager) GetMAC(iface string) (string, error)                 { return "", nil }
func (f *fakeNetworkManager) SetIP(iface, addr, gateway string, metric int) error { return nil }
func (f *fakeNetworkManager) AddRoute(iface, destination, gateway string) error   { return nil }
func (f *fakeNetworkManager) FlushRoutes(iface string) error                      { return nil }
func (f *fakeNetworkManager) StartDHCP(_ context.Context, iface string, hostname string) error {
	return nil
}
func (f *fakeNetworkManager) DHCPRenew(iface string, hostname string) error { return nil }
func (f *fakeNetworkManager) ConnectToConfiguredNetwork(_ context.Context, config *types.NetworkConfig, password string, wifiMgr types.WiFiManager) error {
	return nil
}
func (f *fakeNetworkManager) GetConnectionInfo(iface string) (*types.Connection, error) {
	return nil, nil
}
func (f *fakeNetworkManager) Disconnect(iface string) error { return nil }
func (f *fakeNetworkManager) DisconnectAll() []string       { return nil }

var _ types.NetworkManager = (*fakeNetworkManager)(nil)

// --- VPN-provided DNS ---

func TestConnectWireGuard_AppliesDNS(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"1.1.1.1"}}
	m := newWGTestManager(t, newFakeLinks(), netMgr)

	require.NoError(t, m.connectWireGuard(&types.VPNConfig{
		Config: skovenConfig, Interface: "wg0",
	}, "192.168.1.1", "eth0"))

	require.Len(t, netMgr.SetCalls, 1, "DNS from the config block must reach resolv.conf")
	assert.Equal(t, []string{"10.77.0.1", "orisonnet"}, netMgr.SetCalls[0])
}

// The pre-VPN resolver must be captured so disconnect can restore it.
func TestConnectWireGuard_RecordsPriorDNS(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"1.1.1.1", "8.8.8.8"}}
	m := newWGTestManager(t, newFakeLinks(), netMgr)

	require.NoError(t, m.connectWireGuard(&types.VPNConfig{
		Config: skovenConfig, Interface: "wg0",
	}, "192.168.1.1", "eth0"))

	assert.Equal(t, "1.1.1.1,8.8.8.8", m.originalDNS)
}

// A config without DNS must behave byte-identically to before: no SetDNS call.
func TestConnectWireGuard_NoDNSKeyIsNoOp(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"1.1.1.1"}}
	m := newWGTestManager(t, newFakeLinks(), netMgr)

	require.NoError(t, m.connectWireGuard(&types.VPNConfig{
		Config:    "[Interface]\nPrivateKey = " + wgKey + "\n\n[Peer]\nPublicKey = " + wgKey + "\nAllowedIPs = 0.0.0.0/0\n",
		Interface: "wg0",
	}, "192.168.1.1", "eth0"))

	assert.Empty(t, netMgr.SetCalls, "no DNS key must mean no DNS call")
	assert.Empty(t, m.originalDNS)
}

// DNS is a convenience, not the tunnel: a failure must not fail the connect.
func TestConnectWireGuard_DNSFailureIsNonFatal(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"1.1.1.1"}, SetDNSErr: assert.AnError}
	links := newFakeLinks()
	m := newWGTestManager(t, links, netMgr)

	err := m.connectWireGuard(&types.VPNConfig{
		Config: skovenConfig, Interface: "wg0",
	}, "192.168.1.1", "eth0")

	require.NoError(t, err, "a DNS failure must leave the tunnel up")
	assert.Empty(t, links.Deleted, "the interface must survive a DNS failure")
	assert.Empty(t, m.originalDNS, "a failed apply must not claim DNS to restore")
}

// With no NetworkManager injected, DNS handling is skipped rather than panicking.
func TestConnectWireGuard_NilNetworkManagerSkipsDNS(t *testing.T) {
	m := newWGTestManager(t, newFakeLinks(), nil)
	m.networkMgr = nil

	require.NoError(t, m.connectWireGuard(&types.VPNConfig{
		Config: skovenConfig, Interface: "wg0",
	}, "192.168.1.1", "eth0"))
}

func TestRestoreDNS_PutsBackPriorServers(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"10.77.0.1"}}
	m := newWGTestManager(t, newFakeLinks(), netMgr)

	m.restoreDNS(&vpnState{OriginalDNS: "1.1.1.1,8.8.8.8"})

	require.Len(t, netMgr.SetCalls, 1)
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, netMgr.SetCalls[0])
}

// When the VPN never set DNS there is nothing to restore; resolv.conf must be
// left strictly alone so `net stop` doesn't clobber the network's own DNS.
func TestRestoreDNS_NoOpWhenVPNDidNotSetDNS(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"1.1.1.1"}}
	m := newWGTestManager(t, newFakeLinks(), netMgr)

	m.restoreDNS(&vpnState{OriginalDNS: ""})
	m.restoreDNS(nil)

	assert.Empty(t, netMgr.SetCalls)
}

// --- state file round-trip ---

func TestVPNState_DNSRoundTrip(t *testing.T) {
	m := newWGTestManager(t, newFakeLinks(), &fakeNetworkManager{})

	require.NoError(t, m.setActiveVPNState(vpnState{
		Name: "skoven", Interface: "wg0", Type: "wireguard",
		OriginalGateway: "192.168.1.1", OriginalInterface: "eth0",
		EndpointRoute: "192.0.2.1", OriginalDNS: "1.1.1.1,8.8.8.8",
	}))

	got := m.getActiveVPNState()
	require.NotNil(t, got)
	assert.Equal(t, "1.1.1.1,8.8.8.8", got.OriginalDNS)
	assert.Equal(t, "192.0.2.1", got.EndpointRoute)
}

// A state file written before OriginalDNS existed (6 fields) must still load.
func TestVPNState_BackwardCompatibleWithSixFields(t *testing.T) {
	m := newWGTestManager(t, newFakeLinks(), &fakeNetworkManager{})
	require.NoError(t, os.WriteFile(m.activeVPNFilePath(),
		[]byte("skoven|wg0|wireguard|192.168.1.1|eth0|192.0.2.1"), 0600))

	got := m.getActiveVPNState()
	require.NotNil(t, got)
	assert.Equal(t, "skoven", got.Name)
	assert.Equal(t, "192.0.2.1", got.EndpointRoute)
	assert.Empty(t, got.OriginalDNS, "absent field must read as empty, not garbage")
}

// Disconnect must restore DNS through the real Disconnect path, reading the
// state file the way a separate process would. A direct restoreDNS test cannot
// catch the helper being left unwired.
func TestDisconnect_RestoresDNSFromStateFile(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"10.77.0.1"}}
	m := NewManagerWithDir(&mockSystemExecutor{commands: map[string]string{}},
		&mockLogger{}, &mockConfigManager{}, t.TempDir())
	m.routeMgr = newFakeRoutes()
	m.addrMgr = newFakeAddrs()
	m.linkMgr = newFakeLinks()
	m.networkMgr = netMgr

	// State as written by a previous process's Connect.
	require.NoError(t, m.setActiveVPNState(vpnState{
		Name: "skoven", Interface: "wg0", Type: "wireguard",
		OriginalGateway: "192.168.1.1", OriginalInterface: "eth0",
		OriginalDNS: "1.1.1.1",
	}))

	require.NoError(t, m.Disconnect(""))

	require.Len(t, netMgr.SetCalls, 1, "Disconnect must restore the pre-VPN DNS")
	assert.Equal(t, []string{"1.1.1.1"}, netMgr.SetCalls[0])
}

// Switching VPNs must restore the old VPN's DNS before the new one applies its
// own, so the pre-VPN resolver is never lost across a switch.
func TestConnect_SwitchRestoresPreviousVPNDNS(t *testing.T) {
	netMgr := &fakeNetworkManager{current: []string{"10.77.0.1"}}
	m := NewManagerWithDir(&mockSystemExecutor{commands: map[string]string{}},
		&mockLogger{}, &mockConfigManager{}, t.TempDir())
	m.routeMgr = newFakeRoutes()
	m.addrMgr = newFakeAddrs()
	m.linkMgr = newFakeLinks()
	m.networkMgr = netMgr

	require.NoError(t, m.setActiveVPNState(vpnState{
		Name: "skoven", Interface: "wg0", Type: "wireguard",
		OriginalDNS: "1.1.1.1",
	}))

	// Connecting a different VPN tears down the old one first.
	_ = m.Connect("other")

	require.NotEmpty(t, netMgr.SetCalls, "a VPN switch must restore the prior DNS")
	assert.Equal(t, []string{"1.1.1.1"}, netMgr.SetCalls[0])
}
