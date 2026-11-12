package network

import (
	"context"
	"os"
	"testing"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A guest network handed out DNS server 172.18.4.50, reachable only through
// its gateway. A local Docker bridge owned 172.18.0.0/16, so the kernel sent
// every DNS query into the bridge and the captive portal never resolved.
// These routes reproduce that table.
func shadowedRoutes(iface string) *fake.RouteManager {
	return &fake.RouteManager{Routes: []types.Route{
		{Gw: "100.68.8.1", Iface: iface},
		{Dst: "100.68.8.0/21", Iface: iface},
		{Dst: "172.18.0.0/16", Iface: "br-7ec5a75d86c2"},
	}}
}

// connectWithLease runs the real connect path for config, with a DHCP client
// that writes resolvConf the way a lease does.
func connectWithLease(t *testing.T, routes *fake.RouteManager, config *types.NetworkConfig, resolvConf string) {
	t.Helper()
	manager := newSeamTestManager(t)
	manager.routeMgr = routes
	lease := func() {
		// Connecting flushes the interface's routes; the lease installs them.
		leased := shadowedRoutes(config.Interface).Routes[:2]
		kept := routes.Routes[:0:0]
		for _, r := range routes.Routes {
			if r.Iface != config.Interface {
				kept = append(kept, r)
			}
		}
		routes.Routes = append(kept, leased...)
		require.NoError(t, os.WriteFile(manager.resolvConf(), []byte(resolvConf), 0644))
	}
	wifi := &mockWiFiManagerImpl{onConnect: func() error { lease(); return nil }}
	manager.dhcpClient = &scriptedDHCPClient{onAcquire: lease}
	require.NoError(t, manager.ConnectToConfiguredNetwork(context.Background(), config, "", wifi))
}

func TestConnectToConfiguredNetwork_ShadowedDHCPDNSIsRoutedViaConnectedInterface(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *types.NetworkConfig
	}{
		{"wifi, dns: dhcp", &types.NetworkConfig{Interface: "wlan0", SSID: "RegHGaest", DNS: []string{"dhcp"}}},
		{"wifi, no dns configured", &types.NetworkConfig{Interface: "wlan0", SSID: "RegHGaest"}},
		{"wired, dns: dhcp", &types.NetworkConfig{Interface: "eth0", DNS: []string{"dhcp"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := shadowedRoutes(tc.config.Interface)
			connectWithLease(t, routes, tc.config, "domain gaest.regionh.dk\nnameserver 172.18.4.50\n")
			assert.Equal(t,
				[]fake.AddCall{{Iface: tc.config.Interface, Destination: "172.18.4.50/32", Gw: "100.68.8.1"}},
				routes.ReplacedRoutes)
		})
	}
}

func TestConnectToConfiguredNetwork_ReachableDHCPDNSGetsNoHostRoute(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resolvConf string
	}{
		{"via the default route", "nameserver 9.9.9.9\n"},
		{"on the connected subnet", "nameserver 100.68.8.1\n"},
		{"ipv6", "nameserver 2001:db8::53\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := shadowedRoutes("wlan0")
			connectWithLease(t, routes, &types.NetworkConfig{Interface: "wlan0", SSID: "x", DNS: []string{"dhcp"}}, tc.resolvConf)
			assert.Empty(t, routes.ReplacedRoutes)
		})
	}
}

// Configured DNS is not tied to the link it is used on: where it goes is the
// routing table's business.
func TestConnectToConfiguredNetwork_ConfiguredDNSGetsNoHostRoute(t *testing.T) {
	routes := shadowedRoutes("wlan0")
	connectWithLease(t, routes, &types.NetworkConfig{Interface: "wlan0", SSID: "x", DNS: []string{"172.18.4.50"}}, "nameserver 172.18.4.50\n")
	assert.Empty(t, routes.ReplacedRoutes)
}

func TestPinDNSRoutes_MostSpecificRouteDecides(t *testing.T) {
	manager := newSeamTestManager(t)
	routes := shadowedRoutes("wlan0")
	// The network itself routes 172.18.4.0/24: more specific than the bridge.
	routes.Routes = append(routes.Routes, types.Route{Dst: "172.18.4.0/24", Gw: "100.68.8.1", Iface: "wlan0"})
	manager.routeMgr = routes
	require.NoError(t, os.WriteFile(manager.resolvConf(), []byte("nameserver 172.18.4.50\n"), 0644))

	manager.PinDNSRoutes("wlan0")

	assert.Empty(t, routes.ReplacedRoutes)
}

func TestPinDNSRoutes_NoDefaultRouteOnInterfaceLeavesRoutesAlone(t *testing.T) {
	manager := newSeamTestManager(t)
	routes := &fake.RouteManager{Routes: []types.Route{{Dst: "172.18.0.0/16", Iface: "br-x"}}}
	manager.routeMgr = routes
	require.NoError(t, os.WriteFile(manager.resolvConf(), []byte("nameserver 172.18.4.50\n"), 0644))

	manager.PinDNSRoutes("wlan0")

	assert.Empty(t, routes.ReplacedRoutes)
}
