package vpn

import (
	"testing"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// newRouteTestManager builds a VPN Manager wired to the given fake RouteManager.
func newRouteTestManager(t *testing.T, rm *fake.RouteManager) *Manager {
	t.Helper()
	m := NewManagerWithDir(&mockSystemExecutor{}, &mockLogger{}, &mockConfigManager{}, t.TempDir())
	m.routeMgr = rm
	return m
}

func TestGetCurrentGateway_GatewayRoute(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{{Gw: "10.0.0.1", Iface: "eth0"}},
	}
	m := newRouteTestManager(t, rm)

	gw, iface := m.getCurrentGateway()
	assert.Equal(t, "10.0.0.1", gw)
	assert.Equal(t, "eth0", iface)
}

// A device-only default route (e.g. `default dev wg0`) has no gateway. The old
// text parser required "default via X" and dropped it; netlink returns iface
// with an empty gateway.
func TestGetCurrentGateway_DeviceOnlyRoute(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{{Gw: "", Iface: "wg0"}},
	}
	m := newRouteTestManager(t, rm)

	gw, iface := m.getCurrentGateway()
	assert.Equal(t, "", gw, "device-only route has no gateway")
	assert.Equal(t, "wg0", iface)
}

func TestGetCurrentGateway_NoDefaultRoute(t *testing.T) {
	rm := &fake.RouteManager{} // empty: GetDefaultRoute returns an error
	m := newRouteTestManager(t, rm)

	gw, iface := m.getCurrentGateway()
	assert.Equal(t, "", gw)
	assert.Equal(t, "", iface)
}

func TestRestoreDefaultRouteFromState_GatewayRoute(t *testing.T) {
	rm := &fake.RouteManager{}
	m := newRouteTestManager(t, rm)

	m.restoreDefaultRouteFromState(&vpnState{
		OriginalGateway:   "192.168.1.1",
		OriginalInterface: "eth0",
	})

	assert.Len(t, rm.Replaced, 1)
	assert.Equal(t, fake.ReplaceCall{Iface: "eth0", Gw: "192.168.1.1", Metric: 0}, rm.Replaced[0])
}

// The crux of the motivating bug: restoring a device-only default route. The
// saved state has an interface but NO gateway. Branching on interface (not
// gateway) means it IS restored, as `default dev wg0`.
func TestRestoreDefaultRouteFromState_DeviceOnlyRoute(t *testing.T) {
	rm := &fake.RouteManager{}
	m := newRouteTestManager(t, rm)

	m.restoreDefaultRouteFromState(&vpnState{
		OriginalGateway:   "", // device-only: no gateway
		OriginalInterface: "wg0",
	})

	assert.Len(t, rm.Replaced, 1, "device-only route must still be restored")
	assert.Equal(t, fake.ReplaceCall{Iface: "wg0", Gw: "", Metric: 0}, rm.Replaced[0])
}

// With no interface in the saved state, restore falls back to heuristic
// detection over the live route table.
func TestRestoreDefaultRouteFromState_FallsBackWhenNoInterface(t *testing.T) {
	rm := &fake.RouteManager{
		// Heuristic scan finds a physical route via eth0.
		Routes: []types.Route{
			{Dst: "10.8.0.0/24", Gw: "", Iface: "wg0"}, // skipped: VPN iface
			{Dst: "192.168.1.0/24", Gw: "192.168.1.1", Iface: "eth0"},
		},
	}
	m := newRouteTestManager(t, rm)

	m.restoreDefaultRouteFromState(&vpnState{OriginalInterface: ""})

	// Heuristic picks the physical eth0 route and restores via it.
	assert.Len(t, rm.Replaced, 1)
	assert.Equal(t, "eth0", rm.Replaced[0].Iface)
	assert.Equal(t, "192.168.1.1", rm.Replaced[0].Gw)
}

// restoreDefaultRoute (heuristic) must skip VPN interfaces when searching for
// the original upstream gateway.
func TestRestoreDefaultRoute_SkipsVPNInterfaces(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{
			{Dst: "10.0.0.0/8", Gw: "10.0.0.1", Iface: "tun0"},            // VPN, skipped
			{Dst: "100.64.0.0/10", Gw: "100.64.0.1", Iface: "tailscale0"}, // VPN, skipped
			{Dst: "192.168.5.0/24", Gw: "192.168.5.1", Iface: "wlan0"},    // physical, chosen
		},
	}
	m := newRouteTestManager(t, rm)

	m.restoreDefaultRoute()

	assert.Len(t, rm.Replaced, 1)
	assert.Equal(t, "wlan0", rm.Replaced[0].Iface)
	assert.Equal(t, "192.168.5.1", rm.Replaced[0].Gw)
}

// When no physical gateway route can be found, restoreDefaultRoute must not
// attempt any replace (nothing to restore).
func TestRestoreDefaultRoute_NoPhysicalRoute(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{
			{Dst: "10.0.0.0/8", Gw: "10.0.0.1", Iface: "wg0"}, // only VPN routes
		},
	}
	m := newRouteTestManager(t, rm)

	m.restoreDefaultRoute()

	assert.Empty(t, rm.Replaced, "no physical route: nothing should be restored")
}

func TestIsVPNInterface(t *testing.T) {
	vpn := []string{"wg0", "wg-home", "tun0", "tun1", "tailscale0", "wt0", "utun3"}
	physical := []string{"eth0", "wlan0", "wlp1s0", "enp3s0", "br0", "lo"}

	for _, name := range vpn {
		assert.True(t, isVPNInterface(name), "%q should be a VPN interface", name)
	}
	for _, name := range physical {
		assert.False(t, isVPNInterface(name), "%q should NOT be a VPN interface", name)
	}
}
