package main

import (
	"testing"

	"github.com/angelfreak/net/pkg/vpn"
	"github.com/stretchr/testify/require"
)

// A WireGuard config's MTU and DNS are only applied if the VPN manager is
// actually given a network manager by the real startup path. Unit tests inject
// one by hand and so cannot catch initializeManagers() forgetting to wire it,
// which would make VPN DNS a silent no-op in production — the exact class of
// bug this feature fixes. Drive the real constructor and assert the seam.
func TestInitializeManagers_WiresNetworkManagerIntoVPN(t *testing.T) {
	t.Cleanup(func() {
		vpnMgr, netMgr, wifiMgr, cfgManager = nil, nil, nil, nil
		logger, sysExecutor = nil, nil
		iface, configPath = "", ""
	})

	configPath = "testdata/nonexistent.yaml" // config load failure must not skip wiring
	initializeManagers()

	require.NotNil(t, vpnMgr, "initializeManagers must construct a VPN manager")
	concrete, ok := vpnMgr.(*vpn.Manager)
	require.True(t, ok, "expected the concrete *vpn.Manager")
	require.NotNil(t, netMgr, "initializeManagers must construct a network manager")

	require.True(t, concrete.HasNetworkManager(),
		"VPN manager must be given a network manager, or VPN-provided DNS is silently ignored")
}
