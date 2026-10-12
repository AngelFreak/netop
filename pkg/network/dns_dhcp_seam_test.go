package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/angelfreak/net/pkg/dhcpclient"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The DNS ownership marker is the contract between this manager and net's
// udhcpc script: what SetDNS records must decide whether an hourly lease
// renewal may rewrite resolv.conf. resolv.conf is left unlocked here, as it
// is while Tailscale accept_dns owns it, so only the marker stands between
// the renewal and the file.
// udhcpcEvent writes net's real udhcpc script for the manager's resolv.conf
// and marker, and returns a func that runs one lease event through it the way
// udhcpc does (direct exec) and returns the resulting resolv.conf.
func udhcpcEvent(t *testing.T, manager *Manager) func(event string) string {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	require.NoError(t, os.Mkdir(bin, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "busybox"), []byte("#!/bin/sh\n[ \"$1\" = awk ] && { shift; exec awk \"$@\"; }\nexit 0\n"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "logger"), []byte("#!/bin/sh\nexit 0\n"), 0755))
	script := filepath.Join(tmp, "udhcpc.script")
	require.NoError(t, os.WriteFile(script, []byte(dhcpclient.UdhcpcScript(manager.resolvConf(), manager.dnsOwnedPath())), 0700))

	return func(event string) string {
		t.Helper()
		cmd := exec.Command(script, event)
		cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "interface=wlan0", "ip=192.168.0.105", "subnet=255.255.255.0", "dns=217.26.160.4"}
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "script failed: %s", out)
		got, err := os.ReadFile(manager.resolvConf())
		require.NoError(t, err)
		return string(got)
	}
}

func newSeamTestManager(t *testing.T) *Manager {
	t.Helper()
	tmp := t.TempDir()
	return &Manager{
		routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(),
		executor: newMockExecutor(), logger: &mockLogger{},
		dnsOwnershipPath: filepath.Join(tmp, "dns-owned"),
		resolvConfPath:   filepath.Join(tmp, "resolv.conf"),
		setImmutable:     func(string, bool) error { return nil },
	}
}

// The DNS ownership marker is the contract between this manager and net's
// udhcpc script: what SetDNS records must decide whether an hourly lease
// renewal may rewrite resolv.conf. resolv.conf is left unlocked here, as it
// is while Tailscale accept_dns owns it, so only the marker stands between
// the renewal and the file.
func TestDNSOwnership_DecidesWhetherUdhcpcRenewalWritesResolvConf(t *testing.T) {
	manager := newSeamTestManager(t)
	renew := udhcpcEvent(t, manager)

	require.NoError(t, manager.SetDNS([]string{"1.1.1.1"}))
	assert.Equal(t, "nameserver 1.1.1.1\n", renew("renew"), "configured DNS must survive a renewal")

	require.NoError(t, manager.SetDNS([]string{"dhcp"}))
	assert.Equal(t, "\nnameserver 217.26.160.4\n", renew("renew"), "dns: dhcp must still take the lease's servers")
}

// scriptedDHCPClient runs a lease event when Acquire is called, as the real
// wired DHCP client would.
type scriptedDHCPClient struct {
	mockDHCPClient
	onAcquire func()
}

func (c *scriptedDHCPClient) Acquire(iface, hostname string) error {
	c.onAcquire()
	return nil
}

// Every earlier connect leaves the marker behind (SetDNS, or LockDNS after
// DHCP DNS). Connecting to a network that takes DNS from DHCP must hand DNS
// back to the DHCP client before it runs; otherwise the new lease's servers
// are skipped and resolv.conf keeps only the "Waiting for DHCP" placeholder.
func TestConnectToConfiguredNetwork_DHCPDNSAfterOwnedDNSTakesLeaseServers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *types.NetworkConfig
	}{
		{"wifi, no dns configured", &types.NetworkConfig{Interface: "wlan0", SSID: "home"}},
		{"wifi, dns: dhcp", &types.NetworkConfig{Interface: "wlan0", SSID: "home", DNS: []string{"dhcp"}}},
		{"wired, no dns configured", &types.NetworkConfig{Interface: "eth0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := newSeamTestManager(t)
			bound := udhcpcEvent(t, manager)
			require.NoError(t, manager.SetDNS([]string{"9.9.9.9"})) // the previous connection

			var got string
			lease := func() { got = bound("bound") }
			wifi := &mockWiFiManagerImpl{onConnect: func() error { lease(); return nil }}
			manager.dhcpClient = &scriptedDHCPClient{onAcquire: lease}

			require.NoError(t, manager.ConnectToConfiguredNetwork(tc.config, "", wifi))
			assert.Equal(t, "\nnameserver 217.26.160.4\n", got, "the lease's DNS must be written")
			assert.True(t, manager.resolvConfHasNameserver())
		})
	}
}

// Production wiring: both sides default to the same marker path.
func TestDNSOwnership_DefaultMarkerIsSharedWithUdhcpcScript(t *testing.T) {
	m := NewManager(newMockExecutor(), &mockLogger{}, nil)
	assert.Equal(t, types.DNSOwnedPath, m.dnsOwnedPath())
}
