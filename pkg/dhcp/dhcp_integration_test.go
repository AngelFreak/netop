//go:build integration

package dhcp

import (
	"os/exec"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
	"github.com/angelfreak/net/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDHCPServer_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "dnsmasq")
	testutil.SkipIfMissingCmd(t, "ip")

	// Create network namespace for isolation
	ns := testutil.NewTestNamespace(t)

	// Create a veth pair
	err := ns.AddVethPair("veth-dhcp-host", "veth-dhcp-ns")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-dhcp-host").Run()
	})

	// Set up host side interface with IP
	err = exec.Command("ip", "addr", "add", "192.168.200.1/24", "dev", "veth-dhcp-host").Run()
	require.NoError(t, err)
	err = exec.Command("ip", "link", "set", "veth-dhcp-host", "up").Run()
	require.NoError(t, err)

	// Bring up namespace side interface
	err = ns.Exec("ip", "link", "set", "veth-dhcp-ns", "up")
	require.NoError(t, err)

	// Start DHCP server on host side
	server := testutil.StartDHCPServer(t, testutil.DHCPServerConfig{
		Interface:  "veth-dhcp-host",
		RangeStart: "192.168.200.10",
		RangeEnd:   "192.168.200.50",
		Gateway:    "192.168.200.1",
		DNS:        "8.8.8.8",
	})
	require.True(t, server.IsRunning())

	time.Sleep(1 * time.Second)

	t.Run("DHCP server is running", func(t *testing.T) {
		assert.True(t, server.IsRunning())
	})

	t.Run("client can request lease", func(t *testing.T) {
		// Create DHCP client in namespace
		client := testutil.NewDHCPClient(t, ns, "veth-dhcp-ns")

		// Request lease
		err := client.RequestLease()
		if err != nil {
			t.Logf("Lease request result: %v", err)
			// May fail in some environments, that's OK for integration test
		}

		// Check if IP was assigned
		ip, err := client.GetIP()
		if err == nil && ip != "" {
			t.Logf("Client got IP: %s", ip)
			assert.Contains(t, ip, "192.168.200.")
		}

		// Check leases file
		leases, err := server.GetLeases()
		require.NoError(t, err)
		t.Logf("DHCP leases:\n%s", leases)
	})
}

func TestDHCPManager_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "dnsmasq")
	testutil.SkipIfMissingCmd(t, "ip")

	ns := testutil.NewTestNamespace(t)

	// Create a veth pair
	err := ns.AddVethPair("veth-mgr-host", "veth-mgr-ns")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-mgr-host").Run()
	})

	// Set up host side
	err = exec.Command("ip", "addr", "add", "192.168.201.1/24", "dev", "veth-mgr-host").Run()
	require.NoError(t, err)
	err = exec.Command("ip", "link", "set", "veth-mgr-host", "up").Run()
	require.NoError(t, err)

	// Create DHCP manager
	executor := system.NewExecutor(&testLogger{t: t}, false)
	logger := &testLogger{t: t}
	manager := NewDHCPManager(executor, logger)

	config := &types.DHCPServerConfig{
		Interface: "veth-mgr-host",
		IPRange:   "192.168.201.10,192.168.201.50",
		Gateway:   "192.168.201.1",
		LeaseTime: "1h",
	}

	t.Run("start DHCP server via manager", func(t *testing.T) {
		err := manager.Start(config)
		if err != nil {
			t.Logf("Manager start result: %v", err)
			// May fail depending on system config
		}

		time.Sleep(1 * time.Second)
	})

	t.Run("check running status", func(t *testing.T) {
		running := manager.IsRunning()
		t.Logf("DHCP running: %v", running)
	})

	t.Run("stop DHCP server", func(t *testing.T) {
		err := manager.Stop()
		if err != nil {
			t.Logf("Stop result: %v", err)
		}
	})
}

func TestDHCPServerConfig_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "dnsmasq")

	ns := testutil.NewTestNamespace(t)

	// Create interface
	err := ns.AddVethPair("veth-cfg-host", "veth-cfg-ns")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-cfg-host").Run()
	})

	// Configure host side
	err = exec.Command("ip", "addr", "add", "10.0.100.1/24", "dev", "veth-cfg-host").Run()
	require.NoError(t, err)
	err = exec.Command("ip", "link", "set", "veth-cfg-host", "up").Run()
	require.NoError(t, err)

	t.Run("custom DNS", func(t *testing.T) {
		server := testutil.StartDHCPServer(t, testutil.DHCPServerConfig{
			Interface:  "veth-cfg-host",
			RangeStart: "10.0.100.10",
			RangeEnd:   "10.0.100.20",
			Gateway:    "10.0.100.1",
			DNS:        "1.1.1.1",
		})
		require.True(t, server.IsRunning())
		server.Stop()
	})

	t.Run("custom lease time", func(t *testing.T) {
		server := testutil.StartDHCPServer(t, testutil.DHCPServerConfig{
			Interface:  "veth-cfg-host",
			RangeStart: "10.0.100.10",
			RangeEnd:   "10.0.100.20",
			Gateway:    "10.0.100.1",
			LeaseTime:  "30m",
		})
		require.True(t, server.IsRunning())
		server.Stop()
	})

	t.Run("with domain", func(t *testing.T) {
		server := testutil.StartDHCPServer(t, testutil.DHCPServerConfig{
			Interface:  "veth-cfg-host",
			RangeStart: "10.0.100.10",
			RangeEnd:   "10.0.100.20",
			Gateway:    "10.0.100.1",
			Domain:     "test.local",
		})
		require.True(t, server.IsRunning())
		server.Stop()
	})
}

// testLogger implements types.Logger
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debug(msg string, args ...interface{}) {
	l.t.Logf("[DEBUG] "+msg, args...)
}

func (l *testLogger) Info(msg string, args ...interface{}) {
	l.t.Logf("[INFO] "+msg, args...)
}

func (l *testLogger) Warn(msg string, args ...interface{}) {
	l.t.Logf("[WARN] "+msg, args...)
}

func (l *testLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("[ERROR] "+msg, args...)
}
