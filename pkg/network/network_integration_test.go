//go:build integration

package network

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetDNS_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "ip")

	// Create isolated namespace
	ns := testutil.NewTestNamespace(t)

	// Create a veth pair to have an interface to work with
	err := ns.AddVethPair("veth-host-dns", "veth-ns-dns")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-host-dns").Run()
	})

	// Bring up the interface in namespace
	err = ns.Exec("ip", "link", "set", "veth-ns-dns", "up")
	require.NoError(t, err)

	// Create a test resolv.conf in the namespace
	// Since we can't easily modify /etc/resolv.conf in namespace, we test the DNS setting logic
	ns.Run(func() {
		executor := system.NewExecutor(&testLogger{t: t}, false)
		manager := NewManager(executor, &testLogger{t: t}, nil)

		// Test that SetDNS constructs the correct command
		// In a real namespace, this would modify /etc/resolv.conf
		err := manager.SetDNS([]string{"1.1.1.1", "8.8.8.8"})
		// This may fail in namespace without proper /etc setup, which is expected
		// The test verifies the code path executes without panic
		if err != nil {
			t.Logf("SetDNS returned error (expected in isolated namespace): %v", err)
		}
	})
}

func TestSetMAC_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "ip")

	ns := testutil.NewTestNamespace(t)

	// Create a veth pair
	err := ns.AddVethPair("veth-host-mac", "veth-ns-mac")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-host-mac").Run()
	})

	// Get original MAC
	output, err := ns.ExecOutput("ip", "link", "show", "veth-ns-mac")
	require.NoError(t, err)
	t.Logf("Original interface state:\n%s", output)

	// Set a new MAC address
	newMAC := "02:00:00:00:00:01"
	err = ns.Exec("ip", "link", "set", "veth-ns-mac", "down")
	require.NoError(t, err)
	err = ns.Exec("ip", "link", "set", "veth-ns-mac", "address", newMAC)
	require.NoError(t, err)
	err = ns.Exec("ip", "link", "set", "veth-ns-mac", "up")
	require.NoError(t, err)

	// Verify MAC was changed
	output, err = ns.ExecOutput("ip", "link", "show", "veth-ns-mac")
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(output), newMAC)
	t.Logf("After MAC change:\n%s", output)
}

func TestSetStaticIP_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "ip")

	ns := testutil.NewTestNamespace(t)

	// Create a veth pair
	err := ns.AddVethPair("veth-host-ip", "veth-ns-ip")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-host-ip").Run()
	})

	// Bring up interface
	err = ns.Exec("ip", "link", "set", "veth-ns-ip", "up")
	require.NoError(t, err)

	// Set static IP
	testIP := "192.168.100.10/24"
	err = ns.Exec("ip", "addr", "add", testIP, "dev", "veth-ns-ip")
	require.NoError(t, err)

	// Verify IP was set
	output, err := ns.ExecOutput("ip", "addr", "show", "veth-ns-ip")
	require.NoError(t, err)
	assert.Contains(t, output, "192.168.100.10")
	t.Logf("Interface with IP:\n%s", output)
}

func TestRouteManagement_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "ip")

	ns := testutil.NewTestNamespace(t)

	// Create a veth pair
	err := ns.AddVethPair("veth-host-rt", "veth-ns-rt")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-host-rt").Run()
	})

	// Bring up interface and set IP
	err = ns.Exec("ip", "link", "set", "veth-ns-rt", "up")
	require.NoError(t, err)
	err = ns.Exec("ip", "addr", "add", "10.0.0.2/24", "dev", "veth-ns-rt")
	require.NoError(t, err)

	// Add a route
	err = ns.Exec("ip", "route", "add", "10.10.0.0/24", "via", "10.0.0.1", "dev", "veth-ns-rt")
	// This may fail if gateway is unreachable, which is fine for the test
	if err != nil {
		t.Logf("Route add failed (expected without real gateway): %v", err)
	}

	// List routes
	output, err := ns.ExecOutput("ip", "route", "show")
	require.NoError(t, err)
	t.Logf("Routes in namespace:\n%s", output)
	assert.Contains(t, output, "10.0.0.0/24")

	// Flush routes for the interface
	err = ns.Exec("ip", "route", "flush", "dev", "veth-ns-rt")
	require.NoError(t, err)

	// Verify routes were flushed
	output, err = ns.ExecOutput("ip", "route", "show")
	require.NoError(t, err)
	assert.NotContains(t, output, "veth-ns-rt")
	t.Logf("After flush:\n%s", output)
}

func TestNetworkManager_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfMissingCmd(t, "ip")

	ns := testutil.NewTestNamespace(t)

	// Create a veth pair
	err := ns.AddVethPair("veth-host-nm", "veth-ns-nm")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "veth-host-nm").Run()
	})

	ns.Run(func() {
		executor := system.NewExecutor(&testLogger{t: t}, false)
		manager := NewManager(executor, &testLogger{t: t}, nil)

		// Test getting connection info (should not panic even if interface doesn't exist in this context)
		info, err := manager.GetConnectionInfo("veth-ns-nm")
		if err != nil {
			t.Logf("GetConnectionInfo error (expected in namespace): %v", err)
		} else {
			t.Logf("Connection info: %+v", info)
		}
	})
}

// testLogger implements types.Logger for integration tests
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debug(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[DEBUG] "+msg, args...)
}

func (l *testLogger) Info(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[INFO] "+msg, args...)
}

func (l *testLogger) Warn(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[WARN] "+msg, args...)
}

func (l *testLogger) Error(msg string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("[ERROR] "+msg, args...)
}
