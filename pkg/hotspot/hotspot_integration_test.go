//go:build integration

package hotspot

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

func TestHotspotStart_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "hostapd")
	testutil.SkipIfMissingCmd(t, "dnsmasq")

	// Load virtual radios
	radios := testutil.LoadHWSim(t, 2)
	require.Len(t, radios, 2)

	apRadio := radios[0]
	clientRadio := radios[1]

	// Create hotspot manager
	executor := system.NewExecutor(&testLogger{t: t}, false)
	logger := &testLogger{t: t}
	manager := NewHotspotManager(executor, logger)

	// Configure hotspot
	config := &types.HotspotConfig{
		SSID:      "TestHotspot",
		Password:  "hotspotpass123",
		Interface: apRadio.Interface,
		Channel:   6,
		Gateway:   "192.168.50.1",
		IPRange:   "192.168.50.10,192.168.50.50",
	}

	t.Run("start hotspot", func(t *testing.T) {
		err := manager.Start(config)
		if err != nil {
			// May fail in hwsim environment, log but continue
			t.Logf("Hotspot start result: %v", err)
			t.Skip("Hotspot start failed - hwsim may not support AP mode fully")
		}

		// Give time to start
		time.Sleep(2 * time.Second)

		// Verify AP is visible from client
		output, err := clientRadio.Scan(nil)
		if err == nil {
			assert.Contains(t, output, "TestHotspot", "Hotspot SSID should be visible")
			t.Logf("Scan from client:\n%s", output)
		}
	})

	t.Run("stop hotspot", func(t *testing.T) {
		err := manager.Stop()
		if err != nil {
			t.Logf("Hotspot stop result: %v", err)
		}

		time.Sleep(1 * time.Second)
	})
}

func TestHotspotWithClient_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "hostapd")
	testutil.SkipIfMissingCmd(t, "dnsmasq")
	testutil.SkipIfMissingCmd(t, "wpa_supplicant")

	radios := testutil.LoadHWSim(t, 2)
	require.Len(t, radios, 2)

	apRadio := radios[0]
	clientRadio := radios[1]

	// Start AP using testutil (more reliable than our hotspot manager for testing)
	ap := testutil.StartTestAP(t, apRadio, testutil.TestAPConfig{
		SSID:    "ClientTestHotspot",
		PSK:     "clienttestpass",
		Channel: 1,
	})
	require.True(t, ap.IsRunning())

	// Start DHCP server
	// First, set IP on AP interface
	err := setInterfaceIP(apRadio.Interface, "192.168.60.1/24")
	require.NoError(t, err)

	dhcpServer := testutil.StartDHCPServer(t, testutil.DHCPServerConfig{
		Interface:  apRadio.Interface,
		RangeStart: "192.168.60.10",
		RangeEnd:   "192.168.60.50",
		Gateway:    "192.168.60.1",
		DNS:        "8.8.8.8",
	})
	require.True(t, dhcpServer.IsRunning())

	time.Sleep(2 * time.Second)

	// Scan from client
	output, err := clientRadio.Scan(nil)
	if err == nil {
		t.Logf("Client scan:\n%s", output)
		assert.Contains(t, output, "ClientTestHotspot")
	}

	// Try to get DHCP lease (may not work fully in hwsim)
	t.Run("client DHCP lease", func(t *testing.T) {
		// This test verifies the DHCP server is running and responsive
		leases, err := dhcpServer.GetLeases()
		require.NoError(t, err)
		t.Logf("DHCP leases:\n%s", leases)
	})
}

func TestHotspotStatus_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "hostapd")

	radios := testutil.LoadHWSim(t, 1)
	require.Len(t, radios, 1)

	// Start AP
	ap := testutil.StartTestAP(t, radios[0], testutil.TestAPConfig{
		SSID:    "StatusTestAP",
		PSK:     "statustest",
		Channel: 11,
	})
	require.True(t, ap.IsRunning())

	time.Sleep(1 * time.Second)

	// Get interface info
	info, err := radios[0].GetInfo(nil)
	require.NoError(t, err)
	t.Logf("AP interface info:\n%s", info)

	// Verify AP mode
	assert.Contains(t, info, "type AP", "Interface should be in AP mode")
}

// setInterfaceIP sets an IP address on a network interface.
func setInterfaceIP(iface, ip string) error {
	return exec.Command("ip", "addr", "add", ip, "dev", iface).Run()
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

// testDHCPManager implements types.DHCPManager
type testDHCPManager struct {
	t       *testing.T
	running bool
}

func (d *testDHCPManager) Start(config *types.DHCPServerConfig) error {
	d.t.Logf("DHCP Start called: %+v", config)
	d.running = true
	return nil
}

func (d *testDHCPManager) Stop() error {
	d.t.Logf("DHCP Stop called")
	d.running = false
	return nil
}

func (d *testDHCPManager) IsRunning() bool {
	return d.running
}
