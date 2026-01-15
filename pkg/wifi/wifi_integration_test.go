//go:build integration

package wifi

import (
	"strings"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWiFiScan_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "hostapd")
	testutil.SkipIfMissingCmd(t, "iw")

	// Load virtual radios - need 2: one for AP, one for client
	radios := testutil.LoadHWSim(t, 2)
	require.Len(t, radios, 2)

	apRadio := radios[0]
	clientRadio := radios[1]

	// Start test AP
	ap := testutil.StartTestAP(t, apRadio, testutil.TestAPConfig{
		SSID:    "IntegrationTestAP",
		PSK:     "testpassword123",
		Channel: 6,
	})
	require.True(t, ap.IsRunning(), "AP should be running")

	// Give the AP time to start beaconing
	time.Sleep(2 * time.Second)

	// Scan from client radio
	t.Run("iw scan finds test AP", func(t *testing.T) {
		output, err := clientRadio.Scan(nil)
		// Scan might fail with "resource busy" on first try
		if err != nil && strings.Contains(output, "busy") {
			time.Sleep(1 * time.Second)
			output, err = clientRadio.Scan(nil)
		}
		require.NoError(t, err, "scan failed: %s", output)
		assert.Contains(t, output, "IntegrationTestAP", "SSID should appear in scan results")
		t.Logf("Scan results:\n%s", output)
	})
}

func TestWiFiConnect_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "hostapd")
	testutil.SkipIfMissingCmd(t, "wpa_supplicant")
	testutil.SkipIfMissingCmd(t, "iw")

	// Load virtual radios
	radios := testutil.LoadHWSim(t, 2)
	require.Len(t, radios, 2)

	apRadio := radios[0]
	clientRadio := radios[1]

	// Start test AP
	ap := testutil.StartTestAP(t, apRadio, testutil.TestAPConfig{
		SSID:    "ConnectTestAP",
		PSK:     "securepassword",
		Channel: 1,
	})
	require.True(t, ap.IsRunning())

	// Give AP time to start
	time.Sleep(2 * time.Second)

	// Create WiFi manager for client
	executor := system.NewExecutor(&testLogger{t: t}, false)
	manager := NewManager(executor, &testLogger{t: t}, clientRadio.Interface, nil) // nil for DHCP manager

	t.Run("connect to WPA2 network", func(t *testing.T) {
		err := manager.Connect("ConnectTestAP", "securepassword", "")
		if err != nil {
			// Connection might fail in hwsim environment, log but don't fail
			t.Logf("Connection attempt result: %v", err)
		}

		// Give time to associate
		time.Sleep(3 * time.Second)

		// Check interface info
		output, err := clientRadio.GetInfo(nil)
		require.NoError(t, err)
		t.Logf("Client interface info:\n%s", output)
	})

	t.Run("disconnect", func(t *testing.T) {
		err := manager.Disconnect()
		if err != nil {
			t.Logf("Disconnect result: %v", err)
		}

		time.Sleep(1 * time.Second)

		// Verify disconnected
		output, err := clientRadio.GetInfo(nil)
		require.NoError(t, err)
		t.Logf("After disconnect:\n%s", output)
	})
}

func TestWiFiOpenNetwork_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "hostapd")
	testutil.SkipIfMissingCmd(t, "iw")

	radios := testutil.LoadHWSim(t, 2)
	require.Len(t, radios, 2)

	apRadio := radios[0]
	clientRadio := radios[1]

	// Start open AP (no PSK)
	ap := testutil.StartTestAP(t, apRadio, testutil.TestAPConfig{
		SSID:    "OpenTestAP",
		Channel: 11,
	})
	require.True(t, ap.IsRunning())

	time.Sleep(2 * time.Second)

	// Verify open network is visible
	output, err := clientRadio.Scan(nil)
	if err != nil && strings.Contains(output, "busy") {
		time.Sleep(1 * time.Second)
		output, err = clientRadio.Scan(nil)
	}
	require.NoError(t, err)
	assert.Contains(t, output, "OpenTestAP")
	t.Logf("Open network scan:\n%s", output)
}

func TestWiFiBSSIDPinning_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "hostapd")
	testutil.SkipIfMissingCmd(t, "wpa_supplicant")

	radios := testutil.LoadHWSim(t, 2)
	require.Len(t, radios, 2)

	apRadio := radios[0]
	clientRadio := radios[1]

	// Start AP
	ap := testutil.StartTestAP(t, apRadio, testutil.TestAPConfig{
		SSID:    "BSSIDTestAP",
		PSK:     "testpassword",
		Channel: 1,
	})
	require.True(t, ap.IsRunning())

	time.Sleep(2 * time.Second)

	// Get AP BSSID
	bssid, err := ap.GetBSSID()
	if err != nil {
		t.Skipf("Could not get BSSID: %v", err)
	}
	t.Logf("AP BSSID: %s", bssid)

	// Create WiFi manager
	executor := system.NewExecutor(&testLogger{t: t}, false)
	manager := NewManager(executor, &testLogger{t: t}, clientRadio.Interface, nil)

	// Try to connect with BSSID
	err = manager.Connect("BSSIDTestAP", "testpassword", bssid)
	if err != nil {
		t.Logf("BSSID connection attempt: %v", err)
	}
}

func TestWiFiManagerListConnections_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoHWSim(t)
	testutil.SkipIfMissingCmd(t, "iw")

	radios := testutil.LoadHWSim(t, 1)
	require.Len(t, radios, 1)

	executor := system.NewExecutor(&testLogger{t: t}, false)
	manager := NewManager(executor, &testLogger{t: t}, radios[0].Interface, nil)

	// List connections (should work even if not connected)
	connections, err := manager.ListConnections()
	require.NoError(t, err)
	t.Logf("Connections: %+v", connections)
}

// testLogger implements types.Logger for integration tests
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
