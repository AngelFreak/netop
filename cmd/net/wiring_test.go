package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runRoot executes the real cobra command tree with the given argv, with the
// package-level managers swapped for the golden fixture and the real
// initializeManagers PersistentPreRun suppressed. It returns what the process
// would have written to stdout. This is the wired path an agent actually hits.
func runRoot(t *testing.T, args ...string) string {
	t.Helper()
	fixture, _ := goldenApp()

	savedPre := rootCmd.PersistentPreRun
	savedLogger, savedCfg, savedWifi, savedVPN, savedNet := logger, cfgManager, wifiMgr, vpnMgr, netMgr
	savedHotspot, savedDHCP, savedIface, savedJSON := hotspotMgr, dhcpMgr, iface, jsonOut
	t.Cleanup(func() {
		rootCmd.PersistentPreRun = savedPre
		logger, cfgManager, wifiMgr, vpnMgr, netMgr = savedLogger, savedCfg, savedWifi, savedVPN, savedNet
		hotspotMgr, dhcpMgr, iface, jsonOut = savedHotspot, savedDHCP, savedIface, savedJSON
		rootCmd.SetArgs(nil)
	})

	rootCmd.PersistentPreRun = func(*cobra.Command, []string) {
		logger = fixture.Logger
		cfgManager, wifiMgr, vpnMgr, netMgr, hotspotMgr, dhcpMgr = fixture.ConfigMgr, fixture.WiFiMgr, fixture.VPNMgr, fixture.NetworkMgr, fixture.HotspotMgr, fixture.DHCPMgr
		iface = fixture.Interface
	}

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	rootCmd.SetArgs(args)
	execErr := rootCmd.Execute()
	w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	require.NoError(t, execErr)
	return buf.String()
}

func TestWiring_JSONFlagReachesApp(t *testing.T) {
	out := runRoot(t, "--json", "list")
	env := decodeEnvelope(t, out)
	assert.True(t, env.OK)
	assert.Equal(t, "list", env.Command)
	assert.Contains(t, string(env.Data), `"HomeNet"`)
}

func TestWiring_JSONFlagAfterSubcommand(t *testing.T) {
	out := runRoot(t, "show", "home", "--json")
	env := decodeEnvelope(t, out)
	assert.Equal(t, "show", env.Command)
	assert.Contains(t, string(env.Data), `"su*******et"`)
}

func TestWiring_NoFlagKeepsTextOutput(t *testing.T) {
	out := runRoot(t, "list")
	assert.Contains(t, out, "Interface: wlan0")
	assert.NotContains(t, out, `"ok"`)
}
