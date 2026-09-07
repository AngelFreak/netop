package main

import (
	"bytes"
	"flag"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	fakenetlink "github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files in testdata/golden")

// hostnameLine varies per machine; it is normalized before comparison.
var hostnameLine = regexp.MustCompile(`(?m)^Hostname:  .*$`)

// goldenApp builds an App with a fixed, fully populated environment so every
// read command has something to print. The same fixture feeds the JSON tests.
func goldenApp() (*App, *bytes.Buffer) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{
				DNS:      []string{"1.1.1.1", "9.9.9.9"},
				MAC:      "00:??:??:??:??:??",
				Hostname: "laptop",
				VPN:      "work",
			},
			Networks: map[string]types.NetworkConfig{
				"home": {Interface: "wlan0", SSID: "HomeNet", PSK: "supersecret", VPN: "work"},
			},
			VPN:     map[string]types.VPNConfig{"work": {Type: "wireguard"}},
			Ignored: types.IgnoredConfig{Interfaces: []string{"docker[0-9]+", "veth.*"}},
		},
		networkConfig: &types.NetworkConfig{Interface: "wlan0", SSID: "HomeNet", PSK: "supersecret", VPN: "work"},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{
			Interface: "wlan0", SSID: "HomeNet", State: "connected",
			IP: net.ParseIP("192.168.1.50"), Gateway: net.ParseIP("192.168.1.1"),
			DNS: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("9.9.9.9")},
		}},
		networks: []types.WiFiNetwork{
			{SSID: "HomeNet", BSSID: "aa:bb:cc:dd:ee:ff", Signal: -40, Security: "WPA2", Frequency: 5180},
			{SSID: "Cafe", BSSID: "11:22:33:44:55:66", Signal: -70, Security: "Open", Frequency: 2412},
		},
	}
	app.NetworkMgr = &testNetworkManager{
		mac: "02:11:22:33:44:55",
		connectionInfo: &types.Connection{
			Interface: "wlan0", SSID: "HomeNet", State: "connected",
			IP: net.ParseIP("192.168.1.50"), Gateway: net.ParseIP("192.168.1.1"),
			DNS: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("9.9.9.9")},
		},
	}
	app.VPNMgr = &testVPNManager{vpns: []types.VPNStatus{
		{Name: "work", Type: "wireguard", Connected: true, Interface: "wg0", IP: net.ParseIP("10.0.0.2")},
		{Name: "nb", Type: "netbird", Ambiguous: true},
	}}
	app.HotspotMgr = &testHotspotManager{status: &types.HotspotStatus{
		Interface: "wlan1", SSID: "Share", Running: true, Clients: 2, Gateway: net.ParseIP("192.168.50.1"),
	}}
	app.DHCPMgr = &testDHCPManager{running: true, natState: types.NATState{Active: true, OutInterface: "wlan0"}}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
		{Dst: "default", Gw: "192.168.1.1", Iface: "wlan0", Metric: 600},
	}}
	return app, stdout
}

// goldenCases are the read commands whose text output must not change when
// --json is absent.
var goldenCases = []struct {
	name string
	run  func(*App) error
}{
	{"status", func(a *App) error { return a.RunStatus() }},
	{"list", func(a *App) error { return a.RunList() }},
	{"scan", func(a *App) error { return a.RunScan(false) }},
	{"scan_open", func(a *App) error { return a.RunScan(true) }},
	{"show_all", func(a *App) error { return a.RunShow("") }},
	{"show_home", func(a *App) error { return a.RunShow("home") }},
	{"vpn_list", func(a *App) error { return a.RunVPN("") }},
}

func TestTextOutputGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			app, stdout := goldenApp()
			require.NoError(t, tc.run(app))
			got := hostnameLine.ReplaceAll(stdout.Bytes(), []byte("Hostname:  <host>"))

			path := filepath.Join("testdata", "golden", tc.name+".txt")
			if *updateGolden {
				require.NoError(t, os.WriteFile(path, got, 0o644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err, "missing golden file; run: go test ./cmd/net -run TestTextOutputGolden -update")
			require.Equal(t, string(want), string(got))
		})
	}
}
