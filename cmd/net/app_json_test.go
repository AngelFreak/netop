package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/angelfreak/net/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

// runJSON runs one read command against the golden fixture in JSON mode and
// returns the decoded envelope plus the data payload as a generic map.
func runJSON(t *testing.T, run func(*App) error) (envelope, map[string]any) {
	t.Helper()
	app, stdout := goldenApp()
	app.JSON = true
	err := run(app)
	env := decodeEnvelope(t, stdout.String())
	if env.OK {
		require.NoError(t, err)
	}
	var data map[string]any
	if env.Data != nil {
		require.NoError(t, json.Unmarshal(env.Data, &data))
	}
	return env, data
}

func TestJSON_Status(t *testing.T) {
	env, data := runJSON(t, func(a *App) error { return a.RunStatus() })
	assert.Equal(t, "status", env.Command)
	assert.True(t, env.OK)

	assert.Equal(t, "wlan0", data["interface"])
	assert.NotEmpty(t, data["hostname"])
	assert.Equal(t, "02:11:22:33:44:55", data["mac"])
	assert.Equal(t, "00:??:??:??:??:??", data["mac_policy"])

	conn := data["connection"].(map[string]any)
	assert.Equal(t, "HomeNet", conn["ssid"])
	assert.Equal(t, "connected", conn["state"])
	assert.Equal(t, "192.168.1.50", conn["ip"])
	assert.Equal(t, "192.168.1.1", conn["gateway"])
	assert.Equal(t, []any{"1.1.1.1", "9.9.9.9"}, conn["dns"])

	inet := data["internet"].(map[string]any)
	assert.Equal(t, "ok", inet["status"])
	assert.Equal(t, "wlan0", inet["default_route"])

	vpns := data["vpns"].([]any)
	require.Len(t, vpns, 2)
	work := vpns[0].(map[string]any)
	assert.Equal(t, "work", work["name"])
	assert.Equal(t, "wireguard", work["type"])
	assert.Equal(t, true, work["connected"])
	assert.Equal(t, "connected", work["status"])
	assert.Equal(t, "wg0", work["interface"])
	assert.Equal(t, "10.0.0.2", work["ip"])
	nb := vpns[1].(map[string]any)
	assert.Equal(t, true, nb["ambiguous"])
	assert.Equal(t, "ambiguous", nb["status"])

	hs := data["hotspot"].(map[string]any)
	assert.Equal(t, true, hs["running"])
	assert.Equal(t, "Share", hs["ssid"])
	assert.Equal(t, float64(2), hs["clients"])
	assert.Equal(t, "192.168.50.1", hs["gateway"])

	assert.Equal(t, map[string]any{"running": true}, data["dhcp_server"])
}

func TestJSON_Status_DisconnectedAndPortal(t *testing.T) {
	app, stdout := goldenApp()
	app.JSON = true
	app.NetworkMgr = &testNetworkManager{connectionErr: errors.New("no link")}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusPortal, PortalURL: "http://portal.example/login"}}}
	app.VPNMgr = &testVPNManager{}
	app.HotspotMgr = &testHotspotManager{}
	app.DHCPMgr = &testDHCPManager{}

	require.NoError(t, app.RunStatus())
	env := decodeEnvelope(t, stdout.String())
	var data map[string]any
	require.NoError(t, json.Unmarshal(env.Data, &data))

	assert.Nil(t, data["connection"])
	inet := data["internet"].(map[string]any)
	assert.Equal(t, "portal", inet["status"])
	assert.Equal(t, "http://portal.example/login", inet["portal_url"])
	assert.Equal(t, []any{}, data["vpns"], "no VPNs must be an empty list, not null")
	assert.Nil(t, data["hotspot"], "a hotspot that is not running is null")
	assert.Equal(t, map[string]any{"running": false}, data["dhcp_server"])
}

func TestJSON_Status_PortalCheckOff_OmitsInternet(t *testing.T) {
	app, stdout := goldenApp()
	app.JSON = true
	app.ConfigMgr.(*testConfigManager).config.Common.Portal.Check = "off"

	require.NoError(t, app.RunStatus())
	env := decodeEnvelope(t, stdout.String())
	var data map[string]any
	require.NoError(t, json.Unmarshal(env.Data, &data))
	_, present := data["internet"]
	assert.False(t, present)
}

func TestJSON_List(t *testing.T) {
	env, data := runJSON(t, func(a *App) error { return a.RunList() })
	assert.Equal(t, "list", env.Command)
	conns := data["connections"].([]any)
	require.Len(t, conns, 1)
	assert.Equal(t, "wlan0", conns[0].(map[string]any)["interface"])
}

func TestJSON_List_Empty(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true
	require.NoError(t, app.RunList())
	env := decodeEnvelope(t, stdout.String())
	assert.JSONEq(t, `{"connections":[]}`, string(env.Data))
}

func TestJSON_List_Error(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true
	app.WiFiMgr = &testWiFiManager{listErr: errors.New("list failed")}
	assert.Error(t, app.RunList())
	env := decodeEnvelope(t, stdout.String())
	assert.False(t, env.OK)
	assert.Equal(t, "list failed", env.Error.Message)
}

func TestJSON_Scan(t *testing.T) {
	env, data := runJSON(t, func(a *App) error { return a.RunScan(false) })
	assert.Equal(t, "scan", env.Command)
	nets := data["networks"].([]any)
	require.Len(t, nets, 2)
	first := nets[0].(map[string]any)
	assert.Equal(t, "HomeNet", first["ssid"])
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", first["bssid"])
	assert.Equal(t, float64(-40), first["signal"])
	assert.Equal(t, "WPA2", first["security"])
	assert.Equal(t, float64(5180), first["frequency"])
}

func TestJSON_Scan_OpenOnly(t *testing.T) {
	_, data := runJSON(t, func(a *App) error { return a.RunScan(true) })
	nets := data["networks"].([]any)
	require.Len(t, nets, 1)
	assert.Equal(t, "Cafe", nets[0].(map[string]any)["ssid"])
}

func TestJSON_Scan_ControlCharsAreEscapedNotStripped(t *testing.T) {
	app, stdout := goldenApp()
	app.JSON = true
	app.WiFiMgr = &testWiFiManager{networks: []types.WiFiNetwork{{SSID: "evil\x1b[31m", BSSID: "00:00:00:00:00:01", Security: "Open"}}}
	require.NoError(t, app.RunScan(false))
	out := stdout.String()
	assert.NotContains(t, out, "\x1b", "raw escape bytes must not reach stdout")
	env := decodeEnvelope(t, out)
	var data struct {
		Networks []struct {
			SSID string `json:"ssid"`
		} `json:"networks"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &data))
	assert.Equal(t, "evil\x1b[31m", data.Networks[0].SSID, "the SSID round-trips intact so an agent can pass it to connect")
}

func TestJSON_ShowAll(t *testing.T) {
	env, data := runJSON(t, func(a *App) error { return a.RunShow("") })
	assert.Equal(t, "show", env.Command)
	common := data["common"].(map[string]any)
	assert.Equal(t, []any{"1.1.1.1", "9.9.9.9"}, common["dns"])
	assert.Equal(t, "laptop", common["hostname"])
	home := data["networks"].(map[string]any)["home"].(map[string]any)
	assert.Equal(t, "HomeNet", home["ssid"])
	_, hasPSK := home["psk"]
	assert.False(t, hasPSK, "show-all must not include secrets")
	assert.Equal(t, map[string]any{"work": "wireguard"}, data["vpns"])
	assert.Equal(t, []any{"docker[0-9]+", "veth.*"}, data["ignored_interfaces"])
}

func TestJSON_ShowOne_MasksPSK(t *testing.T) {
	_, data := runJSON(t, func(a *App) error { return a.RunShow("home") })
	assert.Equal(t, "home", data["name"])
	assert.Equal(t, "su*******et", data["psk"])
	assert.Equal(t, "work", data["vpn"])
}

func TestJSON_ShowOne_NotFound(t *testing.T) {
	app, stdout := goldenApp()
	app.JSON = true
	app.ConfigMgr.(*testConfigManager).networkErr = fmt.Errorf("network configuration 'nope': %w", types.ErrNotFound)
	assert.Error(t, app.RunShow("nope"))
	env := decodeEnvelope(t, stdout.String())
	assert.False(t, env.OK)
	assert.Equal(t, "not_found", env.Error.Code)
}

func TestJSON_VPNList(t *testing.T) {
	env, data := runJSON(t, func(a *App) error { return a.RunVPN("") })
	assert.Equal(t, "vpn", env.Command)
	vpns := data["vpns"].([]any)
	require.Len(t, vpns, 2)
	assert.Equal(t, "connected", vpns[0].(map[string]any)["status"])
}

func TestJSON_Genkey(t *testing.T) {
	app, stdout := goldenApp()
	app.JSON = true
	require.NoError(t, app.RunGenkey())
	env := decodeEnvelope(t, stdout.String())
	assert.Equal(t, "genkey", env.Command)
	var data map[string]string
	require.NoError(t, json.Unmarshal(env.Data, &data))
	assert.NotEmpty(t, data["private_key"])
	assert.NotEmpty(t, data["public_key"])
}
