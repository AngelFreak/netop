package types

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestConfigYAMLMarshalUnmarshal(t *testing.T) {
	config := Config{
		Common: CommonConfig{
			MAC:      "aa:bb:cc:dd:ee:ff",
			DNS:      []string{"8.8.8.8", "1.1.1.1"},
			Hostname: "test-host",
			VPN:      "wireguard",
		},
		Ignored: IgnoredConfig{
			Interfaces: []string{"lo", "eth0"},
		},
		VPN: map[string]VPNConfig{
			"home": {
				Type:      "wireguard",
				Config:    "config data",
				Address:   "10.0.0.1/24",
				Interface: "wg0",
				Gateway:   true,
			},
		},
		Networks: map[string]NetworkConfig{
			"office": {
				Interface: "wlan0",
				SSID:      "OfficeWiFi",
				PSK:       "password",
				Addr:      "192.168.1.100/24",
				Gateway:   "192.168.1.1",
				Routes:    []string{},
				DNS:       []string{"8.8.8.8"},
				MAC:       "aa:bb:cc:dd:ee:ff",
				Hostname:  "office-laptop",
				VPN:       "home",
			},
		},
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&config)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal back
	var unmarshaled Config
	err = yaml.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, config, unmarshaled)
}

func TestWiFiNetwork(t *testing.T) {
	network := WiFiNetwork{
		SSID:      "TestNetwork",
		BSSID:     "aa:bb:cc:dd:ee:ff",
		Signal:    -50,
		Security:  "WPA2",
		Frequency: 2412,
	}

	assert.Equal(t, "TestNetwork", network.SSID)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", network.BSSID)
	assert.Equal(t, -50, network.Signal)
	assert.Equal(t, "WPA2", network.Security)
	assert.Equal(t, 2412, network.Frequency)
}

func TestConnection(t *testing.T) {
	connection := Connection{
		Interface: "wlan0",
		SSID:      "TestWiFi",
		State:     "connected",
		IP:        net.ParseIP("192.168.1.100"),
		Gateway:   net.ParseIP("192.168.1.1"),
		DNS:       []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")},
	}

	assert.Equal(t, "wlan0", connection.Interface)
	assert.Equal(t, "TestWiFi", connection.SSID)
	assert.Equal(t, "connected", connection.State)
	assert.Equal(t, net.ParseIP("192.168.1.100"), connection.IP)
	assert.Equal(t, net.ParseIP("192.168.1.1"), connection.Gateway)
	assert.Len(t, connection.DNS, 2)
}

func TestVPNStatus(t *testing.T) {
	status := VPNStatus{
		Name:      "home",
		Type:      "wireguard",
		Connected: true,
		Interface: "wg0",
		IP:        net.ParseIP("10.0.0.1"),
	}

	assert.Equal(t, "home", status.Name)
	assert.Equal(t, "wireguard", status.Type)
	assert.True(t, status.Connected)
	assert.Equal(t, "wg0", status.Interface)
	assert.Equal(t, net.ParseIP("10.0.0.1"), status.IP)
}

func TestNetworkConfigJSON(t *testing.T) {
	config := NetworkConfig{
		Interface: "wlan0",
		SSID:      "Test",
		PSK:       "secret",
		Addr:      "192.168.1.100/24",
		Gateway:   "192.168.1.1",
		DNS:       []string{"8.8.8.8"},
		MAC:       "aa:bb:cc:dd:ee:ff",
		Hostname:  "test-host",
		VPN:       "home",
	}

	data, err := json.Marshal(&config)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	var unmarshaled NetworkConfig
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, config, unmarshaled)
}

func TestVPNConfig(t *testing.T) {
	config := VPNConfig{
		Type:      "wireguard",
		Config:    "interface config",
		Address:   "10.0.0.1/24",
		Interface: "wg0",
		Gateway:   true,
	}

	assert.Equal(t, "wireguard", config.Type)
	assert.Equal(t, "interface config", config.Config)
	assert.Equal(t, "10.0.0.1/24", config.Address)
	assert.Equal(t, "wg0", config.Interface)
	assert.True(t, config.Gateway)
}

func TestCommonConfig(t *testing.T) {
	config := CommonConfig{
		MAC:      "aa:bb:cc:dd:ee:ff",
		DNS:      []string{"8.8.8.8", "1.1.1.1"},
		Hostname: "common-host",
		VPN:      "default-vpn",
	}

	assert.Equal(t, "aa:bb:cc:dd:ee:ff", config.MAC)
	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, config.DNS)
	assert.Equal(t, "common-host", config.Hostname)
	assert.Equal(t, "default-vpn", config.VPN)
}

func TestIgnoredConfig(t *testing.T) {
	config := IgnoredConfig{
		Interfaces: []string{"lo", "eth0", "docker0"},
	}

	assert.Equal(t, []string{"lo", "eth0", "docker0"}, config.Interfaces)
}
