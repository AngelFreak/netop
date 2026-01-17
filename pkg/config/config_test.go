package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLogger for testing
type mockLogger struct {
	warnMessages []string
}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{}) {
	m.warnMessages = append(m.warnMessages, msg)
}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}

func TestNewManager(t *testing.T) {
	manager := NewManager(&mockLogger{})
	assert.NotNil(t, manager)
	assert.Nil(t, manager.config)
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		setup       func() (cleanup func())
		expectError bool
		// Networks are lazy-loaded, so we test common/ignored/vpn here
		// and test network loading separately via GetNetworkConfig
		expectedCommon  types.CommonConfig
		expectedIgnored types.IgnoredConfig
	}{
		{
			name:            "no config path",
			path:            "-",
			expectedCommon:  types.CommonConfig{},
			expectedIgnored: types.IgnoredConfig{},
		},
		{
			name: "default path",
			path: "",
			setup: func() (cleanup func()) {
				// Create unique temp dir to avoid conflicts
				home, err := os.MkdirTemp("", "test_home_default_*")
				if err != nil {
					panic(err)
				}
				// Unset SUDO_USER to test HOME-based path resolution
				// (SUDO_USER takes priority over HOME in production)
				oldSudoUser := os.Getenv("SUDO_USER")
				os.Unsetenv("SUDO_USER")
				// Set HOME BEFORE creating the config dir structure
				oldHome := os.Getenv("HOME")
				os.Setenv("HOME", home)

				os.MkdirAll(filepath.Join(home, ".net"), 0755)
				configPath := filepath.Join(home, ".net", "config.yaml")
				configContent := `common:
  dns:
    - 8.8.8.8
testnet:
  ssid: test
`
				os.WriteFile(configPath, []byte(configContent), 0644)
				return func() {
					os.Setenv("HOME", oldHome)
					if oldSudoUser != "" {
						os.Setenv("SUDO_USER", oldSudoUser)
					}
					os.RemoveAll(home)
				}
			},
			expectedCommon: types.CommonConfig{
				DNS: []string{"8.8.8.8"},
			},
			expectedIgnored: types.IgnoredConfig{},
		},
		{
			name: "tilde expansion",
			path: "~/test_config.yaml",
			setup: func() (cleanup func()) {
				// Create unique temp dir to avoid conflicts
				home, err := os.MkdirTemp("", "test_home_tilde_*")
				if err != nil {
					panic(err)
				}
				// Unset SUDO_USER to test HOME-based tilde expansion
				oldSudoUser := os.Getenv("SUDO_USER")
				os.Unsetenv("SUDO_USER")
				// Set HOME BEFORE creating the config file
				oldHome := os.Getenv("HOME")
				os.Setenv("HOME", home)

				configPath := filepath.Join(home, "test_config.yaml")
				configContent := `tilde_net:
  ssid: tilde
`
				os.WriteFile(configPath, []byte(configContent), 0644)
				return func() {
					os.Setenv("HOME", oldHome)
					if oldSudoUser != "" {
						os.Setenv("SUDO_USER", oldSudoUser)
					}
					os.RemoveAll(home)
				}
			},
			expectedCommon:  types.CommonConfig{},
			expectedIgnored: types.IgnoredConfig{},
		},
		{
			name:            "file not exists",
			path:            "/nonexistent/config.yaml",
			expectedCommon:  types.CommonConfig{},
			expectedIgnored: types.IgnoredConfig{},
		},
		{
			name: "invalid yaml",
			path: "/tmp/invalid.yaml",
			setup: func() (cleanup func()) {
				os.WriteFile("/tmp/invalid.yaml", []byte("invalid: yaml: content: ["), 0644)
				return func() {
					os.Remove("/tmp/invalid.yaml")
				}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setup != nil {
				cleanup = tt.setup()
				defer cleanup()
			}

			manager := NewManager(&mockLogger{})
			config, err := manager.LoadConfig(tt.path)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, config)
				assert.Equal(t, tt.expectedCommon, config.Common)
				assert.Equal(t, tt.expectedIgnored, config.Ignored)
				assert.NotNil(t, config.Networks)
				assert.NotNil(t, config.VPN)
			}
		})
	}
}

func TestLoadConfig_NetworkLoading(t *testing.T) {
	// Test that networks are loaded during config load
	// Create unique temp dir to avoid conflicts
	home, err := os.MkdirTemp("", "test_home_netload_*")
	require.NoError(t, err)
	// Unset SUDO_USER to test HOME-based path resolution
	oldSudoUser := os.Getenv("SUDO_USER")
	os.Unsetenv("SUDO_USER")
	// Set HOME BEFORE creating the config dir structure
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", home)
	defer func() {
		os.Setenv("HOME", oldHome)
		if oldSudoUser != "" {
			os.Setenv("SUDO_USER", oldSudoUser)
		}
		os.RemoveAll(home)
	}()

	os.MkdirAll(filepath.Join(home, ".net"), 0755)
	configPath := filepath.Join(home, ".net", "config.yaml")
	configContent := `common:
  dns:
    - 8.8.8.8
testnet:
  ssid: test
testnet2:
  ssid: test2
  psk: password123
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	manager := NewManager(&mockLogger{})
	config, err := manager.LoadConfig("")
	require.NoError(t, err)
	assert.NotNil(t, config)

	// Networks should be loaded upfront
	assert.Len(t, config.Networks, 2)
	assert.Equal(t, "test", config.Networks["testnet"].SSID)
	assert.Equal(t, "test2", config.Networks["testnet2"].SSID)

	// GetNetworkConfig should still work
	netConfig, err := manager.GetNetworkConfig("testnet")
	require.NoError(t, err)
	assert.Equal(t, "test", netConfig.SSID)
}

func TestGetNetworkConfig(t *testing.T) {
	hostname, _ := os.Hostname()

	// Create a temp config file to test with
	// Create unique temp dir to avoid conflicts
	home, err := os.MkdirTemp("", "test_home_get_network_*")
	require.NoError(t, err)
	// Unset SUDO_USER to test HOME-based path resolution
	oldSudoUser := os.Getenv("SUDO_USER")
	os.Unsetenv("SUDO_USER")
	// Set HOME BEFORE creating the config dir structure
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", home)
	defer func() {
		os.Setenv("HOME", oldHome)
		if oldSudoUser != "" {
			os.Setenv("SUDO_USER", oldSudoUser)
		}
		os.RemoveAll(home)
	}()

	os.MkdirAll(filepath.Join(home, ".net"), 0755)
	configPath := filepath.Join(home, ".net", "config.yaml")
	configContent := fmt.Sprintf(`testnet:
  ssid: test
%s:
  ssid: host
`, hostname)
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	manager := NewManager(&mockLogger{})
	_, err = manager.LoadConfig("")
	require.NoError(t, err)

	tests := []struct {
		name        string
		networkName string
		expected    *types.NetworkConfig
		expectError bool
	}{
		{
			name:        "existing network",
			networkName: "testnet",
			expected:    &types.NetworkConfig{SSID: "test"},
		},
		{
			name:        "non-existing network",
			networkName: "nonexistent",
			expectError: true,
		},
		{
			name:        "hostname substitution",
			networkName: "$(hostname)",
			expected:    &types.NetworkConfig{SSID: "host"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := manager.GetNetworkConfig(tt.networkName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetNetworkConfig_NoConfig(t *testing.T) {
	manager := NewManager(&mockLogger{})
	_, err := manager.GetNetworkConfig("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config not loaded")
}

func TestGetVPNConfig(t *testing.T) {
	manager := NewManager(&mockLogger{})
	config := &types.Config{
		VPN: map[string]types.VPNConfig{
			"testvpn": {Type: "wireguard"},
		},
	}
	manager.config = config

	t.Run("existing vpn", func(t *testing.T) {
		result, err := manager.GetVPNConfig("testvpn")
		require.NoError(t, err)
		assert.Equal(t, &types.VPNConfig{Type: "wireguard"}, result)
	})

	t.Run("non-existing vpn", func(t *testing.T) {
		_, err := manager.GetVPNConfig("nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VPN configuration 'nonexistent' not found")
	})

	t.Run("no config loaded", func(t *testing.T) {
		manager.config = nil
		_, err := manager.GetVPNConfig("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config not loaded")
	})
}

func TestMergeWithCommon(t *testing.T) {
	manager := NewManager(&mockLogger{})
	config := &types.Config{
		Common: types.CommonConfig{
			DNS:      []string{"1.1.1.1"},
			MAC:      "aa:bb:cc:dd:ee:ff",
			Hostname: "common-host",
			VPN:      "common-vpn",
		},
	}
	manager.config = config

	networkConfig := &types.NetworkConfig{
		Interface: "wlan0",
		SSID:      "test",
	}

	// Mock hostname
	oldHostname := os.Getenv("HOSTNAME")
	os.Setenv("HOSTNAME", "test-host")
	defer os.Setenv("HOSTNAME", oldHostname)

	result := manager.MergeWithCommon("testnet", networkConfig)

	assert.Equal(t, "wlan0", result.Interface)
	assert.Equal(t, "test", result.SSID)
	assert.Equal(t, []string{"1.1.1.1"}, result.DNS)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", result.MAC)
	assert.Equal(t, "common-host", result.Hostname)
	assert.Equal(t, "common-vpn", result.VPN)
}

func TestMergeWithCommon_HostnameTemplate(t *testing.T) {
	// The <name> template is replaced with a random common first name
	manager := NewManager(&mockLogger{})
	config := &types.Config{
		Common: types.CommonConfig{
			Hostname: "prefix-<name>-suffix",
		},
	}
	manager.config = config

	networkConfig := &types.NetworkConfig{}

	result := manager.MergeWithCommon("testnet", networkConfig)

	// Verify the template was replaced (no longer contains <name>)
	assert.NotContains(t, result.Hostname, "<name>")
	// Verify the format is correct (prefix-SomeName-suffix)
	assert.True(t, strings.HasPrefix(result.Hostname, "prefix-"))
	assert.True(t, strings.HasSuffix(result.Hostname, "-suffix"))
	// Extract the name and verify it's a valid first name (non-empty, alphabetic)
	name := strings.TrimPrefix(result.Hostname, "prefix-")
	name = strings.TrimSuffix(name, "-suffix")
	assert.NotEmpty(t, name)
	// Name should be alphabetic (from commonFirstNames list)
	for _, r := range name {
		assert.True(t, (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'),
			"Name should only contain letters, got: %s", name)
	}
}

func TestMergeWithCommon_NoConfig(t *testing.T) {
	manager := NewManager(&mockLogger{})
	networkConfig := &types.NetworkConfig{SSID: "test"}
	result := manager.MergeWithCommon("testnet", networkConfig)
	assert.Equal(t, networkConfig, result)
}

func TestMergeWithCommon_VPNExplicitlyDisabled(t *testing.T) {
	// Test that vpn: (empty/null in YAML) disables VPN inheritance
	// Create a temp config file with vpn: set to null
	tmpFile, err := os.CreateTemp("", "vpn_test_*.yaml")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	configContent := `
common:
  vpn: common-vpn

wired:
  dns: dhcp
  vpn:

wireless:
  ssid: TestWiFi
`
	_, err = tmpFile.WriteString(configContent)
	assert.NoError(t, err)
	tmpFile.Close()

	manager := NewManager(&mockLogger{})
	_, err = manager.LoadConfig(tmpFile.Name())
	assert.NoError(t, err)

	// wired has vpn: (empty) - should NOT inherit from common
	wiredConfig := &types.NetworkConfig{Interface: "eth0"}
	wiredResult := manager.MergeWithCommon("wired", wiredConfig)
	assert.Equal(t, "", wiredResult.VPN, "wired should have no VPN (explicitly disabled)")

	// wireless has no vpn key - should inherit from common
	wirelessConfig := &types.NetworkConfig{SSID: "TestWiFi"}
	wirelessResult := manager.MergeWithCommon("wireless", wirelessConfig)
	assert.Equal(t, "common-vpn", wirelessResult.VPN, "wireless should inherit VPN from common")
}

func TestGetIgnoredInterfaces(t *testing.T) {
	manager := NewManager(&mockLogger{})

	t.Run("with config", func(t *testing.T) {
		config := &types.Config{
			Ignored: types.IgnoredConfig{
				Interfaces: []string{"lo", "eth0"},
			},
		}
		manager.config = config
		result := manager.GetIgnoredInterfaces()
		assert.Equal(t, []string{"lo", "eth0"}, result)
	})

	t.Run("no config", func(t *testing.T) {
		manager.config = nil
		result := manager.GetIgnoredInterfaces()
		assert.Nil(t, result)
	})
}

func TestGetConfig(t *testing.T) {
	manager := NewManager(&mockLogger{})
	config := &types.Config{}
	manager.config = config
	result := manager.GetConfig()
	assert.Equal(t, config, result)
}

func TestValidateConfigFile_ValidConfig(t *testing.T) {
	// Create a temp config file with valid fields
	tmpFile := "/tmp/valid_config.yaml"
	configContent := `common:
  dns:
    - 8.8.8.8
  mac: random
  hostname: test
  vpn: myvpn

ignored:
  interfaces:
    - docker0

vpn:
  myvpn:
    type: openvpn
    config: |
      client

testnet:
  ssid: test
  psk: password
  interface: wlan0
  dns:
    - 1.1.1.1
  mac: default
  hostname: myhost
  vpn: myvpn
  ap-addr: 00:11:22:33:44:55
  addr: 192.168.1.10/24
  gateway: 192.168.1.1
  routes:
    - default
  wpa: |
    network={}
`
	os.WriteFile(tmpFile, []byte(configContent), 0644)
	defer os.Remove(tmpFile)

	errors := ValidateConfigFile(tmpFile)
	assert.Len(t, errors, 0)
}

func TestValidateConfigFile_InvalidFields(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		expectedCount int
		expectedField string
		expectedSuggestion string
	}{
		{
			name: "typo in common - dhs instead of dns",
			config: `common:
  dhs:
    - 8.8.8.8
`,
			expectedCount: 1,
			expectedField: "dhs",
			expectedSuggestion: "dns",
		},
		{
			name: "typo in network - ssd instead of ssid",
			config: `testnet:
  ssd: test
`,
			expectedCount: 1,
			expectedField: "ssd",
			expectedSuggestion: "ssid",
		},
		{
			name: "typo in vpn config - tipe instead of type",
			config: `vpn:
  myvpn:
    tipe: openvpn
`,
			expectedCount: 1,
			expectedField: "tipe",
			expectedSuggestion: "type",
		},
		{
			name: "multiple typos",
			config: `common:
  dhs:
    - 8.8.8.8
testnet:
  ssd: test
  pks: password
`,
			expectedCount: 3,
		},
		{
			name: "completely invalid field",
			config: `testnet:
  invalid_field: value
`,
			expectedCount: 1,
			expectedField: "invalid_field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := "/tmp/test_invalid_config.yaml"
			os.WriteFile(tmpFile, []byte(tt.config), 0644)
			defer os.Remove(tmpFile)

			errors := ValidateConfigFile(tmpFile)
			assert.Len(t, errors, tt.expectedCount)

			if tt.expectedCount > 0 && tt.expectedField != "" {
				found := false
				for _, err := range errors {
					if err.Field == tt.expectedField {
						found = true
						if tt.expectedSuggestion != "" {
							assert.Equal(t, tt.expectedSuggestion, err.Suggestion)
						}
						break
					}
				}
				assert.True(t, found, "Expected field '%s' not found in errors", tt.expectedField)
			}
		})
	}
}

func TestValidateConfigFile_Aliases(t *testing.T) {
	// Aliases (string values) should not trigger validation errors
	tmpFile := "/tmp/alias_config.yaml"
	configContent := `home: home-network
work: work-$(hostname)

home-network:
  ssid: HomeWiFi
`
	os.WriteFile(tmpFile, []byte(configContent), 0644)
	defer os.Remove(tmpFile)

	errors := ValidateConfigFile(tmpFile)
	assert.Len(t, errors, 0)
}

func TestLoadConfig_WithValidationErrors(t *testing.T) {
	// Create a config with typos
	// Create unique temp dir to avoid conflicts
	home, err := os.MkdirTemp("", "test_home_validation_*")
	require.NoError(t, err)
	// Unset SUDO_USER to test HOME-based path resolution
	oldSudoUser := os.Getenv("SUDO_USER")
	os.Unsetenv("SUDO_USER")
	// Set HOME BEFORE creating the config dir structure
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", home)
	defer func() {
		os.Setenv("HOME", oldHome)
		if oldSudoUser != "" {
			os.Setenv("SUDO_USER", oldSudoUser)
		}
		os.RemoveAll(home)
	}()

	os.MkdirAll(filepath.Join(home, ".net"), 0755)
	configPath := filepath.Join(home, ".net", "config.yaml")
	configContent := `common:
  dhs:
    - 8.8.8.8
testnet:
  ssd: test
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	manager := NewManager(&mockLogger{})
	_, err = manager.LoadConfig("")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dhs")
	assert.Contains(t, err.Error(), "ssd")
	assert.Contains(t, err.Error(), "did you mean")
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected int
	}{
		{"dns", "dns", 0},
		{"dns", "dhs", 1},
		{"ssid", "ssd", 1},
		{"type", "tipe", 1},
		{"gateway", "gatway", 1},
		{"interface", "inteface", 1},
		{"abc", "xyz", 3},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%s", tt.a, tt.b), func(t *testing.T) {
			result := levenshteinDistance(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContainsPrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		expected bool
	}{
		{
			name:     "empty config",
			config:   "",
			expected: false,
		},
		{
			name:     "wireguard private key",
			config:   "[Interface]\nPrivateKey = abc123xyz",
			expected: true,
		},
		{
			name: "openvpn inline key",
			config: `<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBg...
-----END PRIVATE KEY-----
</key>`,
			expected: true,
		},
		{
			name: "pem format key",
			config: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`,
			expected: true,
		},
		{
			name: "ec private key",
			config: `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIGk...
-----END EC PRIVATE KEY-----`,
			expected: true,
		},
		{
			name:     "config without private key",
			config:   "[Interface]\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = xyz",
			expected: false,
		},
		{
			name:     "openvpn config referencing file",
			config:   "client\nremote vpn.example.com\nca /etc/openvpn/ca.crt\nkey /etc/openvpn/client.key",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsPrivateKey(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWarnAboutPlainTextCredentials(t *testing.T) {
	t.Run("warns about psk", func(t *testing.T) {
		logger := &mockLogger{}
		manager := NewManager(logger)
		manager.config = &types.Config{
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi", PSK: "mypassword123"},
				"work": {SSID: "WorkWiFi"}, // no PSK
			},
			VPN: map[string]types.VPNConfig{},
		}

		manager.WarnAboutPlainTextCredentials()

		assert.Len(t, logger.warnMessages, 1)
		assert.Contains(t, logger.warnMessages[0], "WiFi password")
	})

	t.Run("warns about vpn private key", func(t *testing.T) {
		logger := &mockLogger{}
		manager := NewManager(logger)
		manager.config = &types.Config{
			Networks: map[string]types.NetworkConfig{},
			VPN: map[string]types.VPNConfig{
				"myvpn": {
					Type:   "wireguard",
					Config: "[Interface]\nPrivateKey = abc123xyz\n\n[Peer]\nPublicKey = xyz",
				},
			},
		}

		manager.WarnAboutPlainTextCredentials()

		assert.Len(t, logger.warnMessages, 1)
		assert.Contains(t, logger.warnMessages[0], "VPN contains private key")
	})

	t.Run("warns about both psk and vpn key", func(t *testing.T) {
		logger := &mockLogger{}
		manager := NewManager(logger)
		manager.config = &types.Config{
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi", PSK: "mypassword123"},
			},
			VPN: map[string]types.VPNConfig{
				"myvpn": {
					Type:   "wireguard",
					Config: "[Interface]\nPrivateKey = abc123xyz",
				},
			},
		}

		manager.WarnAboutPlainTextCredentials()

		assert.Len(t, logger.warnMessages, 2)
	})

	t.Run("no warnings for safe config", func(t *testing.T) {
		logger := &mockLogger{}
		manager := NewManager(logger)
		manager.config = &types.Config{
			Networks: map[string]types.NetworkConfig{
				"open": {SSID: "OpenWiFi"}, // no PSK
			},
			VPN: map[string]types.VPNConfig{
				"myvpn": {
					Type:   "wireguard",
					Config: "/etc/wireguard/wg0.conf", // file path, no inline key
				},
			},
		}

		manager.WarnAboutPlainTextCredentials()

		assert.Len(t, logger.warnMessages, 0)
	})

	t.Run("nil config", func(t *testing.T) {
		logger := &mockLogger{}
		manager := NewManager(logger)
		manager.config = nil

		// Should not panic
		manager.WarnAboutPlainTextCredentials()

		assert.Len(t, logger.warnMessages, 0)
	})

	t.Run("nil logger", func(t *testing.T) {
		manager := NewManager(nil)
		manager.config = &types.Config{
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi", PSK: "password"},
			},
			VPN: map[string]types.VPNConfig{},
		}

		// Should not panic
		manager.WarnAboutPlainTextCredentials()
	})
}
