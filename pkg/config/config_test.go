package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLogger for testing
type mockLogger struct {
	debugMessages []string
	warnMessages  []string
}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {
	m.debugMessages = append(m.debugMessages, msg)
}
func (m *mockLogger) Info(msg string, fields ...interface{}) {}
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

// Viper lowercases all map keys when unmarshalling, so a VPN defined as
// "Work-VPN" in YAML is stored under "work-vpn" while references to it
// (common.vpn or a network's vpn: field) keep their original case.
// GetVPNConfig must resolve those case-preserved references.
func TestGetVPNConfig_MixedCaseName(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	content := `
common:
  vpn: Work-VPN

vpn:
  Work-VPN:
    type: netbird
    profile: work

home:
  ssid: MyWifi
  vpn: Work-VPN
`
	require.NoError(t, os.WriteFile(configFile, []byte(content), 0600))

	manager := NewManager(&mockLogger{})
	_, err := manager.LoadConfig(configFile)
	require.NoError(t, err)

	// Direct lookup with the case-preserved name from the network's vpn: field
	vpnConfig, err := manager.GetVPNConfig("Work-VPN")
	require.NoError(t, err)
	assert.Equal(t, "netbird", vpnConfig.Type)
	assert.Equal(t, "work", vpnConfig.Profile)

	// The merged network config's VPN reference must also resolve
	netConfig, err := manager.GetNetworkConfig("home")
	require.NoError(t, err)
	merged := manager.MergeWithCommon("home", netConfig)
	_, err = manager.GetVPNConfig(merged.VPN)
	assert.NoError(t, err)
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
		name               string
		config             string
		expectedCount      int
		expectedField      string
		expectedSuggestion string
	}{
		{
			name: "typo in common - dhs instead of dns",
			config: `common:
  dhs:
    - 8.8.8.8
`,
			expectedCount:      1,
			expectedField:      "dhs",
			expectedSuggestion: "dns",
		},
		{
			name: "typo in network - ssd instead of ssid",
			config: `testnet:
  ssd: test
`,
			expectedCount:      1,
			expectedField:      "ssd",
			expectedSuggestion: "ssid",
		},
		{
			name: "typo in vpn config - tipe instead of type",
			config: `vpn:
  myvpn:
    tipe: openvpn
`,
			expectedCount:      1,
			expectedField:      "tipe",
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
	// Note: These are debug-level messages to avoid noise on every invocation
	// Users can see them with --debug flag
	t.Run("logs debug message about psk", func(t *testing.T) {
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

		assert.Len(t, logger.debugMessages, 1)
		assert.Contains(t, logger.debugMessages[0], "WiFi password")
	})

	t.Run("logs debug message about vpn private key", func(t *testing.T) {
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

		assert.Len(t, logger.debugMessages, 1)
		assert.Contains(t, logger.debugMessages[0], "VPN contains private key")
	})

	t.Run("logs debug messages about both psk and vpn key", func(t *testing.T) {
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

		assert.Len(t, logger.debugMessages, 2)
	})

	t.Run("no debug messages for safe config", func(t *testing.T) {
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

		assert.Len(t, logger.debugMessages, 0)
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

func TestValidateConfig_TailscaleAndNetBirdFields(t *testing.T) {
	raw := map[string]interface{}{
		"vpn": map[string]interface{}{
			"my-tailscale": map[string]interface{}{
				"type":          "tailscale",
				"auth_key":      "tskey-auth-xxxxx",
				"exit_node":     "us-east-1",
				"accept_routes": true,
			},
			"my-netbird": map[string]interface{}{
				"type":           "netbird",
				"setup_key":      "XXXXXXXX",
				"management_url": "https://api.netbird.io",
			},
		},
	}

	errors := validateRawConfig(raw)
	assert.Empty(t, errors, "Tailscale and NetBird fields should be valid: %v", errors)
}

func TestLoadConfig_WarnsAboutDanglingVPNRefs(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	content := `
common:
  vpn: does-not-exist

vpn:
  real-vpn:
    type: wireguard

home:
  ssid: MyWifi
  vpn: real-vpn

office:
  ssid: OfficeWifi
  vpn: also-missing
`
	require.NoError(t, os.WriteFile(configFile, []byte(content), 0600))

	logger := &mockLogger{}
	manager := NewManager(logger)
	_, err := manager.LoadConfig(configFile)
	require.NoError(t, err)

	// common.vpn and office.vpn reference undefined VPNs; home.vpn is fine
	warnings := strings.Join(logger.warnMessages, "\n")
	assert.Contains(t, warnings, "Config references a VPN that is not defined")
	count := strings.Count(warnings, "Config references a VPN that is not defined")
	assert.Equal(t, 2, count, "expected warnings for common and office only")
}

// The route-metric field (types.NetworkConfig.Metric, feature ccef543) must be
// an accepted config field — otherwise any config that sets it fails to load.
func TestLoadConfig_MetricFieldAccepted(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	content := `
home:
  ssid: MyWifi
  metric: 200
`
	require.NoError(t, os.WriteFile(configFile, []byte(content), 0600))

	manager := NewManager(&mockLogger{})
	_, err := manager.LoadConfig(configFile)
	require.NoError(t, err, "metric is a valid field and must not fail config load")

	nc, err := manager.GetNetworkConfig("home")
	require.NoError(t, err)
	assert.Equal(t, 200, nc.Metric)
}

// An alias whose target contains $(hostname) must resolve to the host-specific
// network block (documented "static: static-$(hostname)" pattern).
func TestGetNetworkConfig_AliasWithHostnameSubstitution(t *testing.T) {
	host, err := os.Hostname()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf(`
static: static-$(hostname)

static-%s:
  ssid: HostWifi
  vpn: work
`, host)
	require.NoError(t, os.WriteFile(configFile, []byte(content), 0600))

	manager := NewManager(&mockLogger{})
	_, err = manager.LoadConfig(configFile)
	require.NoError(t, err)

	nc, err := manager.GetNetworkConfig("static")
	require.NoError(t, err, "alias with $(hostname) must resolve")
	assert.Equal(t, "HostWifi", nc.SSID)
}

// Resolving a network via an alias must make the target's config (incl. VPN)
// findable under the ALIAS name, so connectVPN(aliasName) doesn't skip the VPN.
func TestGetNetworkConfig_AliasCachedUnderAliasName(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	content := `
work: home

home:
  ssid: MyWifi
  vpn: office-vpn
`
	require.NoError(t, os.WriteFile(configFile, []byte(content), 0600))

	manager := NewManager(&mockLogger{})
	cfg, err := manager.LoadConfig(configFile)
	require.NoError(t, err)

	// Connecting via the alias resolves it...
	_, err = manager.GetNetworkConfig("work")
	require.NoError(t, err)

	// ...and the resolved config (with the VPN) is now indexable by the alias
	// name, which is what connectVPN(name) relies on.
	resolved, ok := cfg.Networks["work"]
	assert.True(t, ok, "alias must be cached under its own name for connectVPN")
	assert.Equal(t, "office-vpn", resolved.VPN)
}

// loadPortalConfig writes content to a temp config file and loads it through
// the real Manager, so every portal test exercises actual load+validation.
func loadPortalConfig(t *testing.T, content string) (*types.Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return NewManager(&mockLogger{}).LoadConfig(path)
}

func TestPortalConfigParsing(t *testing.T) {
	// NB: `check: off` is deliberately unquoted — yaml.v3 must keep it a string.
	cfg, err := loadPortalConfig(t, `
common:
  portal:
    check: off
    url: http://example.com/probe
  timeouts:
    portal: 7
`)
	assert.NoError(t, err)
	assert.Equal(t, "off", cfg.Common.Portal.Check)
	assert.True(t, cfg.Common.Portal.CheckDisabled())
	assert.Equal(t, "http://example.com/probe", cfg.Common.Portal.URL)
	assert.Equal(t, 7*time.Second, cfg.Common.Timeouts.GetPortalTimeout())
}

func TestPortalConfigUnknownFieldRejected(t *testing.T) {
	_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    chek: off\n")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chek")
}

func TestPortalConfigBadCheckValueRejected(t *testing.T) {
	_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    check: sometimes\n")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `must be "auto" or "off"`)
}

func TestPortalConfigNonStringCheckRejected(t *testing.T) {
	// Viper weak-typing coerces YAML bools/ints to "0"/"1" with NO decode
	// error (verified empirically), which would silently invert the user's
	// intent. Raw-map validation must reject non-strings before unmarshal.
	for _, val := range []string{"false", "true", "1"} {
		_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    check: "+val+"\n")
		assert.Error(t, err, "check: %s must be rejected", val)
		assert.Contains(t, err.Error(), `must be "auto" or "off"`)
	}
}

func TestPortalConfigBadURLRejected(t *testing.T) {
	// ProbeURL is printed verbatim by the CLI (display-safety contract), so
	// the configured URL is validated at load.
	for _, u := range []string{"https://example.com/p", "http:foo", "ftp://x/", "not a url"} {
		_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    url: \""+u+"\"\n")
		assert.Error(t, err, "url %q must be rejected", u)
	}
}

func TestPortalConfigNonStringURLRejected(t *testing.T) {
	// Same weak-typing trap as check: a YAML bool/int/list url must fail
	// with the explicit message, not coerce or produce a mapstructure mess.
	for _, line := range []string{"url: true", "url: 1", "url: [http://x]"} {
		_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    "+line+"\n")
		assert.Error(t, err, "%q must be rejected", line)
		assert.Contains(t, err.Error(), "common.portal.url must be a string")
	}
}

func TestPortalConfigScalarPortalRejected(t *testing.T) {
	// A scalar or list portal: value must fail with the explicit mapping
	// message, not a cryptic mapstructure decode error or a silent zero.
	for _, portalLine := range []string{"portal: off", "portal: true", "portal: [auto]"} {
		_, err := loadPortalConfig(t, "\ncommon:\n  "+portalLine+"\n")
		assert.Error(t, err, "%q must be rejected", portalLine)
		assert.Contains(t, err.Error(), "must be a mapping")
	}
}

func TestPortalConfigNullPortalSectionAllowed(t *testing.T) {
	// yaml.v3 yields exists=true, value=nil for both forms — that is a valid
	// "stub" (defaults apply), NOT a mapping violation. Guards against a
	// naive type-switch that rejects nil alongside scalars.
	for name, y := range map[string]string{
		"bare key":      "\ncommon:\n  portal:\n",
		"explicit null": "\ncommon:\n  portal: null\n",
	} {
		_, err := loadPortalConfig(t, y)
		assert.NoError(t, err, name)
	}
}

func TestPortalConfigEmptyURLAllowed(t *testing.T) {
	// Three explicit, complete YAML shapes: empty string, null, absent key.
	for name, configContent := range map[string]string{
		"empty string": "\ncommon:\n  portal:\n    url: \"\"\n",
		"null":         "\ncommon:\n  portal:\n    url:\n",
		"absent":       "\ncommon:\n  portal: {}\n",
	} {
		_, err := loadPortalConfig(t, configContent)
		assert.NoError(t, err, "portal url form %s must be accepted", name)
	}
}
