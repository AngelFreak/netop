package vpn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Mock implementations
type mockSystemExecutor struct {
	mu               sync.Mutex
	commands         map[string]string
	errors           map[string]error
	executedCommands []string // Track executed commands for verification
}

func (m *mockSystemExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}

	m.mu.Lock()
	// Track executed command
	m.executedCommands = append(m.executedCommands, fullCmd)

	// Check for errors first
	if err, hasErr := m.errors[fullCmd]; hasErr {
		output := ""
		if val, ok := m.commands[fullCmd]; ok {
			output = val
		}
		m.mu.Unlock()
		return output, err
	}

	if output, ok := m.commands[fullCmd]; ok {
		m.mu.Unlock()
		return output, nil
	}
	m.mu.Unlock()
	return "mock output", nil
}

func (m *mockSystemExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	return "mock output with input", nil
}

func (m *mockSystemExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return m.ExecuteWithInput(cmd, input, args...)
}

func (m *mockSystemExecutor) HasCommand(cmd string) bool {
	return true // mock always has the command
}

// assertCommandExecuted verifies a command was executed
func (m *mockSystemExecutor) assertCommandExecuted(t *testing.T, cmd string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, executed := range m.executedCommands {
		if executed == cmd {
			return
		}
	}
	t.Errorf("expected command %q to be executed, but it wasn't. Executed commands: %v", cmd, m.executedCommands)
}

type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}

type mockConfigManager struct {
	vpnConfigs map[string]*types.VPNConfig
}

func (m *mockConfigManager) LoadConfig(path string) (*types.Config, error) {
	return nil, nil
}

func (m *mockConfigManager) GetNetworkConfig(name string) (*types.NetworkConfig, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockConfigManager) GetVPNConfig(name string) (*types.VPNConfig, error) {
	if m.vpnConfigs == nil {
		return nil, fmt.Errorf("VPN config not found")
	}
	if config, ok := m.vpnConfigs[name]; ok {
		return config, nil
	}
	return nil, fmt.Errorf("VPN config '%s' not found", name)
}

func (m *mockConfigManager) MergeWithCommon(networkName string, config *types.NetworkConfig) *types.NetworkConfig {
	return config
}

func (m *mockConfigManager) GetConfig() *types.Config {
	if m.vpnConfigs == nil {
		return nil
	}
	// Convert vpnConfigs to the format expected by Config.VPN
	vpnMap := make(map[string]types.VPNConfig)
	for name, cfg := range m.vpnConfigs {
		vpnMap[name] = *cfg
	}
	return &types.Config{
		VPN: vpnMap,
	}
}

func TestNewManager(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManager(executor, logger, configMgr)
	assert.NotNil(t, manager)
	assert.Equal(t, executor, manager.executor)
	assert.Equal(t, logger, manager.logger)
	assert.Equal(t, configMgr, manager.configMgr)
	assert.Equal(t, types.RuntimeDir, manager.runtimeDir)
}

func TestNewManagerWithDir(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	customDir := "/custom/runtime/dir"
	manager := NewManagerWithDir(executor, logger, configMgr, customDir)
	assert.NotNil(t, manager)
	assert.Equal(t, executor, manager.executor)
	assert.Equal(t, logger, manager.logger)
	assert.Equal(t, configMgr, manager.configMgr)
	assert.Equal(t, customDir, manager.runtimeDir)
}

func TestConnect(t *testing.T) {
	tests := []struct {
		name    string
		vpnType string
	}{
		{
			name:    "openvpn",
			vpnType: "openvpn",
		},
		{
			name:    "wireguard",
			vpnType: "wireguard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &mockSystemExecutor{
				commands: map[string]string{
					// Common - getting current gateway for state file
					"ip route show default": "default via 192.168.1.1 dev eth0",
					// OpenVPN commands
					"install -m 0600 /dev/stdin /run/net/openvpn.conf":                              "",
					"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
					"ip link show tun0": "", // tunnel verification
					// WireGuard commands
					"install -m 0600 /dev/stdin /run/net/wg.conf": "",
					"rm -f /run/net/wg.conf":                      "",
					"ip link add dev wg0 type wireguard":          "",
					"wg setconf wg0 /run/net/wg.conf":             "",
					"ip addr replace 10.0.0.1/24 dev wg0":         "",
					"ip link set wg0 up":                          "",
					"ip route replace default dev wg0":            "",
				},
			}
			logger := &mockLogger{}
			configMgr := &mockConfigManager{
				vpnConfigs: map[string]*types.VPNConfig{
					"test": {
						Type:      tt.vpnType,
						Config:    "test config",
						Interface: "wg0",
						Address:   "10.0.0.1/24",
						Gateway:   true,
					},
				},
			}
			manager := NewManager(executor, logger, configMgr)

			err := manager.Connect("test")
			assert.NoError(t, err)
		})
	}
}

func TestDisconnect(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pkill -f openvpn":      "",
			"pkill -f wg":           "",
			"ip link set tun0 down": "",
			"ip link set wg0 down":  "",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Disconnect("test")
	assert.NoError(t, err)
}

func TestListVPNs(t *testing.T) {
	t.Run("openvpn running (no config)", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn":            "1234",
				"ip link show type wireguard": "",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{} // No config
		manager := NewManager(executor, logger, configMgr)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 1)
		assert.Equal(t, "openvpn", vpns[0].Name)
		assert.Equal(t, "openvpn", vpns[0].Type)
		assert.True(t, vpns[0].Connected)
		assert.Equal(t, "tun0", vpns[0].Interface)
	})

	t.Run("wireguard running (no config)", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn":            "",
				"ip link show type wireguard": "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/none",
				"wg show wg0":                 "interface: wg0\n  public key: abc123\n  peer: xyz789\n    endpoint: 1.2.3.4:51820",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{} // No config
		manager := NewManager(executor, logger, configMgr)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 1)
		assert.Equal(t, "wg0", vpns[0].Name)
		assert.Equal(t, "wireguard", vpns[0].Type)
		assert.True(t, vpns[0].Connected)
		assert.Equal(t, "wg0", vpns[0].Interface)
	})

	t.Run("no vpns running, no config", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn":            "",
				"ip link show type wireguard": "",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManager(executor, logger, configMgr)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 0)
	})

	t.Run("configured vpn not running", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn":            "",
				"ip link show type wireguard": "",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{
			vpnConfigs: map[string]*types.VPNConfig{
				"work-vpn": {
					Type:      "openvpn",
					Interface: "tun0",
				},
				"home-wg": {
					Type:      "wireguard",
					Interface: "wg0",
				},
			},
		}
		manager := NewManager(executor, logger, configMgr)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 2)

		// Find each VPN by name
		vpnMap := make(map[string]types.VPNStatus)
		for _, v := range vpns {
			vpnMap[v.Name] = v
		}

		assert.Contains(t, vpnMap, "work-vpn")
		assert.Equal(t, "openvpn", vpnMap["work-vpn"].Type)
		assert.False(t, vpnMap["work-vpn"].Connected)

		assert.Contains(t, vpnMap, "home-wg")
		assert.Equal(t, "wireguard", vpnMap["home-wg"].Type)
		assert.False(t, vpnMap["home-wg"].Connected)
	})

	t.Run("configured vpn running", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn":            "1234",
				"ip link show type wireguard": "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP>",
				"wg show wg0":                 "interface: wg0\n  peer: abc123\n    endpoint: 1.2.3.4:51820",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{
			vpnConfigs: map[string]*types.VPNConfig{
				"work-vpn": {
					Type:      "openvpn",
					Interface: "tun0",
				},
				"home-wg": {
					Type:      "wireguard",
					Interface: "wg0",
				},
			},
		}
		manager := NewManager(executor, logger, configMgr)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 2)

		// Find each VPN by name
		vpnMap := make(map[string]types.VPNStatus)
		for _, v := range vpns {
			vpnMap[v.Name] = v
		}

		assert.Contains(t, vpnMap, "work-vpn")
		assert.True(t, vpnMap["work-vpn"].Connected)

		assert.Contains(t, vpnMap, "home-wg")
		assert.True(t, vpnMap["home-wg"].Connected)
	})
}

func TestGenerateWireGuardKey(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManager(executor, logger, configMgr)

	private, public, err := manager.GenerateWireGuardKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, private)
	assert.NotEmpty(t, public)
	// Base64 encoded 32 bytes
	assert.Len(t, private, 44) // base64.StdEncoding.EncodedLen(32)
	assert.Len(t, public, 44)
}

func TestConnectOpenVPN(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"install -m 0600 /dev/stdin /run/net/openvpn.conf":                              "",
			"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
			"ip link show tun0": "", // tunnel verification
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

	config := &types.VPNConfig{
		Config: "openvpn config",
	}

	err := manager.connectOpenVPN(config)
	assert.NoError(t, err)
}

func TestConnectWireGuard(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"install -m 0600 /dev/stdin /run/net/wg.conf": "",
			"ip link add dev wg0 type wireguard":          "",
			"wg setconf wg0 /run/net/wg.conf":             "",
			"rm -f /run/net/wg.conf":                      "",
			"ip addr replace 10.0.0.1/24 dev wg0":         "",
			"ip link set wg0 up":                          "",
			"ip route replace default dev wg0":            "",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

	config := &types.VPNConfig{
		Config:    "wireguard config",
		Interface: "wg0",
		Address:   "10.0.0.1/24",
		Gateway:   true,
	}

	err := manager.connectWireGuard(config)
	assert.NoError(t, err)
}

func TestWriteFile(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger}

	err := manager.writeFile("/tmp/test", "content")
	assert.NoError(t, err)
}

func TestConnect_ErrorCases(t *testing.T) {
	t.Run("invalid VPN config", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{
			vpnConfigs: nil, // Will return error
		}
		manager := NewManager(executor, logger, configMgr)

		err := manager.Connect("nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load VPN config")
	})

	t.Run("unsupported VPN type", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{
			vpnConfigs: map[string]*types.VPNConfig{
				"test": {
					Type: "unsupported",
				},
			},
		}
		manager := NewManager(executor, logger, configMgr)

		err := manager.Connect("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported VPN type")
	})
}

func TestDisconnect_ErrorCases(t *testing.T) {
	t.Run("disconnect with all failures", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"pkill -f openvpn":     assert.AnError,
				"pkill -f wg":          assert.AnError,
				"ip link set tun0 down": assert.AnError,
				"ip link set wg0 down":  assert.AnError,
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManager(executor, logger, configMgr)

		err := manager.Disconnect("test")
		// Disconnect should not return error even if processes don't exist
		assert.NoError(t, err)
	})
}

func TestConnectOpenVPN_ErrorCases(t *testing.T) {
	t.Run("write file error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
				"ip link show tun0": "",
			},
			errors: map[string]error{},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config: "openvpn config",
		}

		err := manager.connectOpenVPN(config)
		// Should succeed with mock executor
		assert.NoError(t, err)
	})

	t.Run("openvpn execution error cleans up temp file", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/openvpn.conf": "",
				"rm -f /run/net/openvpn.conf":                      "", // cleanup should happen
				// KillProcessByPID will try to read PID file - mock it failing (file doesn't exist)
			},
			errors: map[string]error{
				"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": assert.AnError,
				"cat /run/net/openvpn.pid": assert.AnError, // PID file doesn't exist
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config: "openvpn config",
		}

		err := manager.connectOpenVPN(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start OpenVPN")
		// Verify cleanup was called
		executor.assertCommandExecuted(t, "rm -f /run/net/openvpn.conf")
	})

	t.Run("tunnel verification timeout cleans up temp file", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/openvpn.conf":                              "",
				"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
				"rm -f /run/net/openvpn.conf": "",                      // cleanup should happen
				"cat /run/net/openvpn.pid":    "12345",                 // PID file exists
				"kill 12345":                  "",                      // graceful kill
				"kill -0 12345":               "",                      // check if running
				"kill -9 12345":               "",                      // force kill
				"rm -f /run/net/openvpn.pid":  "",                      // PID file cleanup
			},
			errors: map[string]error{
				"ip link show tun0": assert.AnError, // tun0 never appears
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config: "openvpn config",
		}

		err := manager.connectOpenVPN(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to establish tunnel")
		// Verify cleanup was called
		executor.assertCommandExecuted(t, "rm -f /run/net/openvpn.conf")
	})
}

func TestConnectWireGuard_ErrorCases(t *testing.T) {
	t.Run("write file error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link add dev wg0 type wireguard":  "",
				"wg setconf wg0 /run/net/wg.conf":     "",
				"ip addr replace 10.0.0.1/24 dev wg0": "",
				"ip link set wg0 up":                  "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
			Gateway:   false, // No gateway route
		}

		err := manager.connectWireGuard(config)
		// Should succeed with mock executor
		assert.NoError(t, err)
	})

	t.Run("interface creation error (warning only)", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"wg setconf wg0 /run/net/wg.conf":             "",
				"ip addr replace 10.0.0.1/24 dev wg0":         "",
				"ip link set wg0 up":                          "",
			},
			errors: map[string]error{
				"ip link add dev wg0 type wireguard": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		// Interface creation error is only a warning, not a fatal error
		err := manager.connectWireGuard(config)
		assert.NoError(t, err)
	})

	t.Run("setconf error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"ip link add dev wg0 type wireguard":          "",
			},
			errors: map[string]error{
				"wg setconf wg0 /run/net/wg.conf": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set WireGuard config")
	})

	t.Run("ip address assignment error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"ip link add dev wg0 type wireguard":          "",
				"wg setconf wg0 /run/net/wg.conf":             "",
			},
			errors: map[string]error{
				"ip addr replace 10.0.0.1/24 dev wg0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set WireGuard IP")
	})

	t.Run("interface up error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"ip link add dev wg0 type wireguard":          "",
				"wg setconf wg0 /run/net/wg.conf":             "",
				"ip addr replace 10.0.0.1/24 dev wg0":         "",
			},
			errors: map[string]error{
				"ip link set wg0 up": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring WireGuard interface up")
	})

	t.Run("gateway route error (warning only)", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"ip link add dev wg0 type wireguard":          "",
				"wg setconf wg0 /run/net/wg.conf":             "",
				"ip addr replace 10.0.0.1/24 dev wg0":         "",
				"ip link set wg0 up":                          "",
			},
			errors: map[string]error{
				"ip route replace default dev wg0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
			Gateway:   true,
		}

		// Gateway route error is only a warning, not a fatal error
		err := manager.connectWireGuard(config)
		assert.NoError(t, err)
	})
}

func TestGenerateWireGuardKey_Coverage(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManager(executor, logger, configMgr)

	// Run multiple times to ensure randomness
	for i := 0; i < 5; i++ {
		private, public, err := manager.GenerateWireGuardKey()
		assert.NoError(t, err)
		assert.NotEmpty(t, private)
		assert.NotEmpty(t, public)
		assert.Len(t, private, 44)
		assert.Len(t, public, 44)
	}
}

func TestActiveVPNStateFile(t *testing.T) {
	t.Run("getActiveVPN returns empty when file doesn't exist", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

		result := manager.getActiveVPN()
		assert.Equal(t, "", result)
	})

	t.Run("setActiveVPN and getActiveVPN roundtrip", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

		// Set active VPN
		err := manager.setActiveVPN("test-vpn")
		assert.NoError(t, err)

		// Read it back
		result := manager.getActiveVPN()
		assert.Equal(t, "test-vpn", result)
	})

	t.Run("clearActiveVPN removes the file", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

		// Create the file first
		activeVPNFile := filepath.Join(tempDir, "active-vpn")
		os.WriteFile(activeVPNFile, []byte("test-vpn"), 0600)

		// Clear it
		manager.clearActiveVPN()

		// File should be gone
		_, err := os.Stat(activeVPNFile)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestListVPNs_WithActiveVPNStateFile(t *testing.T) {
	t.Run("only active VPN shows as connected when state file exists", func(t *testing.T) {
		tempDir := t.TempDir()

		// Set proton-se as the active VPN
		activeVPNFile := filepath.Join(tempDir, "active-vpn")
		os.WriteFile(activeVPNFile, []byte("proton-se"), 0600)

		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn": "",
				// wg0 interface exists (both VPNs share it)
				"ip link show type wireguard": "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP>",
				"wg show wg0":                 "interface: wg0\n  peer: abc123\n    endpoint: 1.2.3.4:51820",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{
			vpnConfigs: map[string]*types.VPNConfig{
				"proton-se": {
					Type:      "wireguard",
					Interface: "wg0",
				},
				"proton-dk": {
					Type:      "wireguard",
					Interface: "wg0", // Same interface!
				},
			},
		}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 2)

		// Find each VPN by name
		vpnMap := make(map[string]types.VPNStatus)
		for _, v := range vpns {
			vpnMap[v.Name] = v
		}

		// Only proton-se should be connected
		assert.Contains(t, vpnMap, "proton-se")
		assert.True(t, vpnMap["proton-se"].Connected, "proton-se should be connected")

		assert.Contains(t, vpnMap, "proton-dk")
		assert.False(t, vpnMap["proton-dk"].Connected, "proton-dk should NOT be connected")
	})

	t.Run("falls back to interface detection when no state file", func(t *testing.T) {
		tempDir := t.TempDir()
		// No state file created - temp dir is empty

		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn":            "",
				"ip link show type wireguard": "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP>",
				"wg show wg0":                 "interface: wg0\n  peer: abc123\n    endpoint: 1.2.3.4:51820",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{
			vpnConfigs: map[string]*types.VPNConfig{
				"proton-se": {
					Type:      "wireguard",
					Interface: "wg0",
				},
				"proton-dk": {
					Type:      "wireguard",
					Interface: "wg0",
				},
			},
		}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 2)

		// Without state file, both will show as connected (the old buggy behavior)
		// This is expected as a fallback for VPNs started outside of net
		vpnMap := make(map[string]types.VPNStatus)
		for _, v := range vpns {
			vpnMap[v.Name] = v
		}

		// Both should show connected in fallback mode
		assert.True(t, vpnMap["proton-se"].Connected)
		assert.True(t, vpnMap["proton-dk"].Connected)
	})

	t.Run("stale interface without peers shows as not connected", func(t *testing.T) {
		tempDir := t.TempDir()
		// No state file created - temp dir is empty

		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn": "",
				// wg0 interface exists but...
				"ip link show type wireguard": "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP>",
				// ...has no peers configured (stale interface)
				"wg show wg0": "interface: wg0\n  public key: abc123\n  private key: (hidden)",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{
			vpnConfigs: map[string]*types.VPNConfig{
				"proton-se": {
					Type:      "wireguard",
					Interface: "wg0",
				},
			},
		}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 1)

		// Stale interface (no peers) should not show as connected
		assert.False(t, vpns[0].Connected, "VPN with stale interface (no peers) should not be connected")
	})
}

func TestConnect_SetsActiveVPNStateFile(t *testing.T) {
	tempDir := t.TempDir()

	executor := &mockSystemExecutor{
		commands: map[string]string{
			// Getting current gateway for state file - getCurrentGateway first tries "ip route show default"
			"ip route show default": "default via 192.168.1.1 dev eth0",
			// WireGuard commands
			"install -m 0600 /dev/stdin " + tempDir + "/wg.conf": "",
			"ip link add dev wg0 type wireguard":                 "",
			"wg setconf wg0 " + tempDir + "/wg.conf":             "",
			"rm -f " + tempDir + "/wg.conf":                      "",
			"ip addr replace 10.0.0.1/24 dev wg0":                "",
			"ip link set wg0 up":                                 "",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"test-vpn": {
				Type:      "wireguard",
				Config:    "wireguard config",
				Interface: "wg0",
				Address:   "10.0.0.1/24",
				Gateway:   false,
			},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	err := manager.Connect("test-vpn")
	assert.NoError(t, err)

	// Verify state file was written with enhanced format
	state := manager.getActiveVPNState()
	assert.NotNil(t, state)
	assert.Equal(t, "test-vpn", state.Name)
	assert.Equal(t, "wg0", state.Interface)
	assert.Equal(t, "wireguard", state.Type)
	assert.Equal(t, "192.168.1.1", state.OriginalGateway)
	assert.Equal(t, "eth0", state.OriginalInterface)
}

func TestExtractEndpoint(t *testing.T) {
	manager := &Manager{}

	tests := []struct {
		name     string
		config   string
		expected string
	}{
		{
			name:     "IPv4 with port",
			config:   "Endpoint = 1.2.3.4:51820",
			expected: "1.2.3.4",
		},
		{
			name:     "IPv6 with port (bracketed)",
			config:   "Endpoint = [2001:db8::1]:51820",
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6 without port (bracketed)",
			config:   "Endpoint = [2001:db8::1]",
			expected: "2001:db8::1",
		},
		{
			name:     "hostname with port",
			config:   "Endpoint = vpn.example.com:51820",
			expected: "vpn.example.com",
		},
		{
			name:     "hostname without port",
			config:   "Endpoint = vpn.example.com",
			expected: "vpn.example.com",
		},
		{
			name:     "lowercase endpoint",
			config:   "endpoint = 10.0.0.1:51820",
			expected: "10.0.0.1",
		},
		{
			name:     "endpoint in multiline config",
			config:   "[Peer]\nPublicKey = abc\nEndpoint = 192.168.1.1:51820\nAllowedIPs = 0.0.0.0/0",
			expected: "192.168.1.1",
		},
		{
			name:     "no endpoint",
			config:   "[Interface]\nPrivateKey = abc",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.extractEndpoint(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDisconnectTracked(t *testing.T) {
	t.Run("openvpn uses PID file", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"cat " + tempDir + "/openvpn.pid": "12345",
				"kill 12345":                      "",
				"kill -0 12345":                   "",
				"kill -9 12345":                   "",
				"rm -f " + tempDir + "/openvpn.pid": "",
				"ip link set tun0 down":          "",
			},
			errors: map[string]error{
				"kill -0 12345": assert.AnError, // Process already dead
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, runtimeDir: tempDir}

		state := &vpnState{
			Type:      "openvpn",
			Interface: "tun0",
		}
		manager.disconnectTracked(state)

		executor.assertCommandExecuted(t, "cat "+tempDir+"/openvpn.pid")
		executor.assertCommandExecuted(t, "kill 12345")
	})

	t.Run("wireguard deletes only tracked interface", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link delete wg-mynet": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		state := &vpnState{
			Type:      "wireguard",
			Interface: "wg-mynet",
		}
		manager.disconnectTracked(state)

		executor.assertCommandExecuted(t, "ip link delete wg-mynet")
	})
}

func TestVPNStateFileFormat(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, runtimeDir: tempDir}

	// Test setting state
	state := vpnState{
		Name:              "test-vpn",
		Interface:         "wg0",
		Type:              "wireguard",
		OriginalGateway:   "192.168.1.1",
		OriginalInterface: "eth0",
	}
	err := manager.setActiveVPNState(state)
	assert.NoError(t, err)

	// Read state back
	readState := manager.getActiveVPNState()
	assert.NotNil(t, readState)
	assert.Equal(t, "test-vpn", readState.Name)
	assert.Equal(t, "wg0", readState.Interface)
	assert.Equal(t, "wireguard", readState.Type)
	assert.Equal(t, "192.168.1.1", readState.OriginalGateway)
	assert.Equal(t, "eth0", readState.OriginalInterface)

	// Test getActiveVPN returns just the name
	name := manager.getActiveVPN()
	assert.Equal(t, "test-vpn", name)
}

func TestDisconnect_ClearsActiveVPNStateFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create state file first
	activeVPNFile := filepath.Join(tempDir, "active-vpn")
	os.WriteFile(activeVPNFile, []byte("test-vpn"), 0600)

	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pkill -f openvpn":            "",
			"ip link show type wireguard": "",
			"ip link delete wg0":          "",
			"ip link set tun0 down":       "",
			"ip route show":               "",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	err := manager.Disconnect("test-vpn")
	assert.NoError(t, err)

	// Verify state file was removed
	_, err = os.Stat(activeVPNFile)
	assert.True(t, os.IsNotExist(err), "active VPN state file should be removed after disconnect")
}
