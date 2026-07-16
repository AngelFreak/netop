package vpn

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// newFakeRoutes returns a fake RouteManager preloaded with a typical physical
// default route (192.168.1.1 via eth0). Gateway detection and route restore go
// through the RouteManager (netlink) rather than the executor, so tests inject
// this to keep those paths deterministic and off the real kernel. Tests that
// assert on specific gateway/route behavior override manager.routeMgr with their
// own fake.
func newFakeRoutes() *fake.RouteManager {
	return &fake.RouteManager{
		Routes: []types.Route{{Gw: "192.168.1.1", Iface: "eth0"}},
	}
}

// newFakeAddrs returns a fake AddrManager. The WireGuard interface IP is set
// via the AddrManager (netlink) rather than the executor, so tests inject this
// to keep that path deterministic and off the real kernel.
func newFakeAddrs() *fake.AddrManager {
	return &fake.AddrManager{}
}

// newFakeLinks returns a fake LinkManager. WireGuard interface create/delete/
// enumerate and link up/down go through the LinkManager (netlink) rather than
// the executor, so tests inject this to keep those paths deterministic.
func newFakeLinks() *fake.LinkManager {
	return &fake.LinkManager{}
}

// Mock implementations
type mockSystemExecutor struct {
	mu                 sync.Mutex
	commands           map[string]string
	errors             map[string]error
	executedCommands   []string        // Track executed commands for verification
	hasCommandOverride map[string]bool // Override HasCommand results per command
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
	if m.hasCommandOverride != nil {
		if val, ok := m.hasCommandOverride[cmd]; ok {
			return val
		}
	}
	return true
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

// assertCommandNotExecuted verifies a command was NOT executed
func (m *mockSystemExecutor) assertCommandNotExecuted(t *testing.T, cmd string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, executed := range m.executedCommands {
		if executed == cmd {
			t.Errorf("expected command %q to NOT be executed, but it was", cmd)
			return
		}
	}
}

// sequencingExecutor returns different results for successive calls to the same command
type sequencingExecutor struct {
	mockSystemExecutor
	callSequence map[string][]struct {
		output string
		err    error
	}
	callIndex map[string]int
}

func (s *sequencingExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}

	s.mu.Lock()
	s.executedCommands = append(s.executedCommands, fullCmd)

	if seq, ok := s.callSequence[fullCmd]; ok {
		if s.callIndex == nil {
			s.callIndex = make(map[string]int)
		}
		idx := s.callIndex[fullCmd]
		if idx < len(seq) {
			s.callIndex[fullCmd] = idx + 1
			s.mu.Unlock()
			return seq[idx].output, seq[idx].err
		}
	}

	// Fall through to base mock for non-sequenced commands
	// Check for errors first
	if err, hasErr := s.errors[fullCmd]; hasErr {
		output := ""
		if val, ok := s.commands[fullCmd]; ok {
			output = val
		}
		s.mu.Unlock()
		return output, err
	}

	if output, ok := s.commands[fullCmd]; ok {
		s.mu.Unlock()
		return output, nil
	}
	s.mu.Unlock()
	return "mock output", nil
}

func (s *sequencingExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return s.Execute(cmd, args...)
}

func (s *sequencingExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return s.Execute(cmd, args...)
}

func (s *sequencingExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	return s.mockSystemExecutor.ExecuteWithInput(cmd, input, args...)
}

func (s *sequencingExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return s.mockSystemExecutor.ExecuteWithInputContext(ctx, cmd, input, args...)
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
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()
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
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()
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
					// OpenVPN commands
					"install -m 0600 /dev/stdin /run/net/openvpn.conf":                                "",
					"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
					// WireGuard commands
					"install -m 0600 /dev/stdin /run/net/wg.conf": "",
					"rm -f /run/net/wg.conf":                      "",
					"wg setconf wg0 /run/net/wg.conf":             "",
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
			manager.routeMgr = newFakeRoutes()
			manager.addrMgr = newFakeAddrs()
			// OpenVPN verifies the tunnel by probing for its device; report tun0
			// as existing so the connect completes.
			manager.linkMgr = &fake.LinkManager{Existing: map[string]bool{"tun0": true}}

			err := manager.Connect("test")
			assert.NoError(t, err)
		})
	}
}

func TestDisconnect(t *testing.T) {
	t.Run("with tracked state", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{
			commands: map[string]string{},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		// Create a state file so Disconnect has something to act on
		os.WriteFile(filepath.Join(tempDir, "active-vpn"), []byte("test|wg0|wireguard|192.168.1.1|eth0"), 0600)

		err := manager.Disconnect("test")
		assert.NoError(t, err)
	})

	t.Run("no active VPN returns error", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{
			commands: map[string]string{},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		err := manager.Disconnect("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active VPN")
	})
}

func TestListVPNs(t *testing.T) {
	t.Run("openvpn running (no config)", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn": "1234",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{} // No config
		manager := NewManagerWithDir(executor, logger, configMgr, t.TempDir())
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

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
				"pgrep -f openvpn": "",
				"wg show wg0":      "interface: wg0\n  public key: abc123\n  peer: xyz789\n    endpoint: 1.2.3.4:51820",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{} // No config
		manager := NewManagerWithDir(executor, logger, configMgr, t.TempDir())
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		// wg0 exists as a WireGuard interface (netlink enumeration by type).
		manager.linkMgr = &fake.LinkManager{ByType: map[string][]string{"wireguard": {"wg0"}}}

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
				"pgrep -f openvpn": "",
			},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, t.TempDir())
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		vpns, err := manager.ListVPNs()
		assert.NoError(t, err)
		assert.Len(t, vpns, 0)
	})

	t.Run("configured vpn not running", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pgrep -f openvpn": "",
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
		manager := NewManagerWithDir(executor, logger, configMgr, t.TempDir())
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

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
				"pgrep -f openvpn": "1234",
				"wg show wg0":      "interface: wg0\n  peer: abc123\n    endpoint: 1.2.3.4:51820",
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
		manager := NewManagerWithDir(executor, logger, configMgr, t.TempDir())
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		// wg0 is enumerated as a WireGuard interface (netlink by type).
		manager.linkMgr = &fake.LinkManager{ByType: map[string][]string{"wireguard": {"wg0"}}}

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
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

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
			"install -m 0600 /dev/stdin /run/net/openvpn.conf":                                "",
			"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
		},
	}
	logger := &mockLogger{}
	// tunnel verification: tun0 exists (netlink probe).
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: &fake.LinkManager{Existing: map[string]bool{"tun0": true}}, executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

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
			"wg setconf wg0 /run/net/wg.conf":             "",
			"rm -f /run/net/wg.conf":                      "",
			"ip route replace default dev wg0":            "",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

	config := &types.VPNConfig{
		Config:    "wireguard config",
		Interface: "wg0",
		Address:   "10.0.0.1/24",
		Gateway:   true,
	}

	err := manager.connectWireGuard(config, "", "")
	assert.NoError(t, err)
}

func TestWriteFile(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

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
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

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
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		err := manager.Connect("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported VPN type")
	})
}

func TestDisconnect_ErrorCases(t *testing.T) {
	t.Run("disconnect with no active VPN returns error", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{
			commands: map[string]string{},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		err := manager.Disconnect("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active VPN")
	})

	t.Run("disconnect with tracked state returns disconnect error", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{
			commands: map[string]string{},
		}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		// Delete fails and the interface still exists, so disconnect must error.
		manager.linkMgr = &fake.LinkManager{DeleteErr: assert.AnError, Existing: map[string]bool{"wg0": true}}

		// Create state file
		os.WriteFile(filepath.Join(tempDir, "active-vpn"), []byte("test|wg0|wireguard||"), 0600)

		err := manager.Disconnect("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete WireGuard")
	})
}

func TestConnectOpenVPN_ErrorCases(t *testing.T) {
	t.Run("write file error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
			},
			errors: map[string]error{},
		}
		logger := &mockLogger{}
		// tun0 exists so the tunnel verification succeeds.
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: &fake.LinkManager{Existing: map[string]bool{"tun0": true}}, executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

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
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

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
				"install -m 0600 /dev/stdin /run/net/openvpn.conf":                                "",
				"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
				"rm -f /run/net/openvpn.conf":                                                     "",      // cleanup should happen
				"cat /run/net/openvpn.pid":                                                        "12345", // PID file exists
				"kill 12345":                                                                      "",      // graceful kill
				"kill -0 12345":                                                                   "",      // check if running
				"kill -9 12345":                                                                   "",      // force kill
				"rm -f /run/net/openvpn.pid":                                                      "",      // PID file cleanup
			},
		}
		logger := &mockLogger{}
		// tun0 never appears (netlink probe reports it absent).
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config: "openvpn config",
		}

		err := manager.connectOpenVPN(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to establish tunnel")
		// Verify cleanup was called
		executor.assertCommandExecuted(t, "rm -f /run/net/openvpn.conf")
	})

	t.Run("stale device with dead daemon fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/openvpn.conf":                                "",
				"openvpn --config /run/net/openvpn.conf --daemon --writepid /run/net/openvpn.pid": "",
				"cat /run/net/openvpn.pid":                                                        "12345", // PID file exists
				"rm -f /run/net/openvpn.conf":                                                     "",
				"rm -f /run/net/openvpn.pid":                                                      "",
			},
			errors: map[string]error{
				"kill -0 12345": assert.AnError, // daemon already dead
			},
		}
		logger := &mockLogger{}
		// Stale interface still exists (netlink probe reports it present), but the
		// daemon we started is already dead.
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: &fake.LinkManager{Existing: map[string]bool{"tun0": true}}, executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config: "openvpn config",
		}

		err := manager.connectOpenVPN(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exited before")
		// Verify cleanup was called
		executor.assertCommandExecuted(t, "rm -f /run/net/openvpn.conf")
	})
}

func TestConnectWireGuard_ErrorCases(t *testing.T) {
	t.Run("write file error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"wg setconf wg0 /run/net/wg.conf": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
			Gateway:   false, // No gateway route
		}

		err := manager.connectWireGuard(config, "", "")
		// Should succeed with mock executor
		assert.NoError(t, err)
	})

	t.Run("interface creation error after cleanup retry", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"rm -f /run/net/wg.conf":                      "",
			},
		}
		logger := &mockLogger{}
		// Both create attempts fail; the stale interface exists so cleanup can
		// delete it between attempts.
		links := &fake.LinkManager{AddWGErr: assert.AnError, Existing: map[string]bool{"wg0": true}}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		// When both create attempts fail, it should return an error
		err := manager.connectWireGuard(config, "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create WireGuard interface")
		// Verify cleanup was attempted
		assert.Contains(t, links.Deleted, "wg0")
	})

	t.Run("setconf error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
			},
			errors: map[string]error{
				"wg setconf wg0 /run/net/wg.conf": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config, "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set WireGuard config")
	})

	t.Run("ip address assignment error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"wg setconf wg0 /run/net/wg.conf":             "",
			},
		}
		logger := &mockLogger{}
		addrs := newFakeAddrs()
		addrs.ReplaceErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: addrs, linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config, "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set WireGuard IP")
	})

	t.Run("interface up error", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"wg setconf wg0 /run/net/wg.conf":             "",
			},
		}
		logger := &mockLogger{}
		// Bringing the interface up fails (netlink SetUp error).
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: &fake.LinkManager{SetUpErr: assert.AnError}, executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config, "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring WireGuard interface up")
	})

	t.Run("gateway route error (warning only)", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"wg setconf wg0 /run/net/wg.conf":             "",
			},
			errors: map[string]error{
				"ip route replace default dev wg0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
			Gateway:   true,
		}

		// Gateway route error is only a warning, not a fatal error
		err := manager.connectWireGuard(config, "", "")
		assert.NoError(t, err)
	})
}

func TestGenerateWireGuardKey_Coverage(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManager(executor, logger, configMgr)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

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
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		result := manager.getActiveVPN()
		assert.Equal(t, "", result)
	})

	t.Run("setActiveVPNState and getActiveVPN roundtrip", func(t *testing.T) {
		tempDir := t.TempDir()
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		configMgr := &mockConfigManager{}
		manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		// Set active VPN
		err := manager.setActiveVPNState(vpnState{Name: "test-vpn"})
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
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

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
				"wg show wg0":      "interface: wg0\n  peer: abc123\n    endpoint: 1.2.3.4:51820",
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
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		// wg0 interface exists (both VPNs share it) — enumerated by type.
		manager.linkMgr = &fake.LinkManager{ByType: map[string][]string{"wireguard": {"wg0"}}}

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
				"pgrep -f openvpn": "",
				"wg show wg0":      "interface: wg0\n  peer: abc123\n    endpoint: 1.2.3.4:51820",
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
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		// wg0 interface exists — enumerated by type.
		manager.linkMgr = &fake.LinkManager{ByType: map[string][]string{"wireguard": {"wg0"}}}

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
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		// wg0 interface exists but has no peers (stale) — enumerated by type.
		manager.linkMgr = &fake.LinkManager{ByType: map[string][]string{"wireguard": {"wg0"}}}

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
			// WireGuard commands
			"install -m 0600 /dev/stdin " + tempDir + "/wg.conf": "",
			"wg setconf wg0 " + tempDir + "/wg.conf":             "",
			"rm -f " + tempDir + "/wg.conf":                      "",
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
	// Gateway detection now goes through the RouteManager (netlink), not the
	// executor. Inject a fake default route: 192.168.1.1 via eth0.
	manager.routeMgr = &fake.RouteManager{
		Routes: []types.Route{{Gw: "192.168.1.1", Iface: "eth0"}},
	}
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

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
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks()}

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
				"cat " + tempDir + "/openvpn.pid":   "12345",
				"kill 12345":                        "",
				"kill -0 12345":                     "",
				"kill -9 12345":                     "",
				"rm -f " + tempDir + "/openvpn.pid": "",
			},
			errors: map[string]error{
				"kill -0 12345": assert.AnError, // Process already dead
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: tempDir}

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
			commands: map[string]string{},
		}
		logger := &mockLogger{}
		links := &fake.LinkManager{Existing: map[string]bool{"wg-mynet": true}}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		state := &vpnState{
			Type:      "wireguard",
			Interface: "wg-mynet",
		}
		manager.disconnectTracked(state)

		assert.Contains(t, links.Deleted, "wg-mynet")
	})
}

func TestVPNStateFileFormat(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: tempDir}

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
			"pkill -f openvpn": "",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	err := manager.Disconnect("test-vpn")
	assert.NoError(t, err)

	// Verify state file was removed
	_, err = os.Stat(activeVPNFile)
	assert.True(t, os.IsNotExist(err), "active VPN state file should be removed after disconnect")
}

func TestDisconnect_WireGuardAlreadyGone(t *testing.T) {
	tempDir := t.TempDir()

	activeVPNFile := filepath.Join(tempDir, "active-vpn")
	os.WriteFile(activeVPNFile, []byte("test|wg0|wireguard||"), 0600)

	executor := &mockSystemExecutor{
		commands: map[string]string{},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	// Delete fails and the probe confirms the interface is gone (not in
	// Existing), so the disconnect should still succeed and clear state.
	manager.linkMgr = &fake.LinkManager{DeleteErr: assert.AnError}

	err := manager.Disconnect("test")
	assert.NoError(t, err)

	_, err = os.Stat(activeVPNFile)
	assert.True(t, os.IsNotExist(err), "active VPN state file should be removed when the interface is already gone")
}

// sequencingLinks is a LinkManager fake whose AddWireGuard returns successive
// errors from addWGSeq on each call, so tests can exercise the create → delete →
// recreate cleanup path (first attempt fails because the stale interface exists,
// second attempt reflects the retry outcome). All other behavior is inherited
// from fake.LinkManager, including recording deletes in Deleted.
type sequencingLinks struct {
	fake.LinkManager
	addWGSeq []error
	addWGIdx int
}

func (s *sequencingLinks) AddWireGuard(iface string) error {
	if s.addWGIdx < len(s.addWGSeq) {
		err := s.addWGSeq[s.addWGIdx]
		s.addWGIdx++
		if err != nil {
			return err
		}
	}
	return s.LinkManager.AddWireGuard(iface)
}

func TestConnectWireGuard_CleansUpStaleInterface(t *testing.T) {
	t.Run("deletes and recreates interface when it already exists", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"wg setconf wg0 /run/net/wg.conf":             "",
				"rm -f /run/net/wg.conf":                      "",
			},
		}
		logger := &mockLogger{}
		// First create attempt fails (stale interface exists), second succeeds
		// after cleanup. The stale interface exists so cleanup can delete it.
		links := &sequencingLinks{
			LinkManager: fake.LinkManager{Existing: map[string]bool{"wg0": true}},
			addWGSeq: []error{
				fmt.Errorf("RTNETLINK answers: File exists"), // first call fails
				nil, // second call succeeds after cleanup
			},
		}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config, "", "")
		assert.NoError(t, err)

		// Verify cleanup was called between the two AddWireGuard attempts
		assert.Contains(t, links.Deleted, "wg0")
	})

	t.Run("returns error when recreate also fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"install -m 0600 /dev/stdin /run/net/wg.conf": "",
				"rm -f /run/net/wg.conf":                      "",
			},
		}
		logger := &mockLogger{}
		// Both create attempts fail; the stale interface exists so cleanup can
		// delete it between attempts.
		links := &sequencingLinks{
			LinkManager: fake.LinkManager{Existing: map[string]bool{"wg0": true}},
			addWGSeq: []error{
				fmt.Errorf("RTNETLINK answers: File exists"), // first call fails
				fmt.Errorf("some other error"),               // second call also fails
			},
		}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

		config := &types.VPNConfig{
			Config:    "wireguard config",
			Interface: "wg0",
			Address:   "10.0.0.1/24",
		}

		err := manager.connectWireGuard(config, "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create WireGuard interface")
		// Verify cleanup was attempted between the two AddWireGuard attempts
		assert.Contains(t, links.Deleted, "wg0")
	})
}

func TestOpenVPNDevice(t *testing.T) {
	assert.Equal(t, "tun0", openVPNDevice(""))
	assert.Equal(t, "tun0", openVPNDevice("remote vpn.example.com 1194\ndev tun\n"))
	assert.Equal(t, "tap0", openVPNDevice("dev tap\n"))
	assert.Equal(t, "mytun", openVPNDevice("remote x 1194\ndev mytun\nproto udp\n"))
	assert.Equal(t, "tun3", openVPNDevice("  dev tun3\n"))
}

func TestVPNStatusPredicates(t *testing.T) {
	// Tailscale: only BackendState Running counts
	assert.True(t, tailscaleStatusRunning(`{"BackendState":"Running"}`))
	assert.False(t, tailscaleStatusRunning(`{"BackendState":"NeedsLogin"}`))
	assert.False(t, tailscaleStatusRunning(""))

	// NetBird: daemonStatus is the client-level signal; peer status strings
	// must not be mistaken for it
	assert.True(t, netBirdStatusConnected(`{"daemonStatus":"Connected"}`))
	assert.False(t, netBirdStatusConnected(`{"daemonStatus":"NeedsLogin"}`))
	assert.False(t, netBirdStatusConnected(
		`{"peers":{"total":1,"connected":0,"details":[{"status":"Connected"}]},"daemonStatus":"Disconnected"}`))
	assert.False(t, netBirdStatusConnected(""))
}

func TestDisconnect_NameMismatchIsError(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := NewManagerWithDir(executor, logger, &mockConfigManager{}, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	err := manager.setActiveVPNState(vpnState{Name: "work", Type: "netbird", Interface: "wt0"})
	assert.NoError(t, err)

	err = manager.Disconnect("other")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not the active VPN")
	// State must be untouched — nothing was disconnected
	assert.Equal(t, "work", manager.getActiveVPN())
}

func TestDisconnect_RemovesPersistedEndpointRoute(t *testing.T) {
	// The connecting process is not the disconnecting one: the endpoint route
	// must survive via the state file, not just the in-memory field.
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{},
	}
	logger := &mockLogger{}
	manager := NewManagerWithDir(executor, logger, &mockConfigManager{}, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	// Simulate the state written by a previous process's Connect
	err := manager.setActiveVPNState(vpnState{
		Name:              "wg-vpn",
		Interface:         "wg0",
		Type:              "wireguard",
		OriginalGateway:   "192.168.1.1",
		OriginalInterface: "eth0",
		EndpointRoute:     "203.0.113.5",
	})
	assert.NoError(t, err)

	err = manager.Disconnect("")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "ip route del 203.0.113.5")
}

func TestConnectWireGuard_ResolvesHostnameEndpoint(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"install -m 0600 /dev/stdin /run/net/wg.conf": "",
			"wg setconf wg0 /run/net/wg.conf":             "",
			"rm -f /run/net/wg.conf":                      "",
			"ip route replace default dev wg0":            "",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, runtimeDir: types.RuntimeDir}

	config := &types.VPNConfig{
		Config:    "[Peer]\nEndpoint = localhost:51820\n",
		Interface: "wg0",
		Gateway:   true,
	}

	err := manager.connectWireGuard(config, "192.168.1.1", "eth0")
	assert.NoError(t, err)
	// localhost resolves to a loopback address; the protective endpoint route
	// must use the resolved IP, not the hostname
	assert.NotEmpty(t, manager.endpointRoute)
	assert.NotNil(t, net.ParseIP(manager.endpointRoute))
	assert.True(t, net.ParseIP(manager.endpointRoute).IsLoopback())
}

func TestListVPNs_StateFileVerifiedAgainstLiveStatus(t *testing.T) {
	// State file says netbird is the active VPN, but the daemon reports
	// disconnected — status must not lie.
	tempDir := t.TempDir()
	activeVPNFile := filepath.Join(tempDir, "active-vpn")
	os.WriteFile(activeVPNFile, []byte("work-nb|wt0|netbird|192.168.1.1|eth0|"), 0600)

	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Disconnected"}`,
		},
		errors: map[string]error{
			"pgrep -f openvpn": fmt.Errorf("no match"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-nb": {Type: "netbird"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.False(t, vpns[0].Connected, "state file says active but daemon is down — must report disconnected")
}

// Switching directly from one VPN to another (via Connect, not Disconnect)
// must remove the old VPN's persisted endpoint route, not leak it.
func TestConnect_RemovesOldEndpointRouteOnSwitch(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connected"}`,
			"netbird down":             "",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"new-nb": {Type: "netbird"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	// Existing WireGuard VPN with a protective endpoint route recorded.
	err := manager.setActiveVPNState(vpnState{
		Name: "old-wg", Type: "wireguard", Interface: "wg0",
		OriginalGateway: "192.168.1.1", OriginalInterface: "eth0",
		EndpointRoute: "203.0.113.9",
	})
	assert.NoError(t, err)

	err = manager.Connect("new-nb")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "ip route del 203.0.113.9")
}

// When two same-type daemon VPNs are configured and none is net-tracked, live
// detection can't tell which is up, so ListVPNs must not flag both connected.
func TestListVPNs_AmbiguousSameTypeNotBothConnected(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Connected"}`,
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-nb": {Type: "netbird"},
			"home-nb": {Type: "netbird"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 2)
	for _, v := range vpns {
		assert.False(t, v.Connected, "ambiguous same-type VPN %q must not be flagged connected", v.Name)
	}
}
