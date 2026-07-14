package vpn

import (
	"fmt"
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestConnectNetBird_MissingBinary(t *testing.T) {
	executor := &mockSystemExecutor{
		hasCommandOverride: map[string]bool{"netbird": false},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "netbird")
	assert.Contains(t, err.Error(), "install")
}

func TestConnectNetBird_Success(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"netbird up --setup-key-file /run/net/netbird-setupkey --management-url https://api.netbird.io --disable-dns": "",
			"netbird status --json": `{"daemonStatus":"Connected"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {
				Type:          "netbird",
				SetupKey:      "XXXXXXXX",
				ManagementURL: "https://api.netbird.io",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("nb")
	assert.NoError(t, err)
	// The setup key must be passed via --setup-key-file, never as an argv token.
	executor.assertCommandExecuted(t, "netbird up --setup-key-file /run/net/netbird-setupkey --management-url https://api.netbird.io --disable-dns")
	for _, cmd := range executor.executedCommands {
		assert.NotContains(t, cmd, "--setup-key XXXXXXXX", "setup key must never appear in a command argument")
	}
}

func TestConnectNetBird_NoSetupKey(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connected"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("nb")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "netbird up --disable-dns")
}

func TestConnectNetBird_WithProfile(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":       "default via 192.168.1.1 dev eth0",
			"netbird profile select work": "Profile switched successfully to: work",
			"netbird up --disable-dns":    "",
			"netbird status --json":       `{"daemonStatus":"Connected"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-nb": {
				Type:    "netbird",
				Profile: "work",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("work-nb")
	assert.NoError(t, err)

	executor.assertCommandExecuted(t, "netbird profile select work")
	executor.assertCommandExecuted(t, "netbird up --disable-dns")
}

func TestConnectNetBird_ProfileSelectFailureIsFatal(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connected"}`,
		},
		errors: map[string]error{
			"netbird profile select missing": fmt.Errorf("command failed: exit status 1 (stderr: profile not found)"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-nb": {
				Type:    "netbird",
				Profile: "missing",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("work-nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "profile")

	executor.assertCommandExecuted(t, "netbird profile select missing")
	// Connecting without the requested profile would silently use the wrong
	// account, so "up" must not run after a failed profile select.
	executor.assertCommandNotExecuted(t, "netbird up --disable-dns")
}

func TestConnectNetBird_FailsWhenTunnelNeverConnects(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connecting"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManager(executor, logger, configMgr)
	manager.verifyAttempts = 2
	manager.verifyDelay = 0

	err := manager.Connect("nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "did not come up")
}

func TestListVPNs_NetBirdRunning(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":            "",
			"ip link show type wireguard": "",
			"tailscale status --json":     "",
			"netbird status --json":       `{"daemonStatus":"Connected"}`,
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"my-nb": {Type: "netbird"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.Equal(t, "my-nb", vpns[0].Name)
	assert.True(t, vpns[0].Connected)
	assert.Equal(t, "wt0", vpns[0].Interface)
}

func TestNetBird_ConnectDisconnectCycle(t *testing.T) {
	tempDir := t.TempDir()

	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":    "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status --json":    `{"daemonStatus":"Connected"}`,
			"netbird down":             "",
			"ip route show":            "default via 192.168.1.1 dev eth0",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"nb": {Type: "netbird"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	// Connect
	err := manager.Connect("nb")
	assert.NoError(t, err)

	// Verify state file
	state := manager.getActiveVPNState()
	assert.NotNil(t, state)
	assert.Equal(t, "nb", state.Name)
	assert.Equal(t, "netbird", state.Type)
	assert.Equal(t, "wt0", state.Interface)

	// Disconnect
	err = manager.Disconnect("nb")
	assert.NoError(t, err)

	// Verify state file cleared
	state = manager.getActiveVPNState()
	assert.Nil(t, state)

	// Verify netbird down was called
	executor.assertCommandExecuted(t, "netbird down")
}

func TestDisconnectNetBird_Tracked(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"netbird down": "",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger}

	state := &vpnState{Type: "netbird", Interface: "wt0"}
	manager.disconnectTracked(state)

	executor.assertCommandExecuted(t, "netbird down")
}

func TestDisconnectNetBird_FailureKeepsState(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		errors: map[string]error{
			"netbird down": fmt.Errorf("daemon wedged"),
		},
	}
	logger := &mockLogger{}
	manager := NewManagerWithDir(executor, logger, &mockConfigManager{}, tempDir)

	err := manager.setActiveVPNState(vpnState{
		Name:              "nb",
		Interface:         "wt0",
		Type:              "netbird",
		OriginalGateway:   "192.168.1.1",
		OriginalInterface: "eth0",
	})
	assert.NoError(t, err)

	err = manager.Disconnect("nb")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to disconnect NetBird")

	// State must be retained so the user can retry the stop.
	assert.Equal(t, "nb", manager.getActiveVPN())
	// Routes must be left untouched while the tunnel is still up.
	executor.assertCommandNotExecuted(t, "ip route replace default via 192.168.1.1 dev eth0")
}

func TestNetBirdConfigFields(t *testing.T) {
	config := types.VPNConfig{
		Type:          "netbird",
		SetupKey:      "XXXXXXXX",
		ManagementURL: "https://api.netbird.io",
	}
	assert.Equal(t, "netbird", config.Type)
	assert.Equal(t, "XXXXXXXX", config.SetupKey)
	assert.Equal(t, "https://api.netbird.io", config.ManagementURL)
}

func TestConnect_KeepsStateWhenExistingVPNTeardownFails(t *testing.T) {
	// A wedged daemon must not let a new Connect wipe the old VPN's state:
	// the tunnel may still be up and would become untracked.
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
		},
		errors: map[string]error{
			"netbird down": fmt.Errorf("daemon not responding"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"other": {Type: "wireguard", Config: "wireguard config"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	err := manager.setActiveVPNState(vpnState{Name: "old-nb", Type: "netbird", Interface: "wt0"})
	assert.NoError(t, err)

	err = manager.Connect("other")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot disconnect active VPN")
	assert.Equal(t, "old-nb", manager.getActiveVPN(), "old VPN state must be retained")
}
