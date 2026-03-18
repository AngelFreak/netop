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
			"ip route show default":                                                                               "default via 192.168.1.1 dev eth0",
			"netbird up --setup-key XXXXXXXX --management-url https://api.netbird.io --disable-dns": "",
			"netbird status": "Connected",
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
	executor.assertCommandExecuted(t, "netbird up --setup-key XXXXXXXX --management-url https://api.netbird.io --disable-dns")
}

func TestConnectNetBird_NoSetupKey(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":         "default via 192.168.1.1 dev eth0",
			"netbird up --disable-dns": "",
			"netbird status": "Connected",
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

func TestListVPNs_NetBirdRunning(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":            "",
			"ip link show type wireguard": "",
			"tailscale status --json":     "",
			"netbird status --json":       `{"status":"Connected"}`,
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
			"netbird status":           "Connected",
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
