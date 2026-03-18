package vpn

import (
	"fmt"
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestTailscaleConfigFields(t *testing.T) {
	config := types.VPNConfig{
		Type:         "tailscale",
		AuthKey:      "tskey-auth-xxxxx",
		ExitNode:     "us-east-1",
		AcceptRoutes: true,
	}
	assert.Equal(t, "tailscale", config.Type)
	assert.Equal(t, "tskey-auth-xxxxx", config.AuthKey)
	assert.Equal(t, "us-east-1", config.ExitNode)
	assert.True(t, config.AcceptRoutes)
}

func TestConnectTailscale_MissingBinary(t *testing.T) {
	executor := &mockSystemExecutor{}
	// Override HasCommand to return false for tailscale
	executor.hasCommandOverride = map[string]bool{"tailscale": false}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"ts": {Type: "tailscale"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("ts")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tailscale")
	assert.Contains(t, err.Error(), "Install")
}

func TestConnectTailscale_Success(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":                                                       "default via 192.168.1.1 dev eth0",
			"tailscale up --accept-dns=false --authkey=tskey-auth-xxxxx --exit-node=us-1": "",
			"tailscale status --json": `{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.1"]}}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"ts": {
				Type:     "tailscale",
				AuthKey:  "tskey-auth-xxxxx",
				ExitNode: "us-1",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("ts")
	assert.NoError(t, err)

	// Verify tailscale up was called with correct args
	executor.assertCommandExecuted(t, "tailscale up --accept-dns=false --authkey=tskey-auth-xxxxx --exit-node=us-1")
}

func TestConnectTailscale_NoAuthKey(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":              "default via 192.168.1.1 dev eth0",
			"tailscale up --accept-dns=false":    "",
			"tailscale status --json":            `{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.1"]}}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"ts": {Type: "tailscale"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("ts")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "tailscale up --accept-dns=false")
}

func TestConnectTailscale_WithAcceptRoutes(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":                           "default via 192.168.1.1 dev eth0",
			"tailscale up --accept-dns=false --accept-routes": "",
			"tailscale status --json":                         `{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.1"]}}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"ts": {Type: "tailscale", AcceptRoutes: true},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("ts")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "tailscale up --accept-dns=false --accept-routes")
}

func TestListVPNs_TailscaleRunning(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":            "",
			"ip link show type wireguard": "",
			"tailscale status --json":     `{"BackendState":"Running"}`,
			"netbird status --json":       "",
		},
		errors: map[string]error{
			"pgrep -f openvpn":      fmt.Errorf("no match"),
			"netbird status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"my-ts": {Type: "tailscale"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.Equal(t, "my-ts", vpns[0].Name)
	assert.True(t, vpns[0].Connected)
	assert.Equal(t, "tailscale0", vpns[0].Interface)
}

func TestListVPNs_TailscaleNotRunning(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":            "",
			"ip link show type wireguard": "",
			"tailscale status --json":     `{"BackendState":"Stopped"}`,
			"netbird status --json":       "",
		},
		errors: map[string]error{
			"pgrep -f openvpn":      fmt.Errorf("no match"),
			"netbird status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"my-ts": {Type: "tailscale"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.False(t, vpns[0].Connected)
}

func TestDisconnectTailscale_Tracked(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"tailscale down": "",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger}

	state := &vpnState{Type: "tailscale", Interface: "tailscale0"}
	manager.disconnectTracked(state)

	executor.assertCommandExecuted(t, "tailscale down")
}
