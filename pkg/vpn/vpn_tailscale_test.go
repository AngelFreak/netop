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
	tmpDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"tailscale up --auth-key=file:" + tmpDir + "/tailscale-authkey":           "",
			"tailscale set --accept-dns=false --exit-node=us-1 --accept-routes=false": "",
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
	manager := NewManagerWithDir(executor, logger, configMgr, tmpDir)

	err := manager.Connect("ts")
	assert.NoError(t, err)

	// The auth key must be passed via file:, never as an argv token, so it
	// isn't visible in `ps`. The key value must not appear in any command.
	executor.assertCommandExecuted(t, "tailscale up --auth-key=file:"+tmpDir+"/tailscale-authkey")
	executor.assertCommandExecuted(t, "tailscale set --accept-dns=false --exit-node=us-1 --accept-routes=false")
	for _, cmd := range executor.executedCommands {
		assert.NotContains(t, cmd, "tskey-auth-xxxxx", "auth key must never appear in a command argument")
	}
}

func TestConnectTailscale_NoAuthKey(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"tailscale up":          "",
			"tailscale set --accept-dns=false --exit-node= --accept-routes=false": "",
			"tailscale status --json": `{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.1"]}}`,
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
	executor.assertCommandExecuted(t, "tailscale up")
	executor.assertCommandExecuted(t, "tailscale set --accept-dns=false --exit-node= --accept-routes=false")
}

func TestConnectTailscale_WithAcceptRoutes(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"tailscale up":          "",
			"tailscale set --accept-dns=false --exit-node= --accept-routes=true": "",
			"tailscale status --json": `{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.1"]}}`,
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
	executor.assertCommandExecuted(t, "tailscale up")
	executor.assertCommandExecuted(t, "tailscale set --accept-dns=false --exit-node= --accept-routes=true")
}

func TestConnectTailscale_WithProfile(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":             "default via 192.168.1.1 dev eth0",
			"tailscale switch work@company.com": "",
			"tailscale up":                      "",
			"tailscale set --accept-dns=false --exit-node=us-east-1 --accept-routes=false": "",
			"tailscale status --json": `{"BackendState":"Running"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-ts": {
				Type:     "tailscale",
				Profile:  "work@company.com",
				ExitNode: "us-east-1",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("work-ts")
	assert.NoError(t, err)

	// Verify profile switch happened, then up, then set
	executor.assertCommandExecuted(t, "tailscale switch work@company.com")
	executor.assertCommandExecuted(t, "tailscale up")
	executor.assertCommandExecuted(t, "tailscale set --accept-dns=false --exit-node=us-east-1 --accept-routes=false")
}

func TestConnectTailscale_ProfileSwitchEmptyStderr(t *testing.T) {
	// tailscale switch exits non-zero with empty stderr on success;
	// the connect should still succeed without warnings blocking it.
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"tailscale up":          "",
			"tailscale set --accept-dns=false --exit-node= --accept-routes=false": "",
			"tailscale status --json": `{"BackendState":"Running"}`,
		},
		errors: map[string]error{
			"tailscale switch work@company.com": fmt.Errorf("command failed: exit status 1 (stderr: )"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-ts": {
				Type:    "tailscale",
				Profile: "work@company.com",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("work-ts")
	assert.NoError(t, err)

	executor.assertCommandExecuted(t, "tailscale switch work@company.com")
	executor.assertCommandExecuted(t, "tailscale up")
}

func TestIsEmptyStderrError(t *testing.T) {
	assert.True(t, isEmptyStderrError(fmt.Errorf("command failed: exit status 1 (stderr: )")))
	assert.False(t, isEmptyStderrError(fmt.Errorf("command failed: exit status 1 (stderr: profile not found)")))
	assert.False(t, isEmptyStderrError(nil))
}

func TestConnectTailscale_ProfileSwitchFailureIsFatal(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"tailscale up":          "",
			"tailscale set --accept-dns=false --exit-node= --accept-routes=false": "",
			"tailscale status --json": `{"BackendState":"Running"}`,
		},
		errors: map[string]error{
			"tailscale switch missing@example.com": fmt.Errorf("command failed: exit status 1 (stderr: unknown profile)"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"work-ts": {
				Type:    "tailscale",
				Profile: "missing@example.com",
			},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("work-ts")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "profile")

	// Connecting without the requested profile would silently use the wrong
	// account, so "up" must not run after a failed switch.
	executor.assertCommandNotExecuted(t, "tailscale up")
}

func TestConnectTailscale_FailsWhenBackendNeverRuns(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"tailscale up":          "",
			"tailscale set --accept-dns=false --exit-node= --accept-routes=false": "",
			"tailscale status --json": `{"BackendState":"NeedsLogin"}`,
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"ts": {Type: "tailscale"},
		},
	}
	manager := NewManager(executor, logger, configMgr)
	manager.verifyAttempts = 2
	manager.verifyDelay = 0

	err := manager.Connect("ts")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "did not come up")
}

func TestListVPNs_TailscaleRunning(t *testing.T) {
	tempDir := t.TempDir()
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
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.Equal(t, "my-ts", vpns[0].Name)
	assert.True(t, vpns[0].Connected)
	assert.Equal(t, "tailscale0", vpns[0].Interface)
}

func TestListVPNs_TailscaleNotRunning(t *testing.T) {
	tempDir := t.TempDir()
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
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.False(t, vpns[0].Connected)
}

func TestTailscale_ConnectDisconnectCycle(t *testing.T) {
	tempDir := t.TempDir()

	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"tailscale up":          "",
			"tailscale set --accept-dns=false --exit-node= --accept-routes=false": "",
			"tailscale status --json": `{"BackendState":"Running"}`,
			"tailscale down":          "",
			"ip route show":           "default via 192.168.1.1 dev eth0",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"ts": {Type: "tailscale"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)

	// Connect
	err := manager.Connect("ts")
	assert.NoError(t, err)

	// Verify state file
	state := manager.getActiveVPNState()
	assert.NotNil(t, state)
	assert.Equal(t, "ts", state.Name)
	assert.Equal(t, "tailscale", state.Type)
	assert.Equal(t, "tailscale0", state.Interface)

	// Disconnect
	err = manager.Disconnect("ts")
	assert.NoError(t, err)

	// Verify state file cleared
	state = manager.getActiveVPNState()
	assert.Nil(t, state)

	// Verify tailscale down was called
	executor.assertCommandExecuted(t, "tailscale down")
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

// `tailscale set` persists prefs across sessions, so a config that drops
// exit_node/accept_routes must explicitly reset them — otherwise a previous
// session's exit node or accepted routes silently remain in effect.
func TestConnectTailscale_ResetsDroppedPrefs(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default":   "default via 192.168.1.1 dev eth0",
			"tailscale up":            "",
			"tailscale status --json": `{"BackendState":"Running"}`,
			// This is the reset form: empty exit-node, explicit accept-routes=false.
			"tailscale set --accept-dns=false --exit-node= --accept-routes=false": "",
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			// No ExitNode, AcceptRoutes false — must be actively cleared.
			"ts": {Type: "tailscale"},
		},
	}
	manager := NewManager(executor, logger, configMgr)

	err := manager.Connect("ts")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "tailscale set --accept-dns=false --exit-node= --accept-routes=false")
}
