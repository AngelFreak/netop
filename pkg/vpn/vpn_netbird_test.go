package vpn

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	tmpDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip route show default": "default via 192.168.1.1 dev eth0",
			"netbird up --setup-key-file " + tmpDir + "/netbird-setupkey --management-url https://api.netbird.io --disable-dns": "",
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
	manager := NewManagerWithDir(executor, logger, configMgr, tmpDir)

	err := manager.Connect("nb")
	assert.NoError(t, err)
	// The setup key must be passed via --setup-key-file, never as an argv token.
	executor.assertCommandExecuted(t, "netbird up --setup-key-file "+tmpDir+"/netbird-setupkey --management-url https://api.netbird.io --disable-dns")
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

// TestListVPNs_ProfileDisambiguatesNetBird covers the case the typeCount
// guard is too blunt for: two NetBird configs that DO name distinct
// profiles are not ambiguous, because the daemon reports which profile is
// active. Only the entry whose profile is active may show connected.
func TestListVPNs_ProfileDisambiguatesNetBird(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Connected"}`,
			"netbird profile list": "NAME     ACTIVE\n" +
				"wendy\n" +
				"vesperx  ✓\n",
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"wendy-net":   {Type: "netbird", Profile: "wendy"},
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 2)

	byName := map[string]bool{}
	for _, v := range vpns {
		byName[v.Name] = v.Connected
	}
	assert.True(t, byName["vesperx-net"], "the entry whose profile is ACTIVE must report connected")
	assert.False(t, byName["wendy-net"], "an inactive profile must not report connected")
}

// When the daemon is down, no profile reports connected even though one is
// still marked ACTIVE — ACTIVE means "selected", not "up".
func TestListVPNs_ActiveProfileDownNotConnected(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Disconnected"}`,
			"netbird profile list":    "NAME     ACTIVE\nwendy\nvesperx  ✓\n",
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"wendy-net":   {Type: "netbird", Profile: "wendy"},
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	for _, v := range vpns {
		assert.False(t, v.Connected, "daemon down: %q must not report connected", v.Name)
	}
}

// Falling back to the old conservative behavior when "profile list" is
// unavailable (older CLI, permission error) must not regress: neither
// profile-less entry may be flagged connected.
func TestListVPNs_ProfileListUnavailableStaysConservative(t *testing.T) {
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
			"netbird profile list":    fmt.Errorf("unknown command"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"wendy-net":   {Type: "netbird", Profile: "wendy"},
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	for _, v := range vpns {
		assert.False(t, v.Connected, "no profile info: %q must not be flagged connected", v.Name)
	}
}

func TestNetBirdActiveProfile(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"checkmark", "NAME     ACTIVE\nwendy\nvesperx  ✓\n", "vesperx"},
		{"first is active", "NAME     ACTIVE\nwendy    ✓\nvesperx\n", "wendy"},
		{"single default", "NAME     ACTIVE\ndefault  ✓\n", "default"},
		{"none active", "NAME     ACTIVE\nwendy\nvesperx\n", ""},
		// Regression: a row having a second column is not proof of being
		// active. With an extra STATUS column, matching on column presence
		// alone returned the first profile listed.
		{"extra status column", "NAME     ACTIVE   STATUS\nwendy             idle\nvesperx  \u2713        up\n", "vesperx"},
		{"extra column none active", "NAME     ACTIVE   STATUS\nwendy             idle\nvesperx           up\n", ""},
		{"asterisk marker", "NAME     ACTIVE\nwendy\nvesperx  *\n", "vesperx"},
		// Shapes observed from netbird 0.76.0 on a real multi-profile host.
		// Inactive rows carry a trailing-whitespace ACTIVE column, so they
		// yield a single field and must not be mistaken for active.
		{"real: single profile none active", "NAME     ACTIVE\ndefault  \n", ""},
		{"real: middle profile active", "NAME     ACTIVE\ndefault  \nvesperx  \u2713\nwendy    \n", "vesperx"},
		{"real: last profile active", "NAME     ACTIVE\ndefault  \nvesperx  \nwendy    \u2713\n", "wendy"},
		{"empty", "", ""},
		{"header only", "NAME     ACTIVE\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, netBirdActiveProfile(tt.output))
		})
	}
}

// Regression: "netbird status --json" reflects the SHARED daemon, but
// "netbird profile list" is per-OS-user. Run unprivileged, the listing shows
// only that user's profiles with none active, while the daemon is genuinely
// connected under a profile from root's set. Reporting every entry
// disconnected then contradicts the daemon.
//
// With exactly one config entry of the type there is nothing to disambiguate,
// so daemon status alone is authoritative — same as before profiles existed.
func TestListVPNs_SingleNetBirdTrustsDaemonWhenProfileUnknown(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Connected"}`,
			// Unprivileged view: the connected profile is not even listed.
			"netbird profile list": "NAME     ACTIVE\ndefault\n",
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 1)
	assert.True(t, vpns[0].Connected,
		"a lone NetBird entry must follow daemon status when the profile list is unreadable")
}

// The real failure: TWO NetBird entries plus an unprivileged profile list.
// The daemon is connected under "vesperx", but the per-user listing shows
// only "default" with none active, so no entry matches and both report
// disconnected — contradicting the daemon, which says a tunnel is up.
//
// Observed on a real host: "net status" showed vesperx-net disconnected
// while "sudo netbird status" reported Management: Connected.
func TestListVPNs_MultiNetBirdUnreadableProfileStillReportsDaemon(t *testing.T) {
	tempDir := t.TempDir()
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"pgrep -f openvpn":        "",
			"tailscale status --json": "",
			"netbird status --json":   `{"daemonStatus":"Connected"}`,
			"netbird profile list":    "NAME     ACTIVE\ndefault\n",
		},
		errors: map[string]error{
			"pgrep -f openvpn":        fmt.Errorf("no match"),
			"tailscale status --json": fmt.Errorf("not installed"),
		},
	}
	logger := &mockLogger{}
	configMgr := &mockConfigManager{
		vpnConfigs: map[string]*types.VPNConfig{
			"wendy-net":   {Type: "netbird", Profile: "wendy"},
			"vesperx-net": {Type: "netbird", Profile: "vesperx"},
		},
	}
	manager := NewManagerWithDir(executor, logger, configMgr, tempDir)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()

	vpns, err := manager.ListVPNs()
	assert.NoError(t, err)
	assert.Len(t, vpns, 2)

	// We cannot tell WHICH profile is up, so we must not claim either is.
	// But the caller must still learn a NetBird tunnel exists, rather than
	// being told everything is down while the daemon says otherwise.
	for _, v := range vpns {
		assert.False(t, v.Connected,
			"cannot attribute the session to %q without a readable profile list", v.Name)
		assert.True(t, v.Ambiguous,
			"%q must be flagged ambiguous so the caller can surface the live daemon", v.Name)
	}
}

type statusStep = struct {
	output string
	err    error
}

// newNetBirdLoginFixture scripts "netbird status --json" as the given
// daemon states, in call order, and lets "netbird up" fail with upErr.
func newNetBirdLoginFixture(t *testing.T, cfg *types.VPNConfig, upCmd string, upErr error, states ...string) (*Manager, *sequencingExecutor) {
	t.Helper()
	tmpDir := t.TempDir()
	steps := make([]statusStep, 0, len(states))
	for _, st := range states {
		steps = append(steps, statusStep{output: `{"daemonStatus":"` + st + `"}`})
	}
	seq := &sequencingExecutor{
		mockSystemExecutor: mockSystemExecutor{
			commands: map[string]string{
				"ip route show default":          "default via 192.168.1.1 dev eth0",
				"netbird profile select vesperx": "Profile switched successfully to: vesperx",
				upCmd:                            "",
			},
			errors: map[string]error{},
		},
		callSequence: map[string][]struct {
			output string
			err    error
		}{"netbird status --json": steps},
	}
	if upErr != nil {
		seq.errors[upCmd] = upErr
	}
	configMgr := &mockConfigManager{vpnConfigs: map[string]*types.VPNConfig{"nb": cfg}}
	manager := NewManagerWithDir(seq, &mockLogger{}, configMgr, tmpDir)
	manager.verifyAttempts = 2
	manager.verifyDelay = 0
	return manager, seq
}

const loginCmd = "sudo netbird profile select vesperx && sudo netbird up"

// An SSO profile whose session lapsed makes "netbird up" wait for a browser
// login whose URL net cannot show; it looked hung, and a Ctrl-C then took
// WiFi down. When Management has refused the peer, fail fast instead, with
// the command that logs in.
func TestConnectNetBird_NeedsLoginFailsFast(t *testing.T) {
	for _, state := range []string{"NeedsLogin", "SessionExpired"} {
		t.Run(state, func(t *testing.T) {
			manager, seq := newNetBirdLoginFixture(t, &types.VPNConfig{Type: "netbird", Profile: "vesperx"}, "netbird up --disable-dns", nil, state)

			err := manager.Connect("nb")
			require.Error(t, err)
			assert.Contains(t, err.Error(), loginCmd)
			seq.assertCommandNotExecuted(t, "netbird up --disable-dns")
		})
	}
}

// LoginFailed is left behind by an interrupted browser login, but equally by
// an unreachable Management, so it must not block a connect that may work.
func TestConnectNetBird_StaleLoginFailedStillTriesUp(t *testing.T) {
	manager, seq := newNetBirdLoginFixture(t, &types.VPNConfig{Type: "netbird", Profile: "vesperx"}, "netbird up --disable-dns", nil, "LoginFailed", "Connected")

	require.NoError(t, manager.Connect("nb"))
	seq.assertCommandExecuted(t, "netbird up --disable-dns")
}

// When "up" does fail and the daemon is waiting on a login, the error names
// the command that logs in rather than only the timeout.
func TestConnectNetBird_UpFailureNamesLoginCommand(t *testing.T) {
	upErr := errors.New("command timed out after 30s")
	manager, _ := newNetBirdLoginFixture(t, &types.VPNConfig{Type: "netbird", Profile: "vesperx"}, "netbird up --disable-dns", upErr, "Idle", "LoginFailed")

	err := manager.Connect("nb")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command timed out after 30s")
	assert.Contains(t, err.Error(), loginCmd)
}

func TestConnectNetBird_UpFailureWithoutLoginStateKeepsError(t *testing.T) {
	upErr := errors.New("daemon unreachable")
	manager, _ := newNetBirdLoginFixture(t, &types.VPNConfig{Type: "netbird", Profile: "vesperx"}, "netbird up --disable-dns", upErr, "Idle", "Idle")

	err := manager.Connect("nb")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect NetBird: daemon unreachable")
	assert.NotContains(t, err.Error(), "netbird profile select")
}

// A setup key logs in without a browser, so a login-required daemon is
// exactly what "up --setup-key-file" is for: no fail-fast.
func TestConnectNetBird_SetupKeySkipsLoginCheck(t *testing.T) {
	cfg := &types.VPNConfig{Type: "netbird", Profile: "vesperx", SetupKey: "XXXXXXXX"}
	manager, seq := newNetBirdLoginFixture(t, cfg, "unused", nil, "NeedsLogin", "Connected")

	require.NoError(t, manager.Connect("nb"))
	found := false
	for _, cmd := range seq.executedCommands {
		if strings.HasPrefix(cmd, "netbird up --setup-key-file ") {
			found = true
		}
	}
	assert.True(t, found, "up must run with the setup key: %v", seq.executedCommands)
}

func TestNetBirdLoginCommand(t *testing.T) {
	assert.Equal(t, loginCmd, netBirdLoginCommand("vesperx"))
	assert.Equal(t, "sudo netbird up", netBirdLoginCommand(""))
}
