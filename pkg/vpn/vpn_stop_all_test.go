package vpn

import (
	"fmt"
	"testing"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// "Stop all" must not depend on the state file: it lives in /run, which is
// wiped at boot, while the Tailscale and NetBird daemons reconnect on their
// own. After a reboot net has no record of them, yet `net vpn stop`,
// `net vpn <name>` and `net <network>` must still bring them down.

const (
	tsStopped = `{"BackendState":"Stopped"}`
	tsRunning = `{"BackendState":"Running"}`
	nbIdle    = `{"daemonStatus":"Idle"}`
)

const openVPNProbe = "pgrep -f " + openVPNProcessPattern

// idleExecutor reports every VPN type as down; tests override the one that is
// live. Unscripted commands in mockSystemExecutor return "mock output", which
// a pgrep probe would read as a running process.
func idleExecutor() *mockSystemExecutor {
	return &mockSystemExecutor{
		commands: map[string]string{
			"tailscale status --json": tsStopped,
			"netbird status --json":   nbIdle,
		},
		errors: map[string]error{
			openVPNProbe: fmt.Errorf("exit status 1"), // pgrep: no match
		},
	}
}

func newStopAllManager(t *testing.T, exec types.SystemExecutor, links *fake.LinkManager) *Manager {
	t.Helper()
	m := NewManagerWithDir(exec, &mockLogger{}, &mockConfigManager{}, t.TempDir())
	m.routeMgr = newFakeRoutes()
	m.addrMgr = newFakeAddrs()
	if links == nil {
		links = newFakeLinks()
	}
	m.linkMgr = links
	return m
}

func TestDisconnectAll_StopsNetBirdStartedAtBoot(t *testing.T) {
	exec := idleExecutor()
	exec.commands["netbird status --json"] = `{"daemonStatus":"Connected"}`
	m := newStopAllManager(t, exec, nil)

	require.NoError(t, m.Disconnect(""))
	exec.assertCommandExecuted(t, "netbird down")
}

func TestDisconnectAll_StopsNetBirdStillConnecting(t *testing.T) {
	// At boot with Management unreachable the daemon sits in Connecting, but
	// its interface and routes are already up.
	exec := idleExecutor()
	exec.commands["netbird status --json"] = `{"daemonStatus":"Connecting"}`
	m := newStopAllManager(t, exec, nil)

	require.NoError(t, m.Disconnect(""))
	exec.assertCommandExecuted(t, "netbird down")
}

func TestDisconnectAll_StopsUntrackedTailscale(t *testing.T) {
	exec := idleExecutor()
	exec.commands["tailscale status --json"] = tsRunning
	m := newStopAllManager(t, exec, nil)

	require.NoError(t, m.Disconnect(""))
	exec.assertCommandExecuted(t, "tailscale down")
}

func TestDisconnectAll_StopsUntrackedOpenVPN(t *testing.T) {
	exec := idleExecutor()
	delete(exec.errors, openVPNProbe)
	exec.commands[openVPNProbe] = "4242"
	m := newStopAllManager(t, exec, nil)

	require.NoError(t, m.Disconnect(""))
	exec.assertCommandExecuted(t, "pkill -f "+openVPNProcessPattern)
}

func TestDisconnectAll_DeletesWireGuardButLeavesNetBirdInterface(t *testing.T) {
	// NetBird's kernel interface is WireGuard-typed but owned by its daemon;
	// deleting it under the daemon would wedge NetBird.
	links := &fake.LinkManager{ByType: map[string][]string{"wireguard": {"wg0", "wt0"}}}
	m := newStopAllManager(t, idleExecutor(), links)

	require.NoError(t, m.Disconnect(""))
	assert.Equal(t, []string{"wg0"}, links.Deleted)
}

func TestDisconnectAll_NothingRunningIsError(t *testing.T) {
	exec := idleExecutor()
	m := newStopAllManager(t, exec, nil)

	err := m.Disconnect("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no active VPN")
	exec.assertCommandNotExecuted(t, "tailscale down")
	exec.assertCommandNotExecuted(t, "netbird down")
}

func TestDisconnectAll_StopsTrackedAndUntracked(t *testing.T) {
	exec := idleExecutor()
	exec.commands["netbird status --json"] = `{"daemonStatus":"Connected"}`
	links := &fake.LinkManager{Existing: map[string]bool{"wg0": true}}
	m := newStopAllManager(t, exec, links)
	require.NoError(t, m.setActiveVPNState(vpnState{Name: "skoven", Interface: "wg0", Type: "wireguard"}))

	require.NoError(t, m.Disconnect(""))
	assert.Contains(t, links.Deleted, "wg0")
	exec.assertCommandExecuted(t, "netbird down")
	assert.Nil(t, m.getActiveVPNState(), "tracked state must be cleared")
}

func TestDisconnectAll_ReportsUntrackedTeardownFailure(t *testing.T) {
	exec := idleExecutor()
	exec.commands["netbird status --json"] = `{"daemonStatus":"Connected"}`
	exec.errors["netbird down"] = fmt.Errorf("daemon wedged")
	m := newStopAllManager(t, exec, nil)

	err := m.Disconnect("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NetBird")
}

func TestDisconnectNamed_LeavesOtherVPNsAlone(t *testing.T) {
	// Disconnect(name) targets one VPN; only the stop-all form sweeps.
	exec := idleExecutor()
	exec.commands["netbird status --json"] = `{"daemonStatus":"Connected"}`
	m := newStopAllManager(t, exec, nil)
	require.NoError(t, m.setActiveVPNState(vpnState{Name: "ts", Interface: "tailscale0", Type: "tailscale"}))

	require.NoError(t, m.Disconnect("ts"))
	exec.assertCommandExecuted(t, "tailscale down")
	exec.assertCommandNotExecuted(t, "netbird down")
}

// The reported bug: after a reboot NetBird is up but untracked, and
// `net vpn tail-private` brought Tailscale up beside it.
func TestConnect_StopsUntrackedVPNBeforeConnecting(t *testing.T) {
	exec := &sequencingExecutor{
		mockSystemExecutor: *idleExecutor(),
		callSequence: map[string][]struct {
			output string
			err    error
		}{
			// sweep probe, backend-state check, post-up verify
			"tailscale status --json": {{tsStopped, nil}, {tsStopped, nil}, {tsRunning, nil}},
		},
	}
	exec.commands["netbird status --json"] = `{"daemonStatus":"Connected"}`
	m := newStopAllManager(t, exec, nil)
	m.configMgr = &mockConfigManager{vpnConfigs: map[string]*types.VPNConfig{
		"tail-private": {Type: "tailscale", AcceptRoutes: true},
	}}
	m.verifyAttempts, m.verifyDelay = 1, 0

	require.NoError(t, m.Connect("tail-private"))

	down, up := commandIndex(exec.executedCommands, "netbird down"), commandIndex(exec.executedCommands, "tailscale up")
	require.NotEqual(t, -1, down, "NetBird must be stopped; commands: %v", exec.executedCommands)
	require.NotEqual(t, -1, up, "Tailscale must be brought up; commands: %v", exec.executedCommands)
	assert.Less(t, down, up, "NetBird must be down before Tailscale comes up")
}

func TestConnect_AbortsWhenUntrackedVPNWontStop(t *testing.T) {
	exec := idleExecutor()
	exec.commands["netbird status --json"] = `{"daemonStatus":"Connected"}`
	exec.errors["netbird down"] = fmt.Errorf("daemon wedged")
	m := newStopAllManager(t, exec, nil)
	m.configMgr = &mockConfigManager{vpnConfigs: map[string]*types.VPNConfig{
		"tail-private": {Type: "tailscale"},
	}}
	m.verifyAttempts, m.verifyDelay = 1, 0

	err := m.Connect("tail-private")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NetBird")
	exec.assertCommandNotExecuted(t, "tailscale up")
}

func commandIndex(cmds []string, want string) int {
	for i, c := range cmds {
		if c == want {
			return i
		}
	}
	return -1
}
