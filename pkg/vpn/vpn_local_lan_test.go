package vpn

import (
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With accept_routes, Tailscale installs every subnet the tailnet advertises
// into its table 52, which the kernel consults before main. When a peer
// advertises the very LAN the laptop is on (a travel router advertising its
// own 192.168.20.0/24), traffic to the local gateway and its DNS server goes
// into the tunnel and DNS dies. net keeps the uplink's own subnets on the main
// table with a policy rule ahead of table 52.

var (
	lanRuleDel = "del " + strconv.Itoa(localLANRulePriority)
	lanRuleAdd = "add 192.168.20.0/24 " + strconv.Itoa(localLANRulePriority)
)

// lanRoutes is a laptop on WiFi 192.168.20.0/24 with a Docker bridge and a
// gateway route that is not a LAN.
func lanRoutes() *fake.RouteManager {
	return &fake.RouteManager{Routes: []types.Route{
		{Gw: "192.168.20.1", Iface: "wlp1s0"}, // default
		{Dst: "192.168.20.0/24", Iface: "wlp1s0"},
		{Dst: "172.17.0.0/16", Iface: "docker0"},
		{Dst: "203.0.113.7/32", Gw: "192.168.20.1", Iface: "wlp1s0"},
	}}
}

func newTailscaleLANFixture(t *testing.T, cfg *types.VPNConfig, upErr error) (*Manager, *sequencingExecutor, *fake.RuleManager) {
	t.Helper()
	exec := &sequencingExecutor{
		mockSystemExecutor: *idleExecutor(),
		callSequence: map[string][]struct {
			output string
			err    error
		}{
			// stop-all sweep probe, backend-state check, post-up verify
			"tailscale status --json": {{tsStopped, nil}, {tsStopped, nil}, {tsRunning, nil}},
		},
	}
	if upErr != nil {
		exec.errors["tailscale up"] = upErr
	}
	m := newStopAllManager(t, exec, nil)
	m.routeMgr = lanRoutes()
	m.configMgr = &mockConfigManager{vpnConfigs: map[string]*types.VPNConfig{"tail-private": cfg}}
	m.verifyAttempts, m.verifyDelay = 1, 0
	rules := &fake.RuleManager{}
	m.ruleMgr = rules
	return m, exec, rules
}

func TestConnectTailscale_AcceptRoutesKeepsLocalLANDirect(t *testing.T) {
	m, exec, rules := newTailscaleLANFixture(t, &types.VPNConfig{Type: "tailscale", AcceptRoutes: true}, nil)
	var cmdsAtAdd int
	rules.OnCall = func() { cmdsAtAdd = len(exec.executedCommands) }

	require.NoError(t, m.Connect("tail-private"))

	// Stale rules cleared first; only the uplink's connected subnet is kept
	// direct (not the Docker bridge, not the gateway route).
	assert.Equal(t, []string{lanRuleDel, lanRuleAdd}, rules.Calls)
	up := slices.Index(exec.executedCommands, "tailscale up")
	require.NotEqual(t, -1, up)
	assert.LessOrEqual(t, cmdsAtAdd, up, "rule must exist before Tailscale installs its routes")
}

func TestConnectTailscale_WithoutAcceptRoutesLeavesRulesAlone(t *testing.T) {
	m, _, rules := newTailscaleLANFixture(t, &types.VPNConfig{Type: "tailscale"}, nil)

	require.NoError(t, m.Connect("tail-private"))
	assert.Empty(t, rules.Calls, "no accepted routes, nothing to protect: must be a no-op")
}

func TestConnectTailscale_ExitNodeLeavesLANPolicyToTailscale(t *testing.T) {
	// With an exit node Tailscale deliberately blocks LAN access unless
	// --exit-node-allow-lan-access; a rule here would silently undo that.
	m, exec, rules := newTailscaleLANFixture(t, &types.VPNConfig{Type: "tailscale", AcceptRoutes: true, ExitNode: "us-1"}, nil)
	exec.commands["tailscale set --accept-dns=false --exit-node=us-1 --accept-routes=true"] = ""

	require.NoError(t, m.Connect("tail-private"))
	assert.Empty(t, rules.Calls)
}

func TestConnectTailscale_FailedConnectRemovesLANRules(t *testing.T) {
	m, _, rules := newTailscaleLANFixture(t, &types.VPNConfig{Type: "tailscale", AcceptRoutes: true}, fmt.Errorf("control unreachable"))

	require.Error(t, m.Connect("tail-private"))
	assert.Equal(t, []string{lanRuleDel, lanRuleAdd, lanRuleDel}, rules.Calls)
}

func TestConnectTailscale_LANRuleFailureIsNotFatal(t *testing.T) {
	// The tunnel itself works without the rule; only the local LAN is at risk.
	m, _, rules := newTailscaleLANFixture(t, &types.VPNConfig{Type: "tailscale", AcceptRoutes: true}, nil)
	rules.AddErr = fmt.Errorf("operation not permitted")

	require.NoError(t, m.Connect("tail-private"))
}

func TestDisconnectTailscale_RemovesLANRules(t *testing.T) {
	exec := idleExecutor()
	m := newStopAllManager(t, exec, nil)
	rules := &fake.RuleManager{}
	m.ruleMgr = rules
	require.NoError(t, m.setActiveVPNState(vpnState{Name: "tail-private", Interface: "tailscale0", Type: "tailscale"}))

	require.NoError(t, m.Disconnect(""))
	exec.assertCommandExecuted(t, "tailscale down")
	assert.Contains(t, rules.Calls, lanRuleDel)
}

func TestStopAll_UntrackedTailscaleRemovesLANRules(t *testing.T) {
	exec := idleExecutor()
	exec.commands["tailscale status --json"] = tsRunning
	m := newStopAllManager(t, exec, nil)
	rules := &fake.RuleManager{}
	m.ruleMgr = rules

	require.NoError(t, m.Disconnect(""))
	assert.Contains(t, rules.Calls, lanRuleDel)
}

func TestDisconnectNonTailscale_LeavesRulesAlone(t *testing.T) {
	links := &fake.LinkManager{Existing: map[string]bool{"wg0": true}}
	m := newStopAllManager(t, idleExecutor(), links)
	rules := &fake.RuleManager{}
	m.ruleMgr = rules
	require.NoError(t, m.setActiveVPNState(vpnState{Name: "skoven", Interface: "wg0", Type: "wireguard"}))

	require.NoError(t, m.Disconnect(""))
	assert.Empty(t, rules.Calls)
}
