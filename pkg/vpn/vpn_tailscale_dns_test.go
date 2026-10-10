package vpn

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/angelfreak/net/pkg/config"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// immutableCall is one recorded call to the injected setImmutable func.
// cmdsBefore is how many commands the executor had run at that moment, so
// tests can assert the unlock happens before tailscale is told to write DNS.
type immutableCall struct {
	path       string
	immutable  bool
	cmdsBefore int
}

type immutableRecorder struct {
	calls []immutableCall
	err   error
	ran   func() int
}

func (r *immutableRecorder) set(path string, immutable bool) error {
	r.calls = append(r.calls, immutableCall{path: path, immutable: immutable, cmdsBefore: r.ran()})
	return r.err
}

// newTailscaleDNSFixture returns a manager for a logged-in ("Stopped")
// Tailscale profile whose resolv.conf lock calls are recorded.
func newTailscaleDNSFixture(t *testing.T, cfg *types.VPNConfig, setCmd string) (*Manager, *sequencingExecutor, *immutableRecorder) {
	t.Helper()
	tmpDir := t.TempDir()
	seq := &sequencingExecutor{
		mockSystemExecutor: mockSystemExecutor{
			commands: map[string]string{
				"ip route show default": "default via 192.168.1.1 dev eth0",
				"tailscale up":          "",
				setCmd:                  "",
			},
		},
		callSequence: map[string][]struct {
			output string
			err    error
		}{
			"tailscale status --json": {
				{output: `{"BackendState":"Stopped"}`},
				{output: `{"BackendState":"Running"}`},
			},
		},
	}
	configMgr := &mockConfigManager{vpnConfigs: map[string]*types.VPNConfig{"ts": cfg}}
	manager := NewManagerWithDir(seq, &mockLogger{}, configMgr, tmpDir)
	manager.resolvConfPath = filepath.Join(tmpDir, "resolv.conf")
	rec := &immutableRecorder{ran: func() int { return len(seq.executedCommands) }}
	manager.setImmutable = rec.set
	return manager, seq, rec
}

// With accept_dns, Tailscale owns resolv.conf: net turns its DNS on and
// releases net's immutable lock before "up". Otherwise tailscaled's write
// fails with "operation not permitted" and tailnet names never resolve.
func TestConnectTailscale_AcceptDNSUnlocksResolvConfBeforeUp(t *testing.T) {
	setCmd := "tailscale set --accept-dns=true --exit-node= --accept-routes=false"
	manager, seq, rec := newTailscaleDNSFixture(t, &types.VPNConfig{Type: "tailscale", AcceptDNS: true}, setCmd)

	require.NoError(t, manager.Connect("ts"))

	seq.assertCommandExecuted(t, setCmd)
	require.Len(t, rec.calls, 1, "resolv.conf must be unlocked exactly once")
	assert.Equal(t, manager.resolvConfPath, rec.calls[0].path)
	assert.False(t, rec.calls[0].immutable, "the call must clear the immutable flag, not set it")
	upIdx := slices.Index(seq.executedCommands, "tailscale up")
	require.NotEqual(t, -1, upIdx)
	assert.LessOrEqual(t, rec.calls[0].cmdsBefore, upIdx, "unlock must happen before tailscale up")
}

// A login "up" restates every pref net manages, so it must carry
// --accept-dns=true too — otherwise tailscale applies false at login.
func TestConnectTailscale_AcceptDNSNeedsLoginRestatesPref(t *testing.T) {
	tmpDir := t.TempDir()
	upCmd := "tailscale up --auth-key=file:" + tmpDir + "/tailscale-authkey --accept-dns=true --exit-node= --accept-routes=false"
	seq := &sequencingExecutor{
		mockSystemExecutor: mockSystemExecutor{
			commands: map[string]string{
				"ip route show default": "default via 192.168.1.1 dev eth0",
				upCmd:                   "",
				"tailscale set --accept-dns=true --exit-node= --accept-routes=false": "",
			},
		},
		callSequence: map[string][]struct {
			output string
			err    error
		}{
			"tailscale status --json": {
				{output: `{"BackendState":"NeedsLogin"}`},
				{output: `{"BackendState":"Running"}`},
			},
		},
	}
	configMgr := &mockConfigManager{vpnConfigs: map[string]*types.VPNConfig{
		"ts": {Type: "tailscale", AuthKey: "tskey-auth-xxxxx", AcceptDNS: true},
	}}
	manager := NewManagerWithDir(seq, &mockLogger{}, configMgr, tmpDir)
	manager.resolvConfPath = filepath.Join(tmpDir, "resolv.conf")
	manager.setImmutable = func(string, bool) error { return nil }

	require.NoError(t, manager.Connect("ts"))
	seq.assertCommandExecuted(t, upCmd)
}

// Without accept_dns, net keeps owning DNS: Tailscale DNS stays off and
// resolv.conf's lock is never touched.
func TestConnectTailscale_DefaultLeavesResolvConfLocked(t *testing.T) {
	setCmd := "tailscale set --accept-dns=false --exit-node= --accept-routes=false"
	manager, seq, rec := newTailscaleDNSFixture(t, &types.VPNConfig{Type: "tailscale"}, setCmd)

	require.NoError(t, manager.Connect("ts"))

	seq.assertCommandExecuted(t, setCmd)
	assert.Empty(t, rec.calls, "resolv.conf lock must not be touched without accept_dns")
}

// The tunnel itself does not depend on DNS, so a failed unlock (e.g. no
// resolv.conf) is reported but does not fail the connection.
func TestConnectTailscale_AcceptDNSUnlockFailureIsNotFatal(t *testing.T) {
	setCmd := "tailscale set --accept-dns=true --exit-node= --accept-routes=false"
	manager, seq, rec := newTailscaleDNSFixture(t, &types.VPNConfig{Type: "tailscale", AcceptDNS: true}, setCmd)
	rec.err = errors.New("opening resolv.conf: no such file or directory")

	require.NoError(t, manager.Connect("ts"))
	seq.assertCommandExecuted(t, setCmd)
}

// accept_dns travels the real path: YAML → config validation → VPNConfig →
// Connect. A config without the key must produce exactly the commands an
// explicit "accept_dns: false" does, i.e. today's behaviour.
func TestConnectTailscale_AcceptDNSFromYAMLConfig(t *testing.T) {
	run := func(t *testing.T, acceptDNSLine string, setCmd string) (*sequencingExecutor, *immutableRecorder) {
		t.Helper()
		cfgPath := filepath.Join(t.TempDir(), "config.yaml")
		yaml := "vpn:\n  ts:\n    type: tailscale\n" + acceptDNSLine
		require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0600))
		cfgMgr := config.NewManager(&mockLogger{})
		_, err := cfgMgr.LoadConfig(cfgPath)
		require.NoError(t, err)

		manager, seq, rec := newTailscaleDNSFixture(t, &types.VPNConfig{}, setCmd)
		manager.configMgr = cfgMgr
		require.NoError(t, manager.Connect("ts"))
		return seq, rec
	}

	t.Run("enabled", func(t *testing.T) {
		setCmd := "tailscale set --accept-dns=true --exit-node= --accept-routes=false"
		seq, rec := run(t, "    accept_dns: true\n", setCmd)
		seq.assertCommandExecuted(t, setCmd)
		assert.Len(t, rec.calls, 1)
	})

	t.Run("absent matches explicit false", func(t *testing.T) {
		setCmd := "tailscale set --accept-dns=false --exit-node= --accept-routes=false"
		absentSeq, absentRec := run(t, "", setCmd)
		falseSeq, falseRec := run(t, "    accept_dns: false\n", setCmd)
		assert.Equal(t, falseSeq.executedCommands, absentSeq.executedCommands)
		absentSeq.assertCommandExecuted(t, setCmd)
		assert.Empty(t, absentRec.calls)
		assert.Empty(t, falseRec.calls)
	})
}
