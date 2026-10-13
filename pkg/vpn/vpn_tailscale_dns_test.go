package vpn

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
	manager.verifyDelay = 0
	// By default tailscaled took over DNS as it came up.
	writeResolvConf(t, manager.resolvConfPath, quad100ResolvConf)
	rec := &immutableRecorder{ran: func() int { return len(seq.executedCommands) }}
	manager.setImmutable = rec.set
	return manager, seq, rec
}

const quad100ResolvConf = "nameserver 100.100.100.100\nsearch example.ts.net\n"

func writeResolvConf(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
}

// hookExecutor runs a hook after a matching command, so tests can act out
// what tailscaled does in response (e.g. rewriting resolv.conf).
type hookExecutor struct {
	*sequencingExecutor
	hooks map[string]func()
}

func (h *hookExecutor) Execute(cmd string, args ...string) (string, error) {
	out, err := h.sequencingExecutor.Execute(cmd, args...)
	if hook := h.hooks[strings.Join(append([]string{cmd}, args...), " ")]; hook != nil {
		hook()
	}
	return out, err
}

func (h *hookExecutor) ExecuteWithTimeout(_ time.Duration, cmd string, args ...string) (string, error) {
	return h.Execute(cmd, args...)
}

type warnRecorder struct {
	mockLogger
	warns []string
}

func (w *warnRecorder) Warn(msg string, _ ...interface{}) { w.warns = append(w.warns, msg) }

const (
	acceptDNSOff = "tailscale set --accept-dns=false"
	acceptDNSOn  = "tailscale set --accept-dns=true"
)

// newGaveUpFixture reproduces the 2026-10-13 failure: tailscaled was already
// running with accept-dns on when net held resolv.conf locked, so its DNS
// write failed and it never retried. resolv.conf still holds net's servers.
// reapplies says whether flipping accept-dns off and on makes tailscaled
// write the file again, as it does on the real daemon.
func newGaveUpFixture(t *testing.T, reapplies bool) (*Manager, *sequencingExecutor, *warnRecorder) {
	t.Helper()
	setCmd := "tailscale set --accept-dns=true --exit-node= --accept-routes=false"
	manager, seq, _ := newTailscaleDNSFixture(t, &types.VPNConfig{Type: "tailscale", AcceptDNS: true}, setCmd)
	seq.callSequence["tailscale status --json"] = []struct {
		output string
		err    error
	}{
		{output: `{"BackendState":"Running"}`},
		{output: `{"BackendState":"Running"}`},
	}
	writeResolvConf(t, manager.resolvConfPath, "nameserver 1.1.1.1\n")

	turnedOff := false
	manager.executor = &hookExecutor{sequencingExecutor: seq, hooks: map[string]func(){
		acceptDNSOff: func() { turnedOff = true },
		acceptDNSOn: func() {
			if reapplies && turnedOff {
				writeResolvConf(t, manager.resolvConfPath, quad100ResolvConf)
			}
		},
	}}
	logger := &warnRecorder{}
	manager.logger = logger
	return manager, seq, logger
}

// "up" and "set" are no-ops for a tailscaled whose prefs already match, so
// after unlocking resolv.conf net must flip accept-dns to make it re-apply.
func TestConnectTailscale_AcceptDNSReappliesWhenTailscaledGaveUp(t *testing.T) {
	manager, seq, _ := newGaveUpFixture(t, true)

	require.NoError(t, manager.Connect("ts"))

	off := slices.Index(seq.executedCommands, acceptDNSOff)
	on := slices.Index(seq.executedCommands, acceptDNSOn)
	require.NotEqual(t, -1, off, "accept-dns must be turned off to force a re-apply")
	assert.Less(t, off, on, "accept-dns must be turned back on after being turned off")
}

func TestConnectTailscale_AcceptDNSReapplyLeavesTailscaleDNS(t *testing.T) {
	manager, _, _ := newGaveUpFixture(t, true)

	require.NoError(t, manager.Connect("ts"))

	content, err := os.ReadFile(manager.resolvConfPath)
	require.NoError(t, err)
	assert.Equal(t, quad100ResolvConf, string(content))
}

func TestConnectTailscale_AcceptDNSReappliedSilently(t *testing.T) {
	manager, _, logger := newGaveUpFixture(t, true)

	require.NoError(t, manager.Connect("ts"))

	assert.Empty(t, logger.warns)
}

// A tailscaled that came up after the unlock wrote DNS itself; bouncing its
// pref would needlessly rewrite resolv.conf twice.
func TestConnectTailscale_AcceptDNSSkipsReapplyWhenAlreadyApplied(t *testing.T) {
	setCmd := "tailscale set --accept-dns=true --exit-node= --accept-routes=false"
	manager, seq, _ := newTailscaleDNSFixture(t, &types.VPNConfig{Type: "tailscale", AcceptDNS: true}, setCmd)

	require.NoError(t, manager.Connect("ts"))

	seq.assertCommandNotExecuted(t, acceptDNSOff)
}

// If tailscaled still does not take over DNS, the tunnel stays up (it works
// without DNS) but net must not report it as if MagicDNS were working.
func TestConnectTailscale_AcceptDNSWarnsWhenReapplyFails(t *testing.T) {
	manager, _, logger := newGaveUpFixture(t, false)

	require.NoError(t, manager.Connect("ts"))

	assert.Len(t, logger.warns, 1)
}

// Without accept_dns net owns DNS, so resolv.conf not pointing at Tailscale
// is expected and must not trigger a re-apply.
func TestConnectTailscale_DefaultNeverReappliesDNS(t *testing.T) {
	setCmd := "tailscale set --accept-dns=false --exit-node= --accept-routes=false"
	manager, seq, _ := newTailscaleDNSFixture(t, &types.VPNConfig{Type: "tailscale"}, setCmd)
	writeResolvConf(t, manager.resolvConfPath, "nameserver 1.1.1.1\n")

	require.NoError(t, manager.Connect("ts"))

	seq.assertCommandNotExecuted(t, acceptDNSOn)
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
	writeResolvConf(t, manager.resolvConfPath, quad100ResolvConf)
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
