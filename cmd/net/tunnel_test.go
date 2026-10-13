package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/tunnel"
	"github.com/angelfreak/net/pkg/tunnel/testsshd"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTunnelManager records calls. Start echoes the spec back as an up
// tunnel unless startResult or startErr is set.
type fakeTunnelManager struct {
	started     []types.TunnelSpec
	startResult *types.TunnelStatus
	startErr    error
	list        []types.TunnelStatus
	stopTargets []string
	stopped     []types.TunnelStatus
	stopErr     error
}

func (f *fakeTunnelManager) Start(spec types.TunnelSpec) (*types.TunnelStatus, error) {
	f.started = append(f.started, spec)
	if f.startErr != nil {
		return nil, f.startErr
	}
	if f.startResult != nil {
		return f.startResult, nil
	}
	return &types.TunnelStatus{Name: spec.Name, Host: spec.Host, Forwards: spec.Forwards, Up: true, AdHoc: spec.AdHoc}, nil
}

func (f *fakeTunnelManager) Stop(target string) ([]types.TunnelStatus, error) {
	f.stopTargets = append(f.stopTargets, target)
	return f.stopped, f.stopErr
}

func (f *fakeTunnelManager) List() ([]types.TunnelStatus, error) { return f.list, nil }

func tunnelTestApp(tunnels map[string]types.TunnelConfig) (*App, *fakeTunnelManager, *bytesPair) {
	app, stdout, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{Tunnel: tunnels}}
	fake := &fakeTunnelManager{}
	app.TunnelMgr = fake
	return app, fake, &bytesPair{stdout: stdout.String, stderr: stderr.String}
}

type bytesPair struct{ stdout, stderr func() string }

var appTunnel = map[string]types.TunnelConfig{
	"app": {Host: "user@100.72.140.241", Port: 2222, Identity: "~/.ssh/k", Forward: []string{"13000:3000"}},
}

func TestTunnel_IsRootExempt(t *testing.T) {
	assert.False(t, commandNeedsRootArgs([]string{"tunnel", "box", "3000"}))
}

func TestTunnel_AdHocSpec(t *testing.T) {
	app, fake, _ := tunnelTestApp(nil)

	require.NoError(t, app.RunTunnel([]string{"user@box", "3000"}))

	require.Len(t, fake.started, 1)
	assert.Equal(t, types.TunnelSpec{
		Name: "user@box:3000", Host: "user@box", AdHoc: true,
		Forwards: []types.Forward{{LocalPort: 3000, RemoteHost: "127.0.0.1", RemotePort: 3000}},
	}, fake.started[0])
}

func TestTunnel_ConfiguredSpec(t *testing.T) {
	app, fake, _ := tunnelTestApp(appTunnel)

	require.NoError(t, app.RunTunnel([]string{"app"}))

	require.Len(t, fake.started, 1)
	assert.Equal(t, types.TunnelSpec{
		Name: "app", Host: "user@100.72.140.241", Port: 2222, Identity: "~/.ssh/k",
		Forwards: []types.Forward{{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000, Pinned: true}},
	}, fake.started[0])
}

func TestTunnel_ConfiguredNameIgnoresCase(t *testing.T) {
	app, fake, _ := tunnelTestApp(appTunnel)

	require.NoError(t, app.RunTunnel([]string{"App"}))

	require.Len(t, fake.started, 1)
	assert.Equal(t, "app", fake.started[0].Name)
}

func TestTunnel_UnknownNameWithoutPortsIsUsageError(t *testing.T) {
	app, _, out := tunnelTestApp(nil)

	err := app.RunTunnel([]string{"foo"})

	assert.Equal(t, exitUsage, exitCode(err))
	assert.Contains(t, out.stderr(), "net tunnel foo 3000")
}

func TestTunnel_ConfiguredNameWithPortsIsUsageError(t *testing.T) {
	app, _, _ := tunnelTestApp(appTunnel)

	err := app.RunTunnel([]string{"app", "3000"})

	assert.Equal(t, exitUsage, exitCode(err))
}

func TestTunnel_BadForwardIsUsageError(t *testing.T) {
	app, fake, _ := tunnelTestApp(nil)

	err := app.RunTunnel([]string{"box", "abc"})

	assert.Equal(t, exitUsage, exitCode(err))
	assert.Empty(t, fake.started)
}

func TestTunnel_OptionLikeHostIsUsageError(t *testing.T) {
	app, fake, _ := tunnelTestApp(nil)

	err := app.RunTunnel([]string{"-oProxyCommand=sh", "3000"})

	assert.Equal(t, exitUsage, exitCode(err))
	assert.Empty(t, fake.started)
}

func TestTunnel_StartPrintsForwardAndStopHint(t *testing.T) {
	app, _, out := tunnelTestApp(nil)

	require.NoError(t, app.RunTunnel([]string{"box", "3000"}))

	assert.Equal(t, "✓ Tunnel box:3000 up via box\n  localhost:3000 → 127.0.0.1:3000\nStop with: net tunnel stop 3000\n", out.stdout())
}

func TestTunnel_ConfiguredStopHintUsesName(t *testing.T) {
	app, _, out := tunnelTestApp(appTunnel)

	require.NoError(t, app.RunTunnel([]string{"app"}))

	assert.Contains(t, out.stdout(), "Stop with: net tunnel stop app\n")
}

func TestTunnel_StartShowsMovedPort(t *testing.T) {
	app, fake, out := tunnelTestApp(nil)
	fake.startResult = &types.TunnelStatus{Name: "box:3000", Host: "box", Up: true, AdHoc: true,
		Forwards: []types.Forward{{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000}}}

	require.NoError(t, app.RunTunnel([]string{"box", "3000"}))

	assert.Contains(t, out.stdout(), "  localhost:13000 → 127.0.0.1:3000 (3000 was in use)\n")
}

func TestTunnel_WarningsGoToStderr(t *testing.T) {
	app, fake, out := tunnelTestApp(nil)
	fake.startResult = &types.TunnelStatus{Name: "box:3000", Host: "box", Up: true,
		Forwards: []types.Forward{{LocalPort: 3000, RemoteHost: "127.0.0.1", RemotePort: 3000}},
		Warnings: []string{"connected, but nothing is listening on 127.0.0.1:3000 on box"}}

	require.NoError(t, app.RunTunnel([]string{"box", "3000"}))

	assert.Equal(t, "Warning: connected, but nothing is listening on 127.0.0.1:3000 on box\n", out.stderr())
}

func TestTunnel_StartErrorPrinted(t *testing.T) {
	app, fake, out := tunnelTestApp(nil)
	fake.startErr = errors.New("the host key for box is not trusted yet")

	err := app.RunTunnel([]string{"box", "3000"})

	assert.Equal(t, exitFailed, exitCode(err))
	assert.Equal(t, "Error: the host key for box is not trusted yet\n", out.stderr())
}

func TestTunnel_AuthFailureUnderSudoExplainsAgent(t *testing.T) {
	app, fake, out := tunnelTestApp(nil)
	app.TunnelSudo = true
	fake.startErr = fmt.Errorf("box refused the login: %w", tunnel.ErrAuthFailed)

	_ = app.RunTunnel([]string{"box", "3000"})

	assert.Contains(t, out.stderr(), "run 'net tunnel' without sudo")
}

func TestTunnel_ListMergesConfiguredTunnels(t *testing.T) {
	app, fake, out := tunnelTestApp(appTunnel)
	fake.list = []types.TunnelStatus{{Name: "box:3000", Host: "box", Up: true, AdHoc: true,
		Forwards: []types.Forward{{LocalPort: 3000, RemoteHost: "127.0.0.1", RemotePort: 3000}}}}

	require.NoError(t, app.RunTunnel(nil))

	assert.Equal(t, "app (user@100.72.140.241) - stopped: localhost:13000 → 127.0.0.1:3000\n"+
		"box:3000 (box) - up: localhost:3000 → 127.0.0.1:3000\n", out.stdout())
}

func TestTunnel_ListShowsDroppedTunnelAsDown(t *testing.T) {
	app, fake, out := tunnelTestApp(appTunnel)
	fake.list = []types.TunnelStatus{{Name: "app", Host: "user@100.72.140.241", Up: false,
		Forwards: []types.Forward{{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000}}}}

	require.NoError(t, app.RunTunnel(nil))

	assert.Equal(t, "app (user@100.72.140.241) - down: localhost:13000 → 127.0.0.1:3000\n", out.stdout())
}

func TestTunnel_ListEmpty(t *testing.T) {
	app, _, out := tunnelTestApp(nil)

	require.NoError(t, app.RunTunnel(nil))

	assert.Equal(t, "No tunnels\n", out.stdout())
}

func TestTunnel_ListJSON(t *testing.T) {
	app, _, out := tunnelTestApp(appTunnel)
	app.JSON = true

	require.NoError(t, app.RunTunnel(nil))

	env := decodeEnvelope(t, out.stdout())
	assert.Equal(t, "tunnel", env.Command)
	assert.JSONEq(t, `{"tunnels":[{"name":"app","host":"user@100.72.140.241","state":"stopped","ad_hoc":false,
		"forwards":[{"local_port":13000,"remote_host":"127.0.0.1","remote_port":3000}]}]}`, string(env.Data))
}

func TestTunnel_StartRejectsJSON(t *testing.T) {
	app, fake, _ := tunnelTestApp(nil)
	app.JSON = true

	err := app.RunTunnel([]string{"box", "3000"})

	assert.Equal(t, exitUsage, exitCode(err))
	assert.Empty(t, fake.started)
}

func TestTunnel_StopTarget(t *testing.T) {
	app, fake, out := tunnelTestApp(nil)
	fake.stopped = []types.TunnelStatus{{Name: "box:3000"}}

	require.NoError(t, app.RunTunnel([]string{"stop", "3000"}))

	assert.Equal(t, []string{"3000"}, fake.stopTargets)
	assert.Equal(t, "✓ Tunnel box:3000 stopped\n", out.stdout())
}

func TestTunnel_StopAllWhenNoneRunning(t *testing.T) {
	app, fake, out := tunnelTestApp(nil)

	require.NoError(t, app.RunTunnel([]string{"stop"}))

	assert.Equal(t, []string{""}, fake.stopTargets)
	assert.Equal(t, "No tunnels running\n", out.stdout())
}

func TestTunnel_StopUnknownIsNotFound(t *testing.T) {
	app, fake, _ := tunnelTestApp(nil)
	fake.stopErr = fmt.Errorf("no tunnel %q: %w", "x", types.ErrNotFound)

	err := app.RunTunnel([]string{"stop", "x"})

	assert.Equal(t, codeNotFound, errorCode(err))
}

func TestTunnel_StopTooManyArgsIsUsageError(t *testing.T) {
	app, _, _ := tunnelTestApp(nil)

	err := app.RunTunnel([]string{"stop", "a", "b"})

	assert.Equal(t, exitUsage, exitCode(err))
}

func TestStatus_ShowsTunnels(t *testing.T) {
	app, stdout := goldenApp()
	app.TunnelMgr = &fakeTunnelManager{list: []types.TunnelStatus{{Name: "app", Host: "box", Up: true,
		Forwards: []types.Forward{{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000}}}}}

	require.NoError(t, app.RunStatus())

	assert.Contains(t, stdout.String(), "\nTunnels\n-------\napp (box) - up: localhost:13000 → 127.0.0.1:3000\n")
}

func TestStatus_JSONIncludesTunnels(t *testing.T) {
	app, stdout := goldenApp()
	app.JSON = true
	app.TunnelMgr = &fakeTunnelManager{list: []types.TunnelStatus{{Name: "app", Host: "box", Up: true}}}

	require.NoError(t, app.RunStatus())

	var data struct {
		Tunnels []tunnelEntry `json:"tunnels"`
	}
	require.NoError(t, json.Unmarshal(decodeEnvelope(t, stdout.String()).Data, &data))
	require.Len(t, data.Tunnels, 1)
	assert.Equal(t, "up", data.Tunnels[0].State)
}

// The wired path: argv through the real cobra tree and App into a real
// tunnel.Manager, which runs the real ssh client against testsshd.
func TestWiring_TunnelEndToEnd(t *testing.T) {
	server := testsshd.Start(t)
	dir, err := os.MkdirTemp("", "nt")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	mgr := tunnel.NewManager(system.NewExecutor(&testLogger{}, false), &testLogger{}, filepath.Join(dir, "net", "tunnels"))
	mgr.UseSSHConfig(server.ConfigPath)
	t.Cleanup(func() { _, _ = mgr.Stop("") })
	withTunnels := func(a *App) { a.TunnelMgr = mgr }

	remote := httpService(t)
	port := freeLocalPort(t)

	out := runRootWith(t, withTunnels, "tunnel", "testhost", fmt.Sprintf("%d:%d", port, remote))
	assert.Contains(t, out, "✓ Tunnel testhost:")
	assert.Equal(t, "hello", httpGet(t, port))

	list := decodeEnvelope(t, runRootWith(t, withTunnels, "--json", "tunnel"))
	assert.Contains(t, string(list.Data), `"state":"up"`)

	out = runRootWith(t, withTunnels, "tunnel", "stop", fmt.Sprint(port))
	assert.Contains(t, out, "stopped")
}

func httpService(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "hello") })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func httpGet(t *testing.T, port int) string {
	t.Helper()
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}
