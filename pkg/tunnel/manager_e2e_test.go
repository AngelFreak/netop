package tunnel

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the real ssh client against testSSHD through Manager:
// every ssh flag, the control socket and the log parsing are exercised for
// real. They need no root and no sshd, only the ssh binary.

// e2eManager returns a Manager whose ssh uses testSSHD's config. Every
// tunnel it starts is stopped when the test ends, so no ssh outlives it.
func e2eManager(t *testing.T) (*Manager, *testSSHD) {
	t.Helper()
	d := startTestSSHD(t)
	dir := filepath.Join(shortTempDir(t), "net", "tunnels")
	m := NewManager(system.NewExecutor(nopLogger{}, false), nopLogger{}, dir)
	m.sshConfig = d.ConfigPath
	t.Cleanup(func() { _, _ = m.Stop("") })
	return m, d
}

// shortTempDir returns a temp dir with a short path: t.TempDir embeds the
// test name, which can push control socket paths past ssh's limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nt")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// remoteService starts an HTTP server answering "hello", standing in for
// the service on the SSH host. Returns its port.
func remoteService(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func get(port int) (string, error) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func spec(host string, forwards ...types.Forward) types.TunnelSpec {
	return types.TunnelSpec{Name: AdHocName(host, forwards), Host: host, Forwards: forwards, AdHoc: true}
}

// toRemote forwards a fresh local port to remotePort on the SSH host.
func toRemote(t *testing.T, remotePort int) types.Forward {
	return types.Forward{LocalPort: closedPort(t), RemoteHost: "127.0.0.1", RemotePort: remotePort, Pinned: true}
}

func TestE2E_TrafficFlowsThroughTunnel(t *testing.T) {
	m, _ := e2eManager(t)
	fwd := toRemote(t, remoteService(t))

	_, err := m.Start(spec("testhost", fwd))
	require.NoError(t, err)

	body, err := get(fwd.LocalPort)
	require.NoError(t, err)
	assert.Equal(t, "hello", body)
}

func TestE2E_StartReportsUp(t *testing.T) {
	m, _ := e2eManager(t)

	st, err := m.Start(spec("testhost", toRemote(t, remoteService(t))))

	require.NoError(t, err)
	assert.True(t, st.Up)
}

func TestE2E_ListShowsRunningTunnel(t *testing.T) {
	m, _ := e2eManager(t)
	s := spec("testhost", toRemote(t, remoteService(t)))
	_, err := m.Start(s)
	require.NoError(t, err)

	list, err := m.List()

	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, types.TunnelStatus{Name: s.Name, Host: "testhost", Forwards: list[0].Forwards, Up: true, AdHoc: true}, list[0])
}

func TestE2E_StartTwiceKeepsOneTunnel(t *testing.T) {
	m, _ := e2eManager(t)
	s := spec("testhost", toRemote(t, remoteService(t)))
	_, err := m.Start(s)
	require.NoError(t, err)

	_, err = m.Start(s)
	require.NoError(t, err)

	list, err := m.List()
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestE2E_StopByLocalPortEndsTraffic(t *testing.T) {
	m, _ := e2eManager(t)
	fwd := toRemote(t, remoteService(t))
	_, err := m.Start(spec("testhost", fwd))
	require.NoError(t, err)

	stopped, err := m.Stop(fmt.Sprint(fwd.LocalPort))
	require.NoError(t, err)
	require.Len(t, stopped, 1)

	_, err = get(fwd.LocalPort)
	assert.Error(t, err)
}

func TestE2E_StopRemovesState(t *testing.T) {
	m, _ := e2eManager(t)
	s := spec("testhost", toRemote(t, remoteService(t)))
	_, err := m.Start(s)
	require.NoError(t, err)

	_, err = m.Stop(s.Name)
	require.NoError(t, err)

	entries, err := os.ReadDir(m.dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestE2E_StopUnknownIsNotFound(t *testing.T) {
	m, _ := e2eManager(t)

	_, err := m.Stop("nope")

	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestE2E_DeadTunnelListedAsDown(t *testing.T) {
	m, d := e2eManager(t)
	s := spec("testhost", toRemote(t, remoteService(t)))
	_, err := m.Start(s)
	require.NoError(t, err)
	// Stop the ssh master behind net's back, as a network drop would.
	sock := filepath.Join(m.dir, tunnelID(s.Name)+".sock")
	_, err = m.executor.Execute("ssh", "-F", d.ConfigPath, "-S", sock, "-O", "exit", "testhost")
	require.NoError(t, err)

	list, err := m.List()

	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.False(t, list[0].Up)
}

func TestE2E_RestartAfterDropBringsTunnelBack(t *testing.T) {
	m, d := e2eManager(t)
	fwd := toRemote(t, remoteService(t))
	s := spec("testhost", fwd)
	_, err := m.Start(s)
	require.NoError(t, err)
	sock := filepath.Join(m.dir, tunnelID(s.Name)+".sock")
	_, err = m.executor.Execute("ssh", "-F", d.ConfigPath, "-S", sock, "-O", "exit", "testhost")
	require.NoError(t, err)

	_, err = m.Start(s)
	require.NoError(t, err)

	body, err := get(fwd.LocalPort)
	require.NoError(t, err)
	assert.Equal(t, "hello", body)
}

func TestE2E_WarnsWhenNothingListensRemotely(t *testing.T) {
	m, _ := e2eManager(t)

	st, err := m.Start(spec("testhost", toRemote(t, closedPort(t))))

	require.NoError(t, err)
	require.Len(t, st.Warnings, 1)
	assert.Contains(t, st.Warnings[0], "nothing is listening on 127.0.0.1:")
}

func TestE2E_NoWarningWhenServiceListens(t *testing.T) {
	m, _ := e2eManager(t)

	st, err := m.Start(spec("testhost", toRemote(t, remoteService(t))))

	require.NoError(t, err)
	assert.Empty(t, st.Warnings)
}

func TestE2E_BusyLocalPortMovesToAnother(t *testing.T) {
	m, _ := e2eManager(t)
	remote := remoteService(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port

	st, err := m.Start(spec("testhost", types.Forward{LocalPort: busyPort, RemoteHost: "127.0.0.1", RemotePort: remote}))
	require.NoError(t, err)

	require.NotEqual(t, busyPort, st.Forwards[0].LocalPort)
	body, err := get(st.Forwards[0].LocalPort)
	require.NoError(t, err)
	assert.Equal(t, "hello", body)
}

func TestE2E_UntrustedHostKeyExplained(t *testing.T) {
	m, _ := e2eManager(t)

	_, err := m.Start(spec("unknownhost", toRemote(t, remoteService(t))))

	assert.ErrorContains(t, err, "host key for unknownhost is not trusted yet")
}

func TestE2E_RejectedKeyIsAuthFailure(t *testing.T) {
	m, _ := e2eManager(t)

	_, err := m.Start(spec("badkeyhost", toRemote(t, remoteService(t))))

	assert.ErrorIs(t, err, ErrAuthFailed)
}

func TestE2E_FailedStartLeavesNoState(t *testing.T) {
	m, _ := e2eManager(t)

	_, err := m.Start(spec("badkeyhost", toRemote(t, remoteService(t))))
	require.Error(t, err)

	list, err := m.List()
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestE2E_ListWithoutDirIsEmpty(t *testing.T) {
	m := NewManager(system.NewExecutor(nopLogger{}, false), nopLogger{}, filepath.Join(t.TempDir(), "missing"))

	list, err := m.List()

	require.NoError(t, err)
	assert.Empty(t, list)
}
