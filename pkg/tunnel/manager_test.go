package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nopLogger struct{}

func (nopLogger) Debug(string, ...interface{}) {}
func (nopLogger) Info(string, ...interface{})  {}
func (nopLogger) Warn(string, ...interface{})  {}
func (nopLogger) Error(string, ...interface{}) {}

func TestDirFor_PrefersXDGRuntimeDir(t *testing.T) {
	assert.Equal(t, "/run/user/1000/net/tunnels", dirFor(1000, "/run/user/1000", func(string) bool { return false }))
}

func TestDirFor_FallsBackToRunUser(t *testing.T) {
	exists := func(p string) bool { return p == "/run/user/1000" }
	assert.Equal(t, "/run/user/1000/net/tunnels", dirFor(1000, "", exists))
}

func TestDirFor_FallsBackToTmp(t *testing.T) {
	assert.Equal(t, "/tmp/net-1000/tunnels", dirFor(1000, "", func(string) bool { return false }))
}

func TestEnsureDir_CreatesPrivateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "net", "tunnels")

	require.NoError(t, ensureDir(dir))

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestEnsureDir_RejectsSymlink(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(base, "elsewhere"), 0700))
	require.NoError(t, os.Mkdir(filepath.Join(base, "net"), 0700))
	dir := filepath.Join(base, "net", "tunnels")
	require.NoError(t, os.Symlink(filepath.Join(base, "elsewhere"), dir))

	assert.Error(t, ensureDir(dir))
}

func TestEnsureDir_RejectsSharedParent(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "net-1000")
	require.NoError(t, os.Mkdir(parent, 0700))
	require.NoError(t, os.Chmod(parent, 0777))

	assert.Error(t, ensureDir(filepath.Join(parent, "tunnels")))
}

func TestTunnelID_ReplacesUnsafeCharacters(t *testing.T) {
	assert.Equal(t, "user_100.72.140.241_3000", tunnelID("user@100.72.140.241:3000"))
}

func TestTunnelID_ShortensLongNames(t *testing.T) {
	long := strings.Repeat("a", 100)
	assert.LessOrEqual(t, len(tunnelID(long)), maxIDLen)
}

func TestTunnelID_LongNamesStayDistinct(t *testing.T) {
	prefix := strings.Repeat("a", 100)
	assert.NotEqual(t, tunnelID(prefix+"1"), tunnelID(prefix+"2"))
}

func TestAdHocName(t *testing.T) {
	forwards := []types.Forward{{LocalPort: 3000, RemotePort: 3000}, {LocalPort: 5432, RemotePort: 5432}}
	assert.Equal(t, "user@box:3000,5432", AdHocName("user@box", forwards))
}

func TestSSHArgs(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	spec := types.TunnelSpec{
		Host: "user@box", Port: 2222, Identity: "~/.ssh/key",
		Forwards: []types.Forward{{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000}},
	}

	assert.Equal(t, []string{
		"-f", "-N", "-M", "-S", "/d/x.sock", "-E", "/d/x.log",
		"-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
		"-o", "ControlPersist=no", "-o", "ConnectTimeout=10",
		"-p", "2222", "-i", "~/.ssh/key",
		"-L", "127.0.0.1:13000:127.0.0.1:3000",
		"--", "user@box",
	}, m.startArgs(spec, "x"))
}

func TestSSHArgs_OmitsUnsetPortAndIdentity(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	args := m.startArgs(types.TunnelSpec{Host: "box", Forwards: []types.Forward{{LocalPort: 1, RemoteHost: "h", RemotePort: 1}}}, "x")
	assert.NotContains(t, args, "-p")
	assert.NotContains(t, args, "-i")
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want string
	}{
		{"host key", "No ED25519 host key is known for box\r\nHost key verification failed.\r\n", "host key for box is not trusted yet; run 'ssh box' once"},
		{"auth", "tester@box: Permission denied (publickey).\r\n", "box refused the login"},
		{"busy", "bind [127.0.0.1]:41351: Address already in use\r\nCould not request local forwarding.\r\n", "local port 41351 is already in use"},
		{"refused", "ssh: connect to host box port 22: Connection refused\r\n", "cannot reach box: ssh: connect to host box port 22: Connection refused"},
		{"dns", "ssh: Could not resolve hostname nope: Name or service not known\r\n", "cannot reach box: ssh: Could not resolve hostname nope"},
		{"other", "first\r\nsomething odd\r\n", "something odd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classify(tt.log, "box", errors.New("exit status 255"))
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestClassify_AuthIsErrAuthFailed(t *testing.T) {
	err := classify("Permission denied (publickey).", "box", errors.New("exit status 255"))
	assert.ErrorIs(t, err, ErrAuthFailed)
}

func TestClassify_EmptyLogUsesExecError(t *testing.T) {
	err := classify("", "box", errors.New("command timed out: ssh"))
	assert.Contains(t, err.Error(), "command timed out")
}

func portsFree(free ...int) func(int) bool {
	return func(p int) bool {
		for _, f := range free {
			if f == p {
				return true
			}
		}
		return false
	}
}

func TestAssignPorts_KeepsFreePort(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	m.portFree = portsFree(3000)
	got, err := m.assignPorts([]types.Forward{{LocalPort: 3000, RemotePort: 3000}})
	require.NoError(t, err)
	assert.Equal(t, 3000, got[0].LocalPort)
}

func TestAssignPorts_BusyPortMovesUpTenThousand(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	m.portFree = portsFree(13000)
	got, err := m.assignPorts([]types.Forward{{LocalPort: 3000, RemotePort: 3000}})
	require.NoError(t, err)
	assert.Equal(t, 13000, got[0].LocalPort)
}

func TestAssignPorts_FallsBackToAnyFreePort(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	m.portFree = portsFree()
	m.anyFreePort = func() (int, error) { return 45678, nil }
	got, err := m.assignPorts([]types.Forward{{LocalPort: 3000, RemotePort: 3000}})
	require.NoError(t, err)
	assert.Equal(t, 45678, got[0].LocalPort)
}

func TestAssignPorts_PinnedBusyPortFails(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	m.portFree = portsFree(23000)
	_, err := m.assignPorts([]types.Forward{{LocalPort: 13000, RemotePort: 3000, Pinned: true}})
	assert.ErrorContains(t, err, "local port 13000 is already in use")
}

func TestAssignPorts_NoDuplicateLocalPorts(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	m.portFree = portsFree(3000, 13000)
	got, err := m.assignPorts([]types.Forward{
		{LocalPort: 3000, RemotePort: 3000},
		{LocalPort: 3000, RemoteHost: "other", RemotePort: 3000},
	})
	require.NoError(t, err)
	assert.NotEqual(t, got[0].LocalPort, got[1].LocalPort)
}

func TestAssignPorts_DoesNotModifyInput(t *testing.T) {
	m := NewManager(nil, nopLogger{}, "/d")
	m.portFree = portsFree(13000)
	in := []types.Forward{{LocalPort: 3000, RemotePort: 3000}}
	_, err := m.assignPorts(in)
	require.NoError(t, err)
	assert.Equal(t, 3000, in[0].LocalPort)
}

func TestStart_RejectsSocketPathTooLongForSSH(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 60))
	m := NewManager(nil, nopLogger{}, dir)

	_, err := m.Start(types.TunnelSpec{Name: "app", Host: "box", Forwards: []types.Forward{{LocalPort: 1, RemoteHost: "h", RemotePort: 1}}})

	assert.ErrorContains(t, err, "too long")
}
