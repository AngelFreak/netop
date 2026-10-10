package dhcpclient

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourceHook does what dhclient-script does: define the stock
// make_resolv_conf, source the enter hooks, then call make_resolv_conf on
// BOUND/RENEW. It reports whether the stock function still ran.
func sourceHook(t *testing.T, hook string) bool {
	t.Helper()
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "hook")
	out := filepath.Join(dir, "wrote")
	require.NoError(t, os.WriteFile(hookPath, []byte(hook), 0644))
	script := `make_resolv_conf() { echo wrote > "$OUT"; }
. "$HOOK"
make_resolv_conf
`
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = []string{"OUT=" + out, "HOOK=" + hookPath, "PATH=" + os.Getenv("PATH")}
	b, err := cmd.CombinedOutput()
	require.NoError(t, err, "sourcing hook failed: %s", b)
	_, err = os.Stat(out)
	return err == nil
}

// While net owns DNS, a dhclient renewal must not rewrite resolv.conf: the
// immutable lock used to hide that write, and Tailscale accept_dns lifts it.
func TestDhclientEnterHook_DisablesResolvConfWhileNetOwnsDNS(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "dns-owned")
	require.NoError(t, os.WriteFile(marker, nil, 0644))
	assert.False(t, sourceHook(t, DhclientEnterHook(marker)), "make_resolv_conf must be a no-op while the marker exists")
}

func TestDhclientEnterHook_InertWhenNetDoesNotOwnDNS(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "dns-owned")
	assert.True(t, sourceHook(t, DhclientEnterHook(marker)), "dns: dhcp must still get the lease's servers")
}

// dhclient-script lists hooks with run-parts, which skips names outside
// [A-Za-z0-9_-] (e.g. anything with a dot).
func TestDhclientEnterHookName_IsRunPartsValid(t *testing.T) {
	assert.Regexp(t, regexp.MustCompile(`^[A-Za-z0-9_-]+$`), DhclientEnterHookName)
}

// newHookTestManager returns a manager for the dhclient path whose runtime
// files and hook dir live in temp dirs. The hook dir is 0755 like
// /etc/dhcp/dhclient-enter-hooks.d (t.TempDir is group-writable).
func newHookTestManager(t *testing.T) (*Manager, *mockExecutor) {
	t.Helper()
	executor := newMockExecutor()
	executor.hasCommands["dhclient"] = true
	executor.commands["ip addr show eth0"] = "inet 192.168.1.50/24"
	manager := NewManager(executor, &mockLogger{})
	manager.runtimeDir = t.TempDir()
	manager.hooksDir = t.TempDir()
	require.NoError(t, os.Chmod(manager.hooksDir, 0755))
	return manager, executor
}

// Acquire is the production entry point: it must install the hook, checking
// the marker the network manager maintains, and still run dhclient.
func TestAcquire_DhclientInstallsEnterHook(t *testing.T) {
	manager, executor := newHookTestManager(t)

	require.NoError(t, manager.Acquire("eth0", ""))

	hook := filepath.Join(manager.hooksDir, DhclientEnterHookName)
	content, err := os.ReadFile(hook)
	require.NoError(t, err)
	assert.Equal(t, DhclientEnterHook(types.DNSOwnedPath), string(content))
	info, err := os.Stat(hook)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "sourced, not executed: no exec bit needed")
	assert.True(t, slices.ContainsFunc(executor.executedCmds, func(c string) bool { return strings.Contains(c, "dhclient -v -1 eth0") }))
}

// Without a Debian-style hooks dir (other dhclient-scripts), nothing is
// created and dhclient runs as before.
func TestAcquire_DhclientWithoutHooksDirStillRuns(t *testing.T) {
	manager, executor := newHookTestManager(t)
	manager.hooksDir = filepath.Join(manager.hooksDir, "missing")

	require.NoError(t, manager.Acquire("eth0", ""))

	_, err := os.Stat(manager.hooksDir)
	assert.True(t, os.IsNotExist(err), "net must not create the hooks dir")
	executor.assertCommandExecuted(t, "dhclient -v -1 eth0")
}

// dhclient-script sources hooks as root; a dir others can write to is refused.
func TestAcquire_DhclientRefusesSharedHooksDir(t *testing.T) {
	manager, executor := newHookTestManager(t)
	require.NoError(t, os.Chmod(manager.hooksDir, 0777))

	require.NoError(t, manager.Acquire("eth0", ""))

	_, err := os.Stat(filepath.Join(manager.hooksDir, DhclientEnterHookName))
	assert.True(t, os.IsNotExist(err))
	executor.assertCommandExecuted(t, "dhclient -v -1 eth0")
}
