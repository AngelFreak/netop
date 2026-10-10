//go:build integration

package dhcpclient

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/angelfreak/net/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runRealDhclient gets a real lease with the system's dhclient and
// dhclient-script inside a throwaway namespace. `ip netns exec` bind-mounts
// /etc/netns/<ns>/{resolv.conf,dhcp} over /etc, so the namespace has its own
// resolv.conf and its own enter-hooks dir holding only net's hook; the
// host's files are never touched. Returns the namespace's resolv.conf and
// its IPv4 address output.
func runRealDhclient(t *testing.T, owned bool) (resolv, addr string) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	testutil.RequireCommands(t, "dhclient", "dnsmasq", "ip")

	ns := testutil.NewTestNamespace(t)
	require.NoError(t, ns.AddVethPair("ntdh0", "ntdc0"))
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "ntdh0").Run() })
	require.NoError(t, exec.Command("ip", "addr", "add", "10.213.0.1/24", "dev", "ntdh0").Run())
	require.NoError(t, exec.Command("ip", "link", "set", "ntdh0", "up").Run())
	require.NoError(t, ns.Exec("ip", "link", "set", "ntdc0", "up"))
	testutil.StartDHCPServer(t, testutil.DHCPServerConfig{
		Interface: "ntdh0", RangeStart: "10.213.0.10", RangeEnd: "10.213.0.50",
		Gateway: "10.213.0.1", DNS: "10.213.0.53",
	})

	etc := filepath.Join("/etc/netns", ns.Name)
	t.Cleanup(func() { _ = os.RemoveAll(etc) })
	hooks := filepath.Join(etc, "dhcp", "dhclient-enter-hooks.d")
	require.NoError(t, os.MkdirAll(hooks, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(etc, "dhcp", "dhclient.conf"), nil, 0644))
	resolvPath := filepath.Join(etc, "resolv.conf")
	require.NoError(t, os.WriteFile(resolvPath, []byte("nameserver 9.9.9.9\n"), 0644))

	tmp := t.TempDir()
	marker := filepath.Join(tmp, "dns-owned")
	if owned {
		require.NoError(t, os.WriteFile(marker, nil, 0644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(hooks, DhclientEnterHookName), []byte(DhclientEnterHook(marker)), 0644))

	pidFile := filepath.Join(tmp, "dhclient.pid")
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", ns.Name,
		"dhclient", "-1", "-v", "-pf", pidFile, "-lf", filepath.Join(tmp, "leases"), "ntdc0").CombinedOutput()
	require.NoError(t, err, "dhclient: %s", out)

	b, err := os.ReadFile(resolvPath)
	require.NoError(t, err)
	addr, err = ns.ExecOutput("ip", "-4", "addr", "show", "ntdc0")
	require.NoError(t, err)
	return string(b), addr
}

// The real dhclient-script must still apply the lease, and with the marker
// present must leave resolv.conf exactly as it was.
func TestDhclientEnterHook_RealDhclient_OwnedKeepsResolvConf_Integration(t *testing.T) {
	resolv, addr := runRealDhclient(t, true)
	assert.Contains(t, addr, "inet 10.213.0.", "the lease must still be applied")
	assert.Equal(t, "nameserver 9.9.9.9\n", resolv)
}

func TestDhclientEnterHook_RealDhclient_NotOwnedTakesLeaseDNS_Integration(t *testing.T) {
	resolv, addr := runRealDhclient(t, false)
	assert.Contains(t, addr, "inet 10.213.0.")
	assert.Contains(t, resolv, "nameserver 10.213.0.53")
}
