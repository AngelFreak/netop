package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/angelfreak/net/pkg/dhcpclient"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The DNS ownership marker is the contract between this manager and net's
// udhcpc script: what SetDNS records must decide whether an hourly lease
// renewal may rewrite resolv.conf. resolv.conf is left unlocked here, as it
// is while Tailscale accept_dns owns it, so only the marker stands between
// the renewal and the file.
func TestDNSOwnership_DecidesWhetherUdhcpcRenewalWritesResolvConf(t *testing.T) {
	tmp := t.TempDir()
	resolv := filepath.Join(tmp, "resolv.conf")
	manager := &Manager{
		routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(),
		executor: newMockExecutor(), logger: &mockLogger{},
		dnsOwnershipPath: filepath.Join(tmp, "dns-owned"),
		resolvConfPath:   resolv,
		setImmutable:     func(string, bool) error { return nil },
	}

	bin := filepath.Join(tmp, "bin")
	require.NoError(t, os.Mkdir(bin, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "busybox"), []byte("#!/bin/sh\n[ \"$1\" = awk ] && { shift; exec awk \"$@\"; }\nexit 0\n"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "logger"), []byte("#!/bin/sh\nexit 0\n"), 0755))
	script := filepath.Join(tmp, "udhcpc.script")
	require.NoError(t, os.WriteFile(script, []byte(dhcpclient.UdhcpcScript(resolv, manager.dnsOwnedPath())), 0700))

	renew := func() string {
		t.Helper()
		cmd := exec.Command(script, "renew") // direct exec, as udhcpc does
		cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "interface=wlan0", "ip=192.168.0.105", "subnet=255.255.255.0", "dns=217.26.160.4"}
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "script failed: %s", out)
		got, err := os.ReadFile(resolv)
		require.NoError(t, err)
		return string(got)
	}

	require.NoError(t, manager.SetDNS([]string{"1.1.1.1"}))
	assert.Equal(t, "nameserver 1.1.1.1\n", renew(), "configured DNS must survive a renewal")

	require.NoError(t, manager.SetDNS([]string{"dhcp"}))
	assert.Equal(t, "\nnameserver 217.26.160.4\n", renew(), "dns: dhcp must still take the lease's servers")
}

// Production wiring: both sides default to the same marker path.
func TestDNSOwnership_DefaultMarkerIsSharedWithUdhcpcScript(t *testing.T) {
	m := NewManager(newMockExecutor(), &mockLogger{}, nil)
	assert.Equal(t, types.DNSOwnedPath, m.dnsOwnedPath())
}
