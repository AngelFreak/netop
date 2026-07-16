package network

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// newFakeRoutes returns a fake RouteManager preloaded with a typical physical
// default route (192.168.1.1 via eth0). Route operations (SetIP gateway,
// AddRoute, FlushRoutes, applyDefaultRouteMetric, GetConnectionInfo) go through
// the RouteManager (netlink) rather than the executor, so tests inject this to
// keep those paths deterministic and off the real kernel.
func newFakeRoutes() *fake.RouteManager {
	return &fake.RouteManager{
		Routes: []types.Route{{Gw: "192.168.1.1", Iface: "eth0"}},
	}
}

// newFakeAddrs returns a fake AddrManager. Address operations (flush/add,
// GetConnectionInfo IP read) go through the AddrManager (netlink) rather than
// the executor, so tests inject this to keep those paths deterministic and off
// the real kernel.
func newFakeAddrs() *fake.AddrManager {
	return &fake.AddrManager{}
}

// newFakeLinks returns a fake LinkManager. Link operations (SetUp/SetDown,
// SetMAC/GetMAC) go through the LinkManager (netlink) rather than the executor,
// so tests inject this to keep those paths deterministic and off the real
// kernel.
func newFakeLinks() *fake.LinkManager {
	return &fake.LinkManager{}
}

func TestMain(m *testing.M) {
	// Disable the wired-settle delay during tests — it's a real-world
	// hardware workaround that adds 1.5s per wired connect path and would
	// inflate test runtime.
	wiredSettleDelay = 0
	os.Exit(m.Run())
}

// Mock implementations with strict mode - fails on unexpected commands
type mockSystemExecutor struct {
	commands       map[string]string
	errors         map[string]error
	strict         bool              // If true, fail on unexpected commands
	executedCmds   []string          // Track executed commands for verification
	inputsReceived map[string]string // Track inputs received by ExecuteWithInput
	hasCommands    map[string]bool   // which commands are "installed"
	failOnPattern  string            // If set, fail any command containing this substring
}

func newStrictMockExecutor() *mockSystemExecutor {
	return &mockSystemExecutor{
		commands:       make(map[string]string),
		errors:         make(map[string]error),
		strict:         true,
		executedCmds:   []string{},
		inputsReceived: make(map[string]string),
	}
}

// newMockExecutor creates a non-strict mock with properly initialized maps
func newMockExecutor() *mockSystemExecutor {
	return &mockSystemExecutor{
		commands:       make(map[string]string),
		errors:         make(map[string]error),
		strict:         false,
		executedCmds:   []string{},
		inputsReceived: make(map[string]string),
	}
}

func (m *mockSystemExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}
	m.executedCmds = append(m.executedCmds, fullCmd)

	// Check failOnPattern
	if m.failOnPattern != "" && strings.Contains(fullCmd, m.failOnPattern) {
		return "", fmt.Errorf("mock error: %s", m.failOnPattern)
	}

	// Check errors first
	if m.errors != nil {
		if err, hasErr := m.errors[fullCmd]; hasErr {
			if output, ok := m.commands[fullCmd]; ok {
				return output, err
			}
			return "", err
		}
	}
	if output, ok := m.commands[fullCmd]; ok {
		return output, nil
	}
	// In strict mode, fail on unexpected commands
	if m.strict {
		return "", fmt.Errorf("unexpected command: %s", fullCmd)
	}
	return "mock output", nil
}

func (m *mockSystemExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}
	m.executedCmds = append(m.executedCmds, fullCmd)
	if m.inputsReceived != nil {
		m.inputsReceived[fullCmd] = input
	}

	// Check failOnPattern
	if m.failOnPattern != "" && strings.Contains(fullCmd, m.failOnPattern) {
		return "", fmt.Errorf("mock error: %s", m.failOnPattern)
	}

	// Check errors first
	if m.errors != nil {
		if err, hasErr := m.errors[fullCmd]; hasErr {
			return "", err
		}
	}
	if output, ok := m.commands[fullCmd]; ok {
		return output, nil
	}
	if m.strict {
		return "", fmt.Errorf("unexpected command with input: %s", fullCmd)
	}
	return "mock output with input", nil
}

func (m *mockSystemExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return m.ExecuteWithInput(cmd, input, args...)
}

func (m *mockSystemExecutor) HasCommand(cmd string) bool {
	if m.hasCommands == nil {
		return false // default: no commands installed (use dhclient fallback)
	}
	return m.hasCommands[cmd]
}

// assertCommandExecuted verifies a command was executed
func (m *mockSystemExecutor) assertCommandExecuted(t *testing.T, cmd string) {
	t.Helper()
	for _, executed := range m.executedCmds {
		if executed == cmd {
			return
		}
	}
	t.Errorf("expected command %q to be executed, but it wasn't. Executed: %v", cmd, m.executedCmds)
}

// assertCommandContains verifies at least one executed command contains the substring
func (m *mockSystemExecutor) assertCommandContains(t *testing.T, substr string) {
	t.Helper()
	for _, executed := range m.executedCmds {
		if strings.Contains(executed, substr) {
			return
		}
	}
	t.Errorf("expected a command containing %q, but none found. Executed: %v", substr, m.executedCmds)
}

// assertInputContains verifies the input to a command contains expected content
func (m *mockSystemExecutor) assertInputContains(t *testing.T, cmd, expected string) {
	t.Helper()
	input, ok := m.inputsReceived[cmd]
	if !ok {
		t.Errorf("no input recorded for command %q", cmd)
		return
	}
	if !strings.Contains(input, expected) {
		t.Errorf("expected input to contain %q, got %q", expected, input)
	}
}

// assertCommandNotExecuted verifies a command was NOT executed
func (m *mockSystemExecutor) assertCommandNotExecuted(t *testing.T, cmd string) {
	t.Helper()
	for _, executed := range m.executedCmds {
		if executed == cmd {
			t.Errorf("expected command %q to NOT be executed, but it was", cmd)
			return
		}
	}
}

type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}

// mockDHCPClient implements types.DHCPClientManager for testing
type mockDHCPClient struct {
	acquireErr error
	releaseErr error
	renewErr   error
}

func (m *mockDHCPClient) Acquire(iface string, hostname string) error {
	return m.acquireErr
}

func (m *mockDHCPClient) Release(iface string) error {
	return m.releaseErr
}

func (m *mockDHCPClient) Renew(iface string, hostname string) error {
	return m.renewErr
}

func TestNewManager(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	dhcpClient := &mockDHCPClient{}
	manager := NewManager(executor, logger, dhcpClient)
	manager.routeMgr = newFakeRoutes()
	manager.addrMgr = newFakeAddrs()
	manager.linkMgr = newFakeLinks()
	assert.NotNil(t, manager)
	assert.Equal(t, executor, manager.executor)
	assert.Equal(t, logger, manager.logger)
	assert.Equal(t, dhcpClient, manager.dhcpClient)
}

func TestSetDNS(t *testing.T) {
	t.Run("empty servers unlocks resolv.conf for DHCP", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// Should unlock resolv.conf so DHCP can write DNS servers
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetDNS([]string{})
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
	})

	t.Run("dhcp keyword unlocks resolv.conf for DHCP", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// Should unlock resolv.conf so DHCP can write DNS servers
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetDNS([]string{"dhcp"})
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
	})

	t.Run("valid servers writes resolv.conf with correct content", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["tee /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetDNS([]string{"8.8.8.8", "1.1.1.1"})
		assert.NoError(t, err)

		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
		executor.assertCommandExecuted(t, "tee /etc/resolv.conf")
		executor.assertCommandExecuted(t, "chattr +i /etc/resolv.conf")
		executor.assertInputContains(t, "tee /etc/resolv.conf", "nameserver 8.8.8.8")
		executor.assertInputContains(t, "tee /etc/resolv.conf", "nameserver 1.1.1.1")
	})

	t.Run("invalid IP addresses are filtered out", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["tee /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetDNS([]string{"invalid", "8.8.8.8", "not-an-ip"})
		assert.NoError(t, err)

		// Only valid IP should be in output
		input := executor.inputsReceived["tee /etc/resolv.conf"]
		assert.Contains(t, input, "nameserver 8.8.8.8")
		assert.NotContains(t, input, "invalid")
		assert.NotContains(t, input, "not-an-ip")
	})

	t.Run("all invalid IPs returns error", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetDNS([]string{"invalid", "not-an-ip"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid DNS servers")
	})

	t.Run("tee failure returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.errors["tee /etc/resolv.conf"] = fmt.Errorf("permission denied")
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetDNS([]string{"8.8.8.8"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write resolv.conf")
	})

	t.Run("does not lock resolv.conf when DNS is DHCP", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := NewManager(executor, logger, &mockDHCPClient{})
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		err := manager.SetDNS([]string{"dhcp"})
		assert.NoError(t, err)

		// Should unlock but NOT re-lock — DHCP needs to write resolv.conf,
		// and external VPN tools (NetBird, Tailscale) also need to modify it
		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
		executor.assertCommandNotExecuted(t, "chattr +i /etc/resolv.conf")
	})

	t.Run("only locks resolv.conf when custom DNS is set", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := NewManager(executor, logger, &mockDHCPClient{})
		manager.routeMgr = newFakeRoutes()
		manager.addrMgr = newFakeAddrs()
		manager.linkMgr = newFakeLinks()

		err := manager.SetDNS([]string{"8.8.8.8"})
		assert.NoError(t, err)

		// Should lock when custom DNS is set — prevents DHCP from overwriting
		executor.assertCommandExecuted(t, "chattr +i /etc/resolv.conf")
	})
}

// After DHCP DNS is written, LockDNS must record ownership so that a later
// ClearDNS/`net stop` can unlock resolv.conf again — a raw `chattr +i` here
// (the old bug) left the file immutable forever.
func TestLockDNS_RecordsOwnership(t *testing.T) {
	tmp := t.TempDir()
	executor := newMockExecutor()
	executor.commands["chattr +i /etc/resolv.conf"] = ""
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, dnsOwnershipPath: tmp + "/dns-owned"}

	assert.False(t, manager.isDNSOwned())
	manager.LockDNS()
	assert.True(t, manager.isDNSOwned(), "LockDNS must mark ownership so ClearDNS can later unlock")

	// A subsequent clear must actually unlock and drop ownership.
	executor.commands["chattr -i /etc/resolv.conf"] = ""
	executor.commands["tee /etc/resolv.conf"] = ""
	cleared, err := manager.ClearDNSIfOwned()
	assert.NoError(t, err)
	assert.True(t, cleared)
	executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
	assert.False(t, manager.isDNSOwned())
}

// resolvConfHasNameserver gates whether we lock after DHCP: a static-addr
// network with dns: dhcp never runs a DHCP client, so resolv.conf holds only
// the placeholder and must not be locked (which would strand the system).
func TestResolvConfHasNameserver(t *testing.T) {
	t.Run("placeholder only - false", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["cat /etc/resolv.conf"] = "# Waiting for DHCP\n"
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}}
		assert.False(t, manager.resolvConfHasNameserver())
	})
	t.Run("has nameserver - true", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["cat /etc/resolv.conf"] = "# comment\nnameserver 192.168.1.1\n"
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}}
		assert.True(t, manager.resolvConfHasNameserver())
	})
}

// RunDNS "dhcp" restore path: DHCPRenew must unlock resolv.conf and release
// ownership first, or the renewed lease's DNS can't be written to an immutable
// file.
func TestDHCPRenew_UnlocksResolvConf(t *testing.T) {
	tmp := t.TempDir()
	executor := newMockExecutor()
	executor.commands["chattr -i /etc/resolv.conf"] = ""
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, dhcpClient: &mockDHCPClient{}, dnsOwnershipPath: tmp + "/dns-owned"}
	manager.markDNSOwned()

	err := manager.DHCPRenew("eth0", "")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
	assert.False(t, manager.isDNSOwned(), "ownership must be released so DHCP DNS takes effect")
}

func TestSetMAC(t *testing.T) {
	t.Run("specific mac - full sequence", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.NoError(t, err)

		// Verify correct sequence via the link manager: down -> set MAC -> up.
		assert.Equal(t, []string{"wlan0"}, links.Downed)
		assert.Equal(t, []fake.MACCall{{Iface: "wlan0", MAC: "aa:bb:cc:dd:ee:ff"}}, links.SetMACCalls)
		assert.Equal(t, []string{"wlan0"}, links.Upped)
	})

	t.Run("random mac - generates valid mac", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "random")
		assert.NoError(t, err)

		// Verify down/up were called and the generated MAC has a valid format.
		assert.Contains(t, links.Downed, "wlan0")
		assert.Contains(t, links.Upped, "wlan0")
		assert.Len(t, links.SetMACCalls, 1)
		assert.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, links.SetMACCalls[0].MAC)
	})

	t.Run("template mac - expands wildcards", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "00:11:??:??:??:??")
		assert.NoError(t, err)

		// Verify the template was expanded before being set on the link.
		assert.Len(t, links.SetMACCalls, 1)
		mac := links.SetMACCalls[0].MAC
		assert.True(t, strings.HasPrefix(mac, "00:11:"))
		assert.NotContains(t, mac, "??", "template wildcards should be expanded")
	})

	t.Run("permanent mac - uses ethtool to get factory MAC", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// ethtool -P returns the permanent/factory MAC address
		executor.commands["ethtool -P wlan0"] = "Permanent address: 00:11:22:33:44:55"
		logger := &mockLogger{}
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "permanent")
		assert.NoError(t, err)

		// Verify ethtool was called and the permanent MAC was used.
		executor.assertCommandExecuted(t, "ethtool -P wlan0")
		assert.Contains(t, links.SetMACCalls, fake.MACCall{Iface: "wlan0", MAC: "00:11:22:33:44:55"})
	})

	t.Run("permanent mac - fails when ethtool unavailable", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["ethtool -P wlan0"] = assert.AnError
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "permanent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get permanent MAC")
	})

	t.Run("permanent mac - fails on invalid ethtool output", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ethtool -P wlan0"] = "Invalid output"
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "permanent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse permanent MAC")
	})
}

func TestGetMAC(t *testing.T) {
	t.Run("success - returns MAC from link manager", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		links := &fake.LinkManager{MACs: map[string]string{"wlan0": "aa:bb:cc:dd:ee:ff"}}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		mac, err := manager.GetMAC("wlan0")
		assert.NoError(t, err)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", mac)
	})

	t.Run("interface down - still has MAC", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		links := &fake.LinkManager{MACs: map[string]string{"eth0": "11:22:33:44:55:66"}}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		mac, err := manager.GetMAC("eth0")
		assert.NoError(t, err)
		assert.Equal(t, "11:22:33:44:55:66", mac)
	})

	t.Run("no MAC available - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		// Link manager reports no MAC for the interface.
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MAC address not found")
	})

	t.Run("link manager error - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		links := &fake.LinkManager{GetMACErr: assert.AnError}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
	})
}

func TestSetIP(t *testing.T) {
	t.Run("full config with addr and gateway", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		routes := newFakeRoutes()
		addrs := newFakeAddrs()
		manager := &Manager{routeMgr: routes, addrMgr: addrs, linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetIP("wlan0", "192.168.1.100/24", "192.168.1.1", 0)
		assert.NoError(t, err)

		// Address ops go through the AddrManager: flush, then add.
		assert.Equal(t, []string{"wlan0"}, addrs.Flushed)
		assert.Len(t, addrs.Added, 1)
		assert.Equal(t, fake.AddrCall{Iface: "wlan0", CIDR: "192.168.1.100/24"}, addrs.Added[0])

		// The default route goes through the RouteManager (per-interface replace).
		assert.Len(t, routes.SetForIface, 1)
		assert.Equal(t, fake.ReplaceCall{Iface: "wlan0", Gw: "192.168.1.1", Metric: 0}, routes.SetForIface[0])
	})
}

func TestAddRoute(t *testing.T) {
	t.Run("success - adds route via gateway", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		routes := newFakeRoutes()
		manager := &Manager{routeMgr: routes, addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.AddRoute("wlan0", "10.0.0.0/24", "192.168.1.1")
		assert.NoError(t, err)
		assert.Len(t, routes.Added, 1)
		assert.Equal(t, fake.AddCall{Iface: "wlan0", Destination: "10.0.0.0/24", Gw: "192.168.1.1"}, routes.Added[0])
	})
}

func TestFlushRoutes(t *testing.T) {
	t.Run("success - flushes all routes on interface", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		routes := newFakeRoutes()
		manager := &Manager{routeMgr: routes, addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.FlushRoutes("wlan0")
		assert.NoError(t, err)
		assert.Equal(t, []string{"wlan0"}, routes.Flushed)
	})
}

func TestStartDHCP(t *testing.T) {
	t.Run("success - delegates to DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), dhcpClient: dhcpClient}

		err := manager.StartDHCP("wlan0", "test-hostname")
		assert.NoError(t, err)
	})

	t.Run("failure - propagates error from DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{acquireErr: fmt.Errorf("dhcp failed")}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), dhcpClient: dhcpClient}

		err := manager.StartDHCP("wlan0", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dhcp failed")
	})
}

func TestDHCPRenew(t *testing.T) {
	t.Run("success - delegates to DHCPClientManager", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}, dhcpClient: dhcpClient}

		err := manager.DHCPRenew("wlan0", "test-hostname")
		assert.NoError(t, err)
	})

	t.Run("failure - propagates error from DHCPClientManager", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		dhcpClient := &mockDHCPClient{renewErr: fmt.Errorf("renew failed")}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}, dhcpClient: dhcpClient}

		err := manager.DHCPRenew("wlan0", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "renew failed")
	})
}

func TestFindWirelessInterface(t *testing.T) {
	t.Run("found - parses iw dev output", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// Realistic iw dev output
		executor.commands["iw dev"] = `phy#0
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 00:11:22:33:44:55
		type managed
		channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz`
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		result, err := manager.findWirelessInterface()
		assert.NoError(t, err)
		assert.Equal(t, "wlan0", result)
	})

	t.Run("no wireless interfaces - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["iw dev"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		_, err := manager.findWirelessInterface()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no wireless interface found")
	})

	t.Run("iw dev fails - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["iw dev"] = fmt.Errorf("iw: command not found")
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		_, err := manager.findWirelessInterface()
		assert.Error(t, err)
	})
}

func TestGenerateRandomMAC(t *testing.T) {
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks()}
	mac := manager.generateRandomMAC()
	assert.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, mac)
}

func TestGenerateMacBookProMAC(t *testing.T) {
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks()}
	mac := manager.generateMacBookProMAC()
	assert.Regexp(t, `^ac:bc:32:[0-9a-f]{2}(:[0-9a-f]{2}){2}$`, mac)
}

func TestExpandMACTemplate(t *testing.T) {
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks()}
	result := manager.expandMACTemplate("00:??:??:??:??:??")
	assert.Regexp(t, `^00:[0-9a-f]{2}(:[0-9a-f]{2}){4}$`, result)
}

func TestWriteFile(t *testing.T) {
	// The staging path includes the PID for uniqueness, so use non-strict mock
	t.Run("success - writes temp and moves to target", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.writeFile("/etc/test.conf", "test content")
		assert.NoError(t, err)

		// Verify tee was called with staging path containing PID
		executor.assertCommandContains(t, "tee /run/net/staging.")
		// Verify mv was called to the target path
		executor.assertCommandContains(t, "mv /run/net/staging.")
		executor.assertCommandContains(t, "/etc/test.conf")
	})

	t.Run("tee fails - returns error", func(t *testing.T) {
		executor := newMockExecutor()
		executor.failOnPattern = "tee"
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.writeFile("/etc/test.conf", "test content")
		assert.Error(t, err)
	})
}

func TestWriteFileDirect(t *testing.T) {
	t.Run("success - writes via tee", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["tee /tmp/test"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.writeFileDirect("/tmp/test", "content")
		assert.NoError(t, err)

		// Verify the content was passed correctly
		executor.assertCommandExecuted(t, "tee /tmp/test")
		executor.assertInputContains(t, "tee /tmp/test", "content")
	})

	t.Run("tee fails - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["tee /tmp/test"] = fmt.Errorf("no space left")
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.writeFileDirect("/tmp/test", "content")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no space left")
	})

	t.Run("multiline content preserved", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["tee /tmp/multiline"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		content := "line1\nline2\nline3"
		err := manager.writeFileDirect("/tmp/multiline", content)
		assert.NoError(t, err)

		// Verify all lines are in the input
		input := executor.inputsReceived["tee /tmp/multiline"]
		assert.Equal(t, content, input)
	})
}

func TestSetHostname(t *testing.T) {
	t.Run("success - hostname command executed", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["hostname test-host"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetHostname("test-host")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "hostname test-host")
	})

	t.Run("empty hostname - no command executed", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// No commands expected for empty hostname
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetHostname("")
		assert.NoError(t, err)
		assert.Empty(t, executor.executedCmds, "no commands should be executed for empty hostname")
	})

	t.Run("hostname command fails - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["hostname fail-host"] = fmt.Errorf("hostname: you must be root to change the host name")
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetHostname("fail-host")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "you must be root")
	})
}

func TestDetectInterface(t *testing.T) {
	t.Run("configured interface", func(t *testing.T) {
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), logger: &mockLogger{}}
		config := &types.NetworkConfig{Interface: "eth0"}
		result := manager.detectInterface(config)
		assert.Equal(t, "eth0", result)
	})

	t.Run("wireless auto-detect", func(t *testing.T) {
		executor := newMockExecutor()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}}
		config := &types.NetworkConfig{SSID: "test-network"}
		// This will try to detect from actual system interfaces
		result := manager.detectInterface(config)
		// Result could be empty or a detected interface
		assert.True(t, result == "" || len(result) > 0)
	})

	t.Run("wired auto-detect", func(t *testing.T) {
		executor := newMockExecutor()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}}
		config := &types.NetworkConfig{}
		// This will try to detect from actual system interfaces
		result := manager.detectInterface(config)
		// Result could be empty or a detected interface
		assert.True(t, result == "" || len(result) > 0)
	})
}

func TestConnectToConfiguredNetwork(t *testing.T) {
	t.Run("wireless with SSID", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["hostname test-host"] = ""
		logger := &mockLogger{}
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "wlan0",
			SSID:      "test-network",
			PSK:       "password123",
			MAC:       "aa:bb:cc:dd:ee:ff",
			Hostname:  "test-host",
		}

		// Create a minimal WiFi manager mock
		wifiManager := &mockWiFiManagerImpl{
			executor: executor,
			logger:   logger,
		}

		err := manager.ConnectToConfiguredNetwork(config, "", wifiManager)
		assert.NoError(t, err)
		// Verify MAC was set before connection (critical ordering)
		assert.Contains(t, links.SetMACCalls, fake.MACCall{Iface: "wlan0", MAC: "aa:bb:cc:dd:ee:ff"})
	})

	t.Run("wireless with BSSID pinning", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "wlan0",
			SSID:      "test-network",
			PSK:       "password123",
			ApAddr:    "00:11:22:33:44:55",
		}

		wifiManager := &mockWiFiManagerImpl{
			executor: executor,
			logger:   logger,
		}

		err := manager.ConnectToConfiguredNetwork(config, "", wifiManager)
		assert.NoError(t, err)
	})

	t.Run("wired connection with DHCP", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{}
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger, dhcpClient: dhcpClient}

		config := &types.NetworkConfig{
			Interface: "eth0",
			// No SSID means wired, no Addr means DHCP
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		// Verify interface was brought up
		assert.Contains(t, links.Upped, "eth0")
		// DHCP is now handled by the mock DHCPClientManager
	})

	t.Run("wired connection flushes stale state before DHCP", func(t *testing.T) {
		// After suspend/resume, stale IPs and routes remain on the interface.
		// Verify that wired connect flushes them before bringing the interface up.
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{}
		routes := newFakeRoutes()
		addrs := newFakeAddrs()
		manager := &Manager{routeMgr: routes, addrMgr: addrs, linkMgr: newFakeLinks(), executor: executor, logger: logger, dhcpClient: dhcpClient}

		config := &types.NetworkConfig{
			Interface: "eth0",
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)

		// Stale state is flushed before the interface is brought up: address
		// flush via the AddrManager, route flush via the RouteManager.
		assert.Contains(t, addrs.Flushed, "eth0", "addresses should be flushed on eth0")
		assert.Contains(t, routes.Flushed, "eth0", "routes should be flushed on eth0")
	})

	t.Run("static IP configuration", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		routes := newFakeRoutes()
		addrs := newFakeAddrs()
		manager := &Manager{routeMgr: routes, addrMgr: addrs, linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		// Static address added via the AddrManager.
		assert.Contains(t, addrs.Added, fake.AddrCall{Iface: "eth0", CIDR: "192.168.1.100/24"})
		// Default route installed per-interface via the RouteManager, with metric.
		assert.Contains(t, routes.SetForIface, fake.ReplaceCall{Iface: "eth0", Gw: "192.168.1.1", Metric: 100})
	})

	t.Run("with custom routes", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		logger := &mockLogger{}
		routes := newFakeRoutes()
		manager := &Manager{routeMgr: routes, addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
			Routes:    []string{"default", "10.0.0.0/24 -> 192.168.1.254"},
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		// Custom route added via the RouteManager.
		assert.Contains(t, routes.Added, fake.AddCall{Iface: "eth0", Destination: "10.0.0.0/24", Gw: "192.168.1.254"})
	})

	t.Run("with custom DNS", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
			DNS:       []string{"8.8.8.8", "1.1.1.1"},
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
	})

	t.Run("static addr with dns dhcp - does NOT lock the placeholder resolv.conf", func(t *testing.T) {
		// A static-addr network skips the DHCP client (Addr != ""), so with
		// dns: dhcp resolv.conf keeps only the "# Waiting for DHCP" placeholder.
		// Locking that would strand the system with no nameservers and an
		// immutable file, so the post-DHCP lock must be skipped here.
		tmp := t.TempDir()
		executor := newMockExecutor()
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		executor.commands["tee /etc/resolv.conf"] = ""
		// resolv.conf still holds only the placeholder (no DHCP client ran).
		executor.commands["cat /etc/resolv.conf"] = "# Waiting for DHCP\n"
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, dnsOwnershipPath: tmp + "/dns-owned"}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
			DNS:       []string{"dhcp"},
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)

		unlockCalled := false
		clearCalled := false
		lockCalled := false
		for _, cmd := range executor.executedCmds {
			if strings.Contains(cmd, "chattr -i") && strings.Contains(cmd, "resolv.conf") {
				unlockCalled = true
			}
			if strings.Contains(cmd, "tee") && strings.Contains(cmd, "resolv.conf") {
				clearCalled = true
			}
			if strings.Contains(cmd, "chattr +i") && strings.Contains(cmd, "resolv.conf") {
				lockCalled = true
			}
		}
		assert.True(t, unlockCalled, "should unlock resolv.conf for DHCP DNS")
		assert.True(t, clearCalled, "should clear resolv.conf before DHCP runs")
		assert.False(t, lockCalled, "must NOT lock the placeholder-only resolv.conf")
		assert.False(t, manager.isDNSOwned(), "must not claim DNS ownership when nothing was written")
		assert.Contains(t, executor.inputsReceived["tee /etc/resolv.conf"], "Waiting for DHCP")
	})

	t.Run("DHCP DNS locks resolv.conf after connection to prevent netbird overwrite", func(t *testing.T) {
		// When using DHCP for DNS and netbird is still connected, netbird
		// will overwrite resolv.conf with its own DNS after DHCP writes it.
		// The fix: lock resolv.conf with chattr +i AFTER DHCP completes.
		tmp := t.TempDir()
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		executor.commands["tee /etc/resolv.conf"] = ""
		// DHCP wrote a real nameserver, so the post-DHCP lock must fire.
		executor.commands["cat /etc/resolv.conf"] = "nameserver 192.168.1.1\n"
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, dnsOwnershipPath: tmp + "/dns-owned"}

		// No DNS configured = DHCP handles DNS
		config := &types.NetworkConfig{
			Interface: "wlan0",
			SSID:      "coffee-shop",
			PSK:       "password",
		}

		wifiManager := &mockWiFiManagerImpl{
			executor: executor,
			logger:   logger,
		}

		err := manager.ConnectToConfiguredNetwork(config, "", wifiManager)
		assert.NoError(t, err)

		// Verify the sequence: unlock -> clear -> (DHCP via wifi connect) -> lock
		unlockIdx := -1
		clearIdx := -1
		lockIdx := -1
		for i, cmd := range executor.executedCmds {
			if strings.Contains(cmd, "chattr -i") && strings.Contains(cmd, "resolv.conf") {
				if unlockIdx == -1 {
					unlockIdx = i
				}
			}
			if strings.Contains(cmd, "tee") && strings.Contains(cmd, "resolv.conf") {
				if clearIdx == -1 {
					clearIdx = i
				}
			}
			if strings.Contains(cmd, "chattr +i") && strings.Contains(cmd, "resolv.conf") {
				lockIdx = i // last lock is the one after connection
			}
		}

		assert.True(t, unlockIdx >= 0, "should unlock resolv.conf before DHCP")
		assert.True(t, clearIdx >= 0, "should clear resolv.conf before DHCP")
		assert.True(t, lockIdx >= 0, "should lock resolv.conf after DHCP to prevent netbird overwrite")
		assert.True(t, unlockIdx < clearIdx, "unlock should come before clear")
		assert.True(t, clearIdx < lockIdx, "lock should come after clear (i.e., after DHCP)")
		// The post-DHCP lock must record ownership so `net stop` can unlock it.
		assert.True(t, manager.isDNSOwned(), "DHCP-DNS lock must mark ownership")
	})

	t.Run("auto-detect interface falls back when detection finds nothing", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger, dhcpClient: dhcpClient}

		// Test wired connection with no interface - system may or may not have eth* interfaces
		config := &types.NetworkConfig{
			// No interface specified, no SSID = wired
			// Auto-detect may succeed or fail depending on system
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		// If no wired interface is detected, should error
		// If one is found, it will try DHCP which may fail
		// Either way, this tests the flow doesn't panic with nil config.Interface
		if err != nil {
			// Either interface detection failed OR dhcp failed
			assert.True(t, strings.Contains(err.Error(), "no suitable interface") ||
				strings.Contains(err.Error(), "dhclient"))
		}
	})
}

// Mock WiFi manager implementation for testing
type mockWiFiManagerImpl struct {
	executor types.SystemExecutor
	logger   types.Logger
}

func (m *mockWiFiManagerImpl) Scan() ([]types.WiFiNetwork, error) {
	return nil, nil
}

func (m *mockWiFiManagerImpl) Connect(ssid, password, hostname string) error {
	return nil
}

func (m *mockWiFiManagerImpl) ConnectWithBSSID(ssid, password, bssid, hostname string) error {
	return nil
}

func (m *mockWiFiManagerImpl) Disconnect() error {
	return nil
}

func (m *mockWiFiManagerImpl) ListConnections() ([]types.Connection, error) {
	return nil, nil
}

func (m *mockWiFiManagerImpl) GetInterface() string {
	return "wlan0"
}

// ============================================================================
// Additional tests for improved coverage
// ============================================================================

func TestClearDNS(t *testing.T) {
	t.Run("success - removes immutable attribute when netop owns DNS", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["tee /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(),
			executor:         executor,
			logger:           logger,
			dnsOwnershipPath: t.TempDir() + "/dns-owned",
		}

		manager.markDNSOwned()

		err := manager.ClearDNS()
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
	})

	t.Run("chattr fails but continues - file not locked", func(t *testing.T) {
		executor := newMockExecutor()
		executor.errors["chattr -i /etc/resolv.conf"] = fmt.Errorf("Operation not supported")
		executor.commands["tee /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(),
			executor:         executor,
			logger:           logger,
			dnsOwnershipPath: t.TempDir() + "/dns-owned",
		}

		manager.markDNSOwned()

		// Should still succeed - chattr failure is expected on some filesystems
		err := manager.ClearDNS()
		assert.NoError(t, err)
	})

	t.Run("no-op when netop does not own DNS", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(),
			executor:         executor,
			logger:           logger,
			dnsOwnershipPath: t.TempDir() + "/dns-owned",
		}

		// No markDNSOwned() call — DNS is not owned by netop
		err := manager.ClearDNS()
		assert.NoError(t, err)
		// Should NOT have touched resolv.conf
		executor.assertCommandNotExecuted(t, "chattr -i /etc/resolv.conf")
	})
}

func TestStartDHCP_ErrorPath(t *testing.T) {
	t.Run("dhcp acquire fails - returns error", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{acquireErr: fmt.Errorf("dhclient failed")}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), dhcpClient: dhcpClient}

		err := manager.StartDHCP("eth0", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dhclient failed")
	})
}

// A wired network whose DHCP lease fails must return an error, not report a
// successful connection with no IP.
func TestConnectToConfiguredNetwork_WiredDHCPFailureReturnsError(t *testing.T) {
	executor := newMockExecutor()
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip route flush dev eth0"] = ""
	executor.commands["cat /sys/class/net/eth0/carrier"] = "1"
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(),
		executor:   executor,
		logger:     logger,
		dhcpClient: &mockDHCPClient{acquireErr: fmt.Errorf("no lease obtained")},
	}

	config := &types.NetworkConfig{Interface: "eth0"} // wired: no SSID, no static Addr

	err := manager.ConnectToConfiguredNetwork(config, "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to obtain DHCP lease")
}

func TestSetMAC_ErrorPaths(t *testing.T) {
	t.Run("interface down fails", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		links := newFakeLinks()
		links.SetDownErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring interface down")
	})

	t.Run("set address fails", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		links := newFakeLinks()
		links.SetMACErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set MAC address")
	})

	t.Run("interface up fails", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		links := newFakeLinks()
		links.SetUpErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring interface up")
	})

	t.Run("empty mac generates random", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		// Empty MAC should generate a random one
		err := manager.SetMAC("wlan0", "")
		assert.NoError(t, err)
		// A random MAC was generated and pushed to the link.
		assert.Len(t, links.SetMACCalls, 1)
		assert.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, links.SetMACCalls[0].MAC)
	})
}

func TestGetMAC_ErrorPaths(t *testing.T) {
	t.Run("link manager fails", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		links := &fake.LinkManager{GetMACErr: assert.AnError}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get interface info")
	})

	t.Run("no MAC available", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		// Link manager reports no MAC for the interface.
		links := newFakeLinks()
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
	})
}

func TestSetIP_ErrorPaths(t *testing.T) {
	t.Run("flush fails but continues", func(t *testing.T) {
		// Flush failure is just a warning, doesn't stop execution
		logger := &mockLogger{}
		addrs := newFakeAddrs()
		addrs.FlushErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: addrs, linkMgr: newFakeLinks(), executor: &mockSystemExecutor{}, logger: logger}

		err := manager.SetIP("eth0", "192.168.1.100/24", "192.168.1.1", 0)
		assert.NoError(t, err) // Flush failure is just logged, not returned
	})

	t.Run("add addr fails", func(t *testing.T) {
		logger := &mockLogger{}
		addrs := newFakeAddrs()
		addrs.AddErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: addrs, linkMgr: newFakeLinks(), executor: &mockSystemExecutor{}, logger: logger}

		err := manager.SetIP("eth0", "192.168.1.100/24", "192.168.1.1", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set IP address")
	})

	t.Run("add route fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr flush dev eth0":                "",
				"ip addr add 192.168.1.100/24 dev eth0": "",
			},
		}
		logger := &mockLogger{}
		routes := newFakeRoutes()
		routes.SetForIfaceErr = assert.AnError
		manager := &Manager{routeMgr: routes, addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetIP("eth0", "192.168.1.100/24", "192.168.1.1", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set gateway")
	})

	t.Run("empty gateway skips route", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr flush dev eth0":                "",
				"ip addr add 192.168.1.100/24 dev eth0": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetIP("eth0", "192.168.1.100/24", "", 0)
		assert.NoError(t, err)
	})

	t.Run("empty addr skips add", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr flush dev eth0":                        "",
				"ip route add default via 192.168.1.1 dev eth0": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		err := manager.SetIP("eth0", "", "192.168.1.1", 0)
		assert.NoError(t, err)
	})
}

func TestDHCPRenew_ErrorPaths(t *testing.T) {
	t.Run("dhcp renew fails", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		dhcpClient := &mockDHCPClient{renewErr: assert.AnError}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}, dhcpClient: dhcpClient}

		err := manager.DHCPRenew("eth0", "")
		assert.Error(t, err)
	})
}

// TestSetDNS_ErrorPaths removed - covered by improved TestSetDNS tests above

func TestConnectToConfiguredNetwork_ErrorPaths(t *testing.T) {
	t.Run("MAC set fails", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		links := newFakeLinks()
		links.SetDownErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			MAC:       "aa:bb:cc:dd:ee:ff",
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set MAC")
	})

	t.Run("WiFi connect fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"hostname test-host": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "wlan0",
			SSID:      "test-network",
			PSK:       "password",
			Hostname:  "test-host",
		}

		wifiManager := &mockWiFiManagerFailing{}

		err := manager.ConnectToConfiguredNetwork(config, "", wifiManager)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect to WiFi")
	})

	t.Run("WiFi BSSID connect fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"hostname test-host": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "wlan0",
			SSID:      "test-network",
			PSK:       "password",
			ApAddr:    "00:11:22:33:44:55",
			Hostname:  "test-host",
		}

		wifiManager := &mockWiFiManagerFailing{}

		err := manager.ConnectToConfiguredNetwork(config, "", wifiManager)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect to WiFi")
	})

	t.Run("static IP fails on addr add", func(t *testing.T) {
		executor := &mockSystemExecutor{}
		logger := &mockLogger{}
		addrs := newFakeAddrs()
		addrs.AddErr = assert.AnError
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: addrs, linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set IP")
	})

	t.Run("invalid route format", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr flush dev eth0":                        "",
				"ip addr add 192.168.1.100/24 dev eth0":         "",
				"ip route add default via 192.168.1.1 dev eth0": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
			Routes:    []string{"invalid-route-format"},
		}

		// Should warn but not fail
		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
	})

	t.Run("password from config PSK", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
		}
		logger := &mockLogger{}
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "wlan0",
			SSID:      "test-network",
			PSK:       "config-password",
		}

		wifiManager := &mockWiFiManagerImpl{executor: executor, logger: logger}

		// Password should come from config.PSK when empty
		err := manager.ConnectToConfiguredNetwork(config, "", wifiManager)
		assert.NoError(t, err)
	})
}

func TestAddRoute_Error(t *testing.T) {
	logger := &mockLogger{}
	routes := newFakeRoutes()
	routes.AddErr = assert.AnError
	manager := &Manager{routeMgr: routes, addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: &mockSystemExecutor{}, logger: logger}

	err := manager.AddRoute("eth0", "10.0.0.0/24", "192.168.1.1")
	assert.Error(t, err)
}

func TestFlushRoutes_Error(t *testing.T) {
	logger := &mockLogger{}
	routes := newFakeRoutes()
	routes.FlushErr = assert.AnError
	manager := &Manager{routeMgr: routes, addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: &mockSystemExecutor{}, logger: logger}

	err := manager.FlushRoutes("eth0")
	assert.Error(t, err)
}

func TestFindWirelessInterface_MultipleInterfaces(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"iw dev": "Interface wlan0\nInterface wlan1",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: logger}

	result, err := manager.findWirelessInterface()
	assert.NoError(t, err)
	assert.Equal(t, "wlan0", result) // Should return first one
}

func TestExpandMACTemplate_FullTemplate(t *testing.T) {
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks()}

	// Test with all question marks
	result := manager.expandMACTemplate("??:??:??:??:??:??")
	assert.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, result)

	// Test with mixed
	result = manager.expandMACTemplate("aa:bb:??:??:??:??")
	assert.True(t, strings.HasPrefix(result, "aa:bb:"))
	assert.Regexp(t, `^aa:bb:[0-9a-f]{2}(:[0-9a-f]{2}){3}$`, result)
}

func TestGenerateRandomMAC_IsLocallyAdministered(t *testing.T) {
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks()}

	// Generate multiple MACs and verify they're locally administered
	for i := 0; i < 10; i++ {
		mac := manager.generateRandomMAC()
		parts := strings.Split(mac, ":")
		assert.Len(t, parts, 6)

		// First byte should have bit 1 set (locally administered)
		// and bit 0 clear (unicast)
		firstByte, err := parseHexByte(parts[0])
		assert.NoError(t, err)
		assert.True(t, firstByte&0x02 == 0x02, "MAC should be locally administered")
		assert.True(t, firstByte&0x01 == 0x00, "MAC should be unicast")
	}
}

func parseHexByte(s string) (byte, error) {
	var b byte
	_, err := fmt.Sscanf(s, "%02x", &b)
	return b, err
}

// Mock WiFi manager that always fails
type mockWiFiManagerFailing struct{}

func (m *mockWiFiManagerFailing) Scan() ([]types.WiFiNetwork, error) {
	return nil, assert.AnError
}

func (m *mockWiFiManagerFailing) Connect(ssid, password, hostname string) error {
	return assert.AnError
}

func (m *mockWiFiManagerFailing) ConnectWithBSSID(ssid, password, bssid, hostname string) error {
	return assert.AnError
}

func (m *mockWiFiManagerFailing) Disconnect() error {
	return assert.AnError
}

func (m *mockWiFiManagerFailing) ListConnections() ([]types.Connection, error) {
	return nil, assert.AnError
}

func (m *mockWiFiManagerFailing) GetInterface() string {
	return "wlan0"
}

// GetConnectionInfo must populate SSID for a wireless interface so `net status`
// can display it (previously always blank).
func TestGetConnectionInfo_PopulatesSSID(t *testing.T) {
	executor := newMockExecutor()
	executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
	executor.commands["cat /etc/resolv.conf"] = "nameserver 1.1.1.1\n"
	executor.commands["iw dev wlan0 link"] = "Connected to aa:bb:cc:dd:ee:ff\n\tSSID: CoffeeShop\n\tfreq: 2412"
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}}

	conn, err := manager.GetConnectionInfo("wlan0")
	assert.NoError(t, err)
	assert.Equal(t, "CoffeeShop", conn.SSID)
}

// A wired interface (iw returns an error / no link) must leave SSID empty
// rather than showing garbage.
func TestGetConnectionInfo_NoSSIDForWired(t *testing.T) {
	executor := newMockExecutor()
	executor.commands["ip addr show eth0"] = "inet 10.0.0.5/24"
	executor.commands["cat /etc/resolv.conf"] = "nameserver 1.1.1.1\n"
	executor.errors["iw dev eth0 link"] = fmt.Errorf("nl80211 not found (not a wireless interface)")
	manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: executor, logger: &mockLogger{}}

	conn, err := manager.GetConnectionInfo("eth0")
	assert.NoError(t, err)
	assert.Equal(t, "", conn.SSID)
}

// Disconnect releases DHCP, flushes addresses/routes, and brings the interface
// down — the core of what `net stop` does per interface.
func TestDisconnect(t *testing.T) {
	t.Run("full sequence succeeds", func(t *testing.T) {
		executor := newMockExecutor()
		dhcp := &mockDHCPClient{}
		routes := newFakeRoutes()
		addrs := newFakeAddrs()
		links := newFakeLinks()
		manager := &Manager{routeMgr: routes, addrMgr: addrs, linkMgr: links, executor: executor, logger: &mockLogger{}, dhcpClient: dhcp}

		err := manager.Disconnect("eth0")
		assert.NoError(t, err)
		assert.Contains(t, addrs.Flushed, "eth0", "addresses should be flushed on eth0")
		assert.Contains(t, routes.Flushed, "eth0", "routes should be flushed on eth0")
		assert.Contains(t, links.Downed, "eth0", "interface should be brought down")
	})

	t.Run("invalid interface name is rejected", func(t *testing.T) {
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: newFakeLinks(), executor: newMockExecutor(), logger: &mockLogger{}}
		err := manager.Disconnect("eth0; rm -rf /")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid interface")
	})

	t.Run("link-down failure returns error", func(t *testing.T) {
		executor := newMockExecutor()
		links := newFakeLinks()
		links.SetDownErr = fmt.Errorf("device busy")
		manager := &Manager{routeMgr: newFakeRoutes(), addrMgr: newFakeAddrs(), linkMgr: links, executor: executor, logger: &mockLogger{}}
		err := manager.Disconnect("eth0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring interface down")
	})
}
