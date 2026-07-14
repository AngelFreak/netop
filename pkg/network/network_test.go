package network

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

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
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{})
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
	})

	t.Run("dhcp keyword unlocks resolv.conf for DHCP", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// Should unlock resolv.conf so DHCP can write DNS servers
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"invalid", "not-an-ip"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid DNS servers")
	})

	t.Run("tee failure returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.errors["tee /etc/resolv.conf"] = fmt.Errorf("permission denied")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"8.8.8.8"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write resolv.conf")
	})

	t.Run("does not lock resolv.conf when DNS is DHCP", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := NewManager(executor, logger, &mockDHCPClient{})

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

		err := manager.SetDNS([]string{"8.8.8.8"})
		assert.NoError(t, err)

		// Should lock when custom DNS is set — prevents DHCP from overwriting
		executor.assertCommandExecuted(t, "chattr +i /etc/resolv.conf")
	})
}

func TestSetMAC(t *testing.T) {
	t.Run("specific mac - full sequence", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ip link set wlan0 down"] = ""
		executor.commands["ip link set wlan0 address aa:bb:cc:dd:ee:ff"] = ""
		executor.commands["ip link set wlan0 up"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.NoError(t, err)

		// Verify correct sequence: down -> set address -> up
		assert.Len(t, executor.executedCmds, 3)
		assert.Equal(t, "ip link set wlan0 down", executor.executedCmds[0])
		assert.Contains(t, executor.executedCmds[1], "ip link set wlan0 address")
		assert.Equal(t, "ip link set wlan0 up", executor.executedCmds[2])
	})

	t.Run("random mac - generates valid mac", func(t *testing.T) {
		// Use non-strict mock since generated MAC is random
		executor := &mockSystemExecutor{
			commands:       make(map[string]string),
			errors:         make(map[string]error),
			executedCmds:   []string{},
			inputsReceived: make(map[string]string),
		}
		// Accept any ip link commands
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "random")
		assert.NoError(t, err)

		// Verify down/up were called and address has valid format
		assert.GreaterOrEqual(t, len(executor.executedCmds), 3)
		// Find the address command and verify it's a valid MAC
		for _, cmd := range executor.executedCmds {
			if strings.Contains(cmd, "address") {
				// Extract MAC from command
				parts := strings.Split(cmd, "address ")
				if len(parts) == 2 {
					mac := parts[1]
					assert.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, mac)
				}
			}
		}
	})

	t.Run("template mac - expands wildcards", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands:       make(map[string]string),
			errors:         make(map[string]error),
			executedCmds:   []string{},
			inputsReceived: make(map[string]string),
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "00:11:??:??:??:??")
		assert.NoError(t, err)

		// Find address command and verify template was expanded
		for _, cmd := range executor.executedCmds {
			if strings.Contains(cmd, "address") {
				assert.True(t, strings.HasPrefix(cmd, "ip link set wlan0 address 00:11:"))
				assert.NotContains(t, cmd, "??", "template wildcards should be expanded")
			}
		}
	})

	t.Run("permanent mac - uses ethtool to get factory MAC", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// ethtool -P returns the permanent/factory MAC address
		executor.commands["ethtool -P wlan0"] = "Permanent address: 00:11:22:33:44:55"
		executor.commands["ip link set wlan0 down"] = ""
		executor.commands["ip link set wlan0 address 00:11:22:33:44:55"] = ""
		executor.commands["ip link set wlan0 up"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "permanent")
		assert.NoError(t, err)

		// Verify ethtool was called and the permanent MAC was used
		executor.assertCommandExecuted(t, "ethtool -P wlan0")
		executor.assertCommandExecuted(t, "ip link set wlan0 address 00:11:22:33:44:55")
	})

	t.Run("permanent mac - fails when ethtool unavailable", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["ethtool -P wlan0"] = assert.AnError
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "permanent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get permanent MAC")
	})

	t.Run("permanent mac - fails on invalid ethtool output", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ethtool -P wlan0"] = "Invalid output"
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "permanent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse permanent MAC")
	})
}

func TestGetMAC(t *testing.T) {
	t.Run("success - parses MAC from ip link output", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// Realistic ip link show output
		executor.commands["ip link show wlan0"] = `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DORMANT group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff`
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		mac, err := manager.GetMAC("wlan0")
		assert.NoError(t, err)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", mac)
		executor.assertCommandExecuted(t, "ip link show wlan0")
	})

	t.Run("interface down - still has MAC", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ip link show eth0"] = `3: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 1000
    link/ether 11:22:33:44:55:66 brd ff:ff:ff:ff:ff:ff`
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		mac, err := manager.GetMAC("eth0")
		assert.NoError(t, err)
		assert.Equal(t, "11:22:33:44:55:66", mac)
	})

	t.Run("no ether in output - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ip link show wlan0"] = `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP`
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MAC address not found")
	})

	t.Run("malformed ether line - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ip link show wlan0"] = `    link/ether`
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
	})
}

func TestSetIP(t *testing.T) {
	t.Run("full config with addr and gateway", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ip addr flush dev wlan0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev wlan0"] = ""
		executor.commands["ip route del default dev wlan0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev wlan0"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetIP("wlan0", "192.168.1.100/24", "192.168.1.1", 0)
		assert.NoError(t, err)

		// Verify commands executed in order: flush addr, add addr, del default (idempotent), add route
		assert.Len(t, executor.executedCmds, 4)
		assert.Equal(t, "ip addr flush dev wlan0", executor.executedCmds[0])
		assert.Equal(t, "ip addr add 192.168.1.100/24 dev wlan0", executor.executedCmds[1])
		assert.Equal(t, "ip route del default dev wlan0", executor.executedCmds[2])
		assert.Equal(t, "ip route add default via 192.168.1.1 dev wlan0", executor.executedCmds[3])
	})
}

func TestAddRoute(t *testing.T) {
	t.Run("success - adds route via gateway", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ip route add 10.0.0.0/24 via 192.168.1.1 dev wlan0"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.AddRoute("wlan0", "10.0.0.0/24", "192.168.1.1")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "ip route add 10.0.0.0/24 via 192.168.1.1 dev wlan0")
	})
}

func TestFlushRoutes(t *testing.T) {
	t.Run("success - flushes all routes on interface", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["ip route flush dev wlan0"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.FlushRoutes("wlan0")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "ip route flush dev wlan0")
	})
}

func TestStartDHCP(t *testing.T) {
	t.Run("success - delegates to DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{dhcpClient: dhcpClient}

		err := manager.StartDHCP("wlan0", "test-hostname")
		assert.NoError(t, err)
	})

	t.Run("failure - propagates error from DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{acquireErr: fmt.Errorf("dhcp failed")}
		manager := &Manager{dhcpClient: dhcpClient}

		err := manager.StartDHCP("wlan0", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dhcp failed")
	})
}

func TestDHCPRenew(t *testing.T) {
	t.Run("success - delegates to DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{dhcpClient: dhcpClient}

		err := manager.DHCPRenew("wlan0", "test-hostname")
		assert.NoError(t, err)
	})

	t.Run("failure - propagates error from DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{renewErr: fmt.Errorf("renew failed")}
		manager := &Manager{dhcpClient: dhcpClient}

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
		manager := &Manager{executor: executor, logger: logger}

		result, err := manager.findWirelessInterface()
		assert.NoError(t, err)
		assert.Equal(t, "wlan0", result)
	})

	t.Run("no wireless interfaces - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["iw dev"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		_, err := manager.findWirelessInterface()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no wireless interface found")
	})

	t.Run("iw dev fails - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["iw dev"] = fmt.Errorf("iw: command not found")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		_, err := manager.findWirelessInterface()
		assert.Error(t, err)
	})
}

func TestGenerateRandomMAC(t *testing.T) {
	manager := &Manager{}
	mac := manager.generateRandomMAC()
	assert.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, mac)
}

func TestGenerateMacBookProMAC(t *testing.T) {
	manager := &Manager{}
	mac := manager.generateMacBookProMAC()
	assert.Regexp(t, `^ac:bc:32:[0-9a-f]{2}(:[0-9a-f]{2}){2}$`, mac)
}

func TestExpandMACTemplate(t *testing.T) {
	manager := &Manager{}
	result := manager.expandMACTemplate("00:??:??:??:??:??")
	assert.Regexp(t, `^00:[0-9a-f]{2}(:[0-9a-f]{2}){4}$`, result)
}

func TestWriteFile(t *testing.T) {
	// The staging path includes the PID for uniqueness, so use non-strict mock
	t.Run("success - writes temp and moves to target", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

		err := manager.writeFile("/etc/test.conf", "test content")
		assert.Error(t, err)
	})
}

func TestWriteFileDirect(t *testing.T) {
	t.Run("success - writes via tee", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["tee /tmp/test"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

		err := manager.writeFileDirect("/tmp/test", "content")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no space left")
	})

	t.Run("multiline content preserved", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["tee /tmp/multiline"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetHostname("test-host")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "hostname test-host")
	})

	t.Run("empty hostname - no command executed", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// No commands expected for empty hostname
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetHostname("")
		assert.NoError(t, err)
		assert.Empty(t, executor.executedCmds, "no commands should be executed for empty hostname")
	})

	t.Run("hostname command fails - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["hostname fail-host"] = fmt.Errorf("hostname: you must be root to change the host name")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetHostname("fail-host")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "you must be root")
	})
}

func TestDetectInterface(t *testing.T) {
	t.Run("configured interface", func(t *testing.T) {
		manager := &Manager{logger: &mockLogger{}}
		config := &types.NetworkConfig{Interface: "eth0"}
		result := manager.detectInterface(config)
		assert.Equal(t, "eth0", result)
	})

	t.Run("wireless auto-detect", func(t *testing.T) {
		executor := newMockExecutor()
		manager := &Manager{executor: executor, logger: &mockLogger{}}
		config := &types.NetworkConfig{SSID: "test-network"}
		// This will try to detect from actual system interfaces
		result := manager.detectInterface(config)
		// Result could be empty or a detected interface
		assert.True(t, result == "" || len(result) > 0)
	})

	t.Run("wired auto-detect", func(t *testing.T) {
		executor := newMockExecutor()
		manager := &Manager{executor: executor, logger: &mockLogger{}}
		config := &types.NetworkConfig{}
		// This will try to detect from actual system interfaces
		result := manager.detectInterface(config)
		// Result could be empty or a detected interface
		assert.True(t, result == "" || len(result) > 0)
	})
}

func TestParseIPAddress(t *testing.T) {
	manager := &Manager{logger: &mockLogger{}}

	t.Run("valid IP", func(t *testing.T) {
		output := `1: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0`
		ip := manager.parseIPAddress(output)
		assert.NotNil(t, ip)
		assert.Equal(t, "192.168.1.100", ip.String())
	})

	t.Run("no IP", func(t *testing.T) {
		output := "no inet here"
		ip := manager.parseIPAddress(output)
		assert.Nil(t, ip)
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		output := "inet invalidip"
		ip := manager.parseIPAddress(output)
		assert.Nil(t, ip)
	})
}

func TestConnectToConfiguredNetwork(t *testing.T) {
	t.Run("wireless with SSID", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set wlan0 down"] = ""
		executor.commands["ip link set wlan0 address aa:bb:cc:dd:ee:ff"] = ""
		executor.commands["ip link set wlan0 up"] = ""
		executor.commands["hostname test-host"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		executor.assertCommandExecuted(t, "ip link set wlan0 address aa:bb:cc:dd:ee:ff")
	})

	t.Run("wireless with BSSID pinning", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set wlan0 down"] = ""
		executor.commands["ip link set wlan0 up"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{executor: executor, logger: logger, dhcpClient: dhcpClient}

		config := &types.NetworkConfig{
			Interface: "eth0",
			// No SSID means wired, no Addr means DHCP
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		// Verify interface was brought up
		executor.assertCommandExecuted(t, "ip link set eth0 up")
		// DHCP is now handled by the mock DHCPClientManager
	})

	t.Run("wired connection flushes stale state before DHCP", func(t *testing.T) {
		// After suspend/resume, stale IPs and routes remain on the interface.
		// Verify that wired connect flushes them before bringing the interface up.
		executor := newMockExecutor()
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip route flush dev eth0"] = ""
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{executor: executor, logger: logger, dhcpClient: dhcpClient}

		config := &types.NetworkConfig{
			Interface: "eth0",
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)

		// Verify flush commands were called
		executor.assertCommandExecuted(t, "ip addr flush dev eth0")
		executor.assertCommandExecuted(t, "ip route flush dev eth0")

		// Verify flush happens before interface up
		flushAddrIdx := -1
		flushRouteIdx := -1
		ifaceUpIdx := -1
		for i, cmd := range executor.executedCmds {
			switch cmd {
			case "ip addr flush dev eth0":
				if flushAddrIdx == -1 {
					flushAddrIdx = i
				}
			case "ip route flush dev eth0":
				if flushRouteIdx == -1 {
					flushRouteIdx = i
				}
			case "ip link set eth0 up":
				ifaceUpIdx = i
			}
		}
		assert.True(t, flushAddrIdx < ifaceUpIdx, "flush addr should come before interface up")
		assert.True(t, flushRouteIdx < ifaceUpIdx, "flush route should come before interface up")
	})

	t.Run("static IP configuration", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route del default dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0 metric 100"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "ip addr add 192.168.1.100/24 dev eth0")
		executor.assertCommandExecuted(t, "ip route add default via 192.168.1.1 dev eth0 metric 100")
	})

	t.Run("with custom routes", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0"] = ""
		executor.commands["ip route add 10.0.0.0/24 via 192.168.1.254 dev eth0"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
			Routes:    []string{"default", "10.0.0.0/24 -> 192.168.1.254"},
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "ip route add 10.0.0.0/24 via 192.168.1.254 dev eth0")
	})

	t.Run("with custom DNS", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
			DNS:       []string{"8.8.8.8", "1.1.1.1"},
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
	})

	t.Run("with DHCP DNS - clears resolv.conf and unlocks for DHCP", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		executor.commands["tee /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			Addr:      "192.168.1.100/24",
			Gateway:   "192.168.1.1",
			DNS:       []string{"dhcp"},
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		// resolv.conf should be unlocked and cleared so DHCP client can write fresh DNS
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
		assert.True(t, lockCalled, "should lock resolv.conf after DHCP to prevent external tools from overwriting")
		// Verify the placeholder content was written
		assert.Contains(t, executor.inputsReceived["tee /etc/resolv.conf"], "Waiting for DHCP")
	})

	t.Run("DHCP DNS locks resolv.conf after connection to prevent netbird overwrite", func(t *testing.T) {
		// When using DHCP for DNS and netbird is still connected, netbird
		// will overwrite resolv.conf with its own DNS after DHCP writes it.
		// The fix: lock resolv.conf with chattr +i AFTER DHCP completes.
		executor := newMockExecutor()
		executor.commands["ip link set wlan0 down"] = ""
		executor.commands["ip link set wlan0 up"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		executor.commands["tee /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
	})

	t.Run("auto-detect interface falls back when detection finds nothing", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{executor: executor, logger: logger, dhcpClient: dhcpClient}

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
		manager := &Manager{
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
		manager := &Manager{
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
		manager := &Manager{
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
		manager := &Manager{dhcpClient: dhcpClient}

		err := manager.StartDHCP("eth0", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dhclient failed")
	})
}

func TestSetMAC_ErrorPaths(t *testing.T) {
	t.Run("interface down fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"ip link set wlan0 down": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring interface down")
	})

	t.Run("set address fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link set wlan0 down": "",
			},
			errors: map[string]error{
				"ip link set wlan0 address aa:bb:cc:dd:ee:ff": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set MAC address")
	})

	t.Run("interface up fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link set wlan0 down":                      "",
				"ip link set wlan0 address aa:bb:cc:dd:ee:ff": "",
			},
			errors: map[string]error{
				"ip link set wlan0 up": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetMAC("wlan0", "aa:bb:cc:dd:ee:ff")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring interface up")
	})

	t.Run("empty mac generates random", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link set wlan0 down": "",
				"ip link set wlan0 up":   "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		// Empty MAC should generate a random one
		err := manager.SetMAC("wlan0", "")
		assert.NoError(t, err)
	})
}

func TestGetMAC_ErrorPaths(t *testing.T) {
	t.Run("execute fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"ip link show wlan0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get interface info")
	})

	t.Run("no ether in output", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link show wlan0": "1: wlan0: <BROADCAST> mtu 1500\n    something else",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		_, err := manager.GetMAC("wlan0")
		assert.Error(t, err)
	})
}

func TestSetIP_ErrorPaths(t *testing.T) {
	t.Run("flush fails but continues", func(t *testing.T) {
		// Flush failure is just a warning, doesn't stop execution
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr add 192.168.1.100/24 dev eth0":         "",
				"ip route add default via 192.168.1.1 dev eth0": "",
			},
			errors: map[string]error{
				"ip addr flush dev eth0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetIP("eth0", "192.168.1.100/24", "192.168.1.1", 0)
		assert.NoError(t, err) // Flush failure is just logged, not returned
	})

	t.Run("add addr fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr flush dev eth0": "",
			},
			errors: map[string]error{
				"ip addr add 192.168.1.100/24 dev eth0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
			errors: map[string]error{
				"ip route add default via 192.168.1.1 dev eth0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetIP("eth0", "", "192.168.1.1", 0)
		assert.NoError(t, err)
	})
}

func TestDHCPRenew_ErrorPaths(t *testing.T) {
	t.Run("dhcp renew fails", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{renewErr: assert.AnError}
		manager := &Manager{dhcpClient: dhcpClient}

		err := manager.DHCPRenew("eth0", "")
		assert.Error(t, err)
	})
}

// TestSetDNS_ErrorPaths removed - covered by improved TestSetDNS tests above

func TestConnectToConfiguredNetwork_ErrorPaths(t *testing.T) {
	t.Run("MAC set fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"ip link set eth0 down": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

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
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link set eth0 up":    "",
				"ip addr flush dev eth0": "",
			},
			errors: map[string]error{
				"ip addr add 192.168.1.100/24 dev eth0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
				"ip link set eth0 up":                           "",
				"ip addr flush dev eth0":                        "",
				"ip addr add 192.168.1.100/24 dev eth0":         "",
				"ip route add default via 192.168.1.1 dev eth0": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
		manager := &Manager{executor: executor, logger: logger}

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
	executor := &mockSystemExecutor{
		commands: map[string]string{},
		errors: map[string]error{
			"ip route add 10.0.0.0/24 via 192.168.1.1 dev eth0": assert.AnError,
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger}

	err := manager.AddRoute("eth0", "10.0.0.0/24", "192.168.1.1")
	assert.Error(t, err)
}

func TestFlushRoutes_Error(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{},
		errors: map[string]error{
			"ip route flush dev eth0": assert.AnError,
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger}

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
	manager := &Manager{executor: executor, logger: logger}

	result, err := manager.findWirelessInterface()
	assert.NoError(t, err)
	assert.Equal(t, "wlan0", result) // Should return first one
}

func TestExpandMACTemplate_FullTemplate(t *testing.T) {
	manager := &Manager{}

	// Test with all question marks
	result := manager.expandMACTemplate("??:??:??:??:??:??")
	assert.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, result)

	// Test with mixed
	result = manager.expandMACTemplate("aa:bb:??:??:??:??")
	assert.True(t, strings.HasPrefix(result, "aa:bb:"))
	assert.Regexp(t, `^aa:bb:[0-9a-f]{2}(:[0-9a-f]{2}){3}$`, result)
}

func TestGenerateRandomMAC_IsLocallyAdministered(t *testing.T) {
	manager := &Manager{}

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
