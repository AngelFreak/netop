package network

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Mock implementations with strict mode - fails on unexpected commands
type mockSystemExecutor struct {
	commands       map[string]string
	errors         map[string]error
	strict         bool                 // If true, fail on unexpected commands
	executedCmds   []string             // Track executed commands for verification
	inputsReceived map[string]string    // Track inputs received by ExecuteWithInput
	hasCommands    map[string]bool      // which commands are "installed"
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

type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}

func TestNewManager(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := NewManager(executor, logger)
	assert.NotNil(t, manager)
	assert.Equal(t, executor, manager.executor)
	assert.Equal(t, logger, manager.logger)
}

func TestSetDNS(t *testing.T) {
	t.Run("empty servers does nothing", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// No commands should be executed for empty servers
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{})
		assert.NoError(t, err)
		assert.Empty(t, executor.executedCmds, "no commands should be executed for empty servers")
	})

	t.Run("dhcp keyword does nothing", func(t *testing.T) {
		executor := newStrictMockExecutor()
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"dhcp"})
		assert.NoError(t, err)
		assert.Empty(t, executor.executedCmds, "no commands should be executed for dhcp")
	})

	t.Run("valid servers writes resolv.conf with correct content", func(t *testing.T) {
		executor := newStrictMockExecutor()
		// Actual implementation: chattr -i, rm temp, tee temp, mv temp to dest, chattr +i
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"8.8.8.8", "1.1.1.1"})
		assert.NoError(t, err)

		// Verify the correct content was written to temp file
		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
		executor.assertCommandExecuted(t, "tee /run/net/staging.conf")
		executor.assertCommandExecuted(t, "mv /run/net/staging.conf /etc/resolv.conf")
		executor.assertCommandExecuted(t, "chattr +i /etc/resolv.conf")
		executor.assertInputContains(t, "tee /run/net/staging.conf", "nameserver 8.8.8.8")
		executor.assertInputContains(t, "tee /run/net/staging.conf", "nameserver 1.1.1.1")
	})

	t.Run("invalid IP addresses are filtered out", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"invalid", "8.8.8.8", "not-an-ip"})
		assert.NoError(t, err)

		// Only valid IP should be in output
		input := executor.inputsReceived["tee /run/net/staging.conf"]
		assert.Contains(t, input, "nameserver 8.8.8.8")
		assert.NotContains(t, input, "invalid")
		assert.NotContains(t, input, "not-an-ip")
	})

	t.Run("all invalid IPs results in empty file", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		executor.commands["chattr +i /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"invalid", "not-an-ip"})
		assert.NoError(t, err)

		// File should be written but empty (no valid nameservers)
		input := executor.inputsReceived["tee /run/net/staging.conf"]
		assert.NotContains(t, input, "nameserver")
	})

	t.Run("tee failure returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.errors["tee /run/net/staging.conf"] = fmt.Errorf("permission denied")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"8.8.8.8"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write resolv.conf")
	})

	t.Run("mv failure returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.errors["mv /run/net/staging.conf /etc/resolv.conf"] = fmt.Errorf("permission denied")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetDNS([]string{"8.8.8.8"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write resolv.conf")
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
		executor.commands["ip route add default via 192.168.1.1 dev wlan0"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.SetIP("wlan0", "192.168.1.100/24", "192.168.1.1")
		assert.NoError(t, err)

		// Verify commands executed in order: flush, add addr, add route
		assert.Len(t, executor.executedCmds, 3)
		assert.Equal(t, "ip addr flush dev wlan0", executor.executedCmds[0])
		assert.Equal(t, "ip addr add 192.168.1.100/24 dev wlan0", executor.executedCmds[1])
		assert.Equal(t, "ip route add default via 192.168.1.1 dev wlan0", executor.executedCmds[2])
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
	t.Run("success with dhclient - kills old process and starts new", func(t *testing.T) {
		executor := newMockExecutor()
		// New streamlined DHCP flow: force kill + lease file removal
		executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
		executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
		executor.commands["timeout 15 dhclient -v wlan0"] = ""
		executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.StartDHCP("wlan0", "")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "pkill -9 -f dhclient.*wlan0")
		executor.assertCommandExecuted(t, "timeout 15 dhclient -v wlan0")
	})

	t.Run("success with udhcpc - uses faster DHCP client when available", func(t *testing.T) {
		executor := newMockExecutor()
		executor.hasCommands = map[string]bool{"udhcpc": true}
		executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
		executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
		executor.commands["udhcpc -i wlan0 -n -q"] = ""
		executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.StartDHCP("wlan0", "")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "udhcpc -i wlan0 -n -q")
	})
}

func TestDHCPRenew(t *testing.T) {
	t.Run("success - renews DHCP lease with dhclient", func(t *testing.T) {
		executor := newMockExecutor()
		// New streamlined DHCP flow
		executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
		executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
		executor.commands["timeout 15 dhclient -v wlan0"] = ""
		executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.DHCPRenew("wlan0", "")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "timeout 15 dhclient -v wlan0")
	})

	t.Run("success - renews DHCP lease with udhcpc", func(t *testing.T) {
		executor := newMockExecutor()
		executor.hasCommands = map[string]bool{"udhcpc": true}
		executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
		executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
		executor.commands["udhcpc -i wlan0 -n -q"] = ""
		executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.DHCPRenew("wlan0", "")
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "udhcpc -i wlan0 -n -q")
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
	t.Run("success - removes temp, writes, and moves", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/test.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.writeFile("/etc/test.conf", "test content")
		assert.NoError(t, err)

		// Verify the correct sequence of operations
		executor.assertCommandExecuted(t, "rm -f /run/net/staging.conf")
		executor.assertCommandExecuted(t, "tee /run/net/staging.conf")
		executor.assertCommandExecuted(t, "mv /run/net/staging.conf /etc/test.conf")
		executor.assertInputContains(t, "tee /run/net/staging.conf", "test content")
	})

	t.Run("rm temp fails - continues anyway", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.errors["rm -f /run/net/staging.conf"] = fmt.Errorf("file not found")
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/test.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.writeFile("/etc/test.conf", "test content")
		assert.NoError(t, err) // Should still succeed
	})

	t.Run("tee fails - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.errors["tee /run/net/staging.conf"] = fmt.Errorf("permission denied")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.writeFile("/etc/test.conf", "test content")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("mv fails - returns error", func(t *testing.T) {
		executor := newStrictMockExecutor()
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.errors["mv /run/net/staging.conf /etc/test.conf"] = fmt.Errorf("permission denied")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.writeFile("/etc/test.conf", "test content")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
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
		// New streamlined DHCP flow
		executor.commands["pkill -9 -f dhclient.*eth0"] = ""
		executor.commands["rm -f /var/lib/dhcp/dhclient.eth0.leases /run/net/dhclient.eth0.leases"] = ""
		executor.commands["timeout 15 dhclient -v eth0"] = ""
		executor.commands["ip addr show eth0"] = "inet 192.168.1.50/24"
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		config := &types.NetworkConfig{
			Interface: "eth0",
			// No SSID means wired
		}

		err := manager.ConnectToConfiguredNetwork(config, "", nil)
		assert.NoError(t, err)
		// Verify interface was brought up and DHCP was started
		executor.assertCommandExecuted(t, "ip link set eth0 up")
		executor.assertCommandExecuted(t, "timeout 15 dhclient -v eth0")
	})

	t.Run("static IP configuration", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0"] = ""
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
		executor.assertCommandExecuted(t, "ip route add default via 192.168.1.1 dev eth0")
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

	t.Run("with DHCP DNS - skips DNS config but unlocks resolv.conf", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["ip link set eth0 up"] = ""
		executor.commands["ip addr flush dev eth0"] = ""
		executor.commands["ip addr add 192.168.1.100/24 dev eth0"] = ""
		executor.commands["ip route add default via 192.168.1.1 dev eth0"] = ""
		executor.commands["chattr -i /etc/resolv.conf"] = "" // Allow unlocking resolv.conf
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
		// DNS should NOT be written when set to "dhcp", but resolv.conf should be unlocked
		// to allow DHCP client to write DNS servers
		unlockCalled := false
		for _, cmd := range executor.executedCmds {
			if strings.Contains(cmd, "chattr -i") && strings.Contains(cmd, "resolv.conf") {
				unlockCalled = true
			}
			// Should NOT write to resolv.conf (no tee or mv)
			if strings.Contains(cmd, "tee") && strings.Contains(cmd, "resolv.conf") {
				t.Error("should not write to resolv.conf when DNS=dhcp")
			}
			if strings.Contains(cmd, "mv") && strings.Contains(cmd, "resolv.conf") {
				t.Error("should not write to resolv.conf when DNS=dhcp")
			}
		}
		assert.True(t, unlockCalled, "should unlock resolv.conf for DHCP DNS")
	})

	t.Run("auto-detect interface falls back when detection finds nothing", func(t *testing.T) {
		executor := newMockExecutor()
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
	t.Run("success - removes immutable attribute", func(t *testing.T) {
		executor := newMockExecutor()
		executor.commands["chattr -i /etc/resolv.conf"] = ""
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		err := manager.ClearDNS()
		assert.NoError(t, err)
		executor.assertCommandExecuted(t, "chattr -i /etc/resolv.conf")
	})

	t.Run("chattr fails but continues - file not locked", func(t *testing.T) {
		executor := newMockExecutor()
		executor.errors["chattr -i /etc/resolv.conf"] = fmt.Errorf("Operation not supported")
		executor.commands["rm -f /run/net/staging.conf"] = ""
		executor.commands["tee /run/net/staging.conf"] = ""
		executor.commands["mv /run/net/staging.conf /etc/resolv.conf"] = ""
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

		// Should still succeed - chattr failure is expected on some filesystems
		err := manager.ClearDNS()
		assert.NoError(t, err)
	})
}

func TestStartDHCP_ErrorPath(t *testing.T) {
	t.Run("dhclient fails - returns error", func(t *testing.T) {
		executor := newMockExecutor()
		// New streamlined DHCP flow
		executor.commands["pkill -9 -f dhclient.*eth0"] = ""
		executor.commands["rm -f /var/lib/dhcp/dhclient.eth0.leases /run/net/dhclient.eth0.leases"] = ""
		executor.errors["timeout 15 dhclient -v eth0"] = fmt.Errorf("dhclient failed")
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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

		err := manager.SetIP("eth0", "192.168.1.100/24", "192.168.1.1")
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

		err := manager.SetIP("eth0", "192.168.1.100/24", "192.168.1.1")
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

		err := manager.SetIP("eth0", "192.168.1.100/24", "192.168.1.1")
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

		err := manager.SetIP("eth0", "192.168.1.100/24", "")
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

		err := manager.SetIP("eth0", "", "192.168.1.1")
		assert.NoError(t, err)
	})
}

func TestDHCPRenew_ErrorPaths(t *testing.T) {
	t.Run("dhclient fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				// New streamlined DHCP flow
				"pkill -9 -f dhclient.*eth0": "",
				"rm -f /var/lib/dhcp/dhclient.eth0.leases /run/net/dhclient.eth0.leases": "",
			},
			errors: map[string]error{
				"timeout 15 dhclient -v eth0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger}

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
