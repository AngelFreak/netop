package dhcpclient

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockLogger implements types.Logger for testing
type mockLogger struct {
	debugMsgs []string
	infoMsgs  []string
	warnMsgs  []string
	errorMsgs []string
}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {
	m.debugMsgs = append(m.debugMsgs, msg)
}
func (m *mockLogger) Info(msg string, fields ...interface{}) {
	m.infoMsgs = append(m.infoMsgs, msg)
}
func (m *mockLogger) Warn(msg string, fields ...interface{}) {
	m.warnMsgs = append(m.warnMsgs, msg)
}
func (m *mockLogger) Error(msg string, fields ...interface{}) {
	m.errorMsgs = append(m.errorMsgs, msg)
}

// mockExecutor implements types.SystemExecutor for testing
type mockExecutor struct {
	commands     map[string]string
	errors       map[string]error
	hasCommands  map[string]bool
	executedCmds []string
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		commands:    make(map[string]string),
		errors:      make(map[string]error),
		hasCommands: make(map[string]bool),
	}
}

func (m *mockExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd + " " + strings.Join(args, " ")
	fullCmd = strings.TrimSpace(fullCmd)
	m.executedCmds = append(m.executedCmds, fullCmd)
	if err, ok := m.errors[fullCmd]; ok {
		return "", err
	}
	if output, ok := m.commands[fullCmd]; ok {
		return output, nil
	}
	return "", nil
}

func (m *mockExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	fullCmd := cmd + " " + strings.Join(args, " ")
	fullCmd = strings.TrimSpace(fullCmd)
	m.executedCmds = append(m.executedCmds, fullCmd)
	if err, ok := m.errors[fullCmd]; ok {
		return "", err
	}
	return "", nil
}

func (m *mockExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return m.ExecuteWithInput(cmd, input, args...)
}

func (m *mockExecutor) HasCommand(cmd string) bool {
	return m.hasCommands[cmd]
}

func (m *mockExecutor) assertCommandExecuted(t *testing.T, cmdSubstring string) {
	t.Helper()
	for _, cmd := range m.executedCmds {
		if strings.Contains(cmd, cmdSubstring) {
			return
		}
	}
	t.Errorf("Expected command containing %q to be executed, but got: %v", cmdSubstring, m.executedCmds)
}

func (m *mockExecutor) assertCommandNotExecuted(t *testing.T, cmdSubstring string) {
	t.Helper()
	for _, cmd := range m.executedCmds {
		if strings.Contains(cmd, cmdSubstring) {
			t.Errorf("Expected command containing %q NOT to be executed, but found: %v", cmdSubstring, cmd)
			return
		}
	}
}

// Tests for NewManager

func TestNewManager(t *testing.T) {
	executor := newMockExecutor()
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	assert.NotNil(t, manager)
	assert.Equal(t, executor, manager.executor)
	assert.Equal(t, logger, manager.logger)
}

// Tests for Acquire

func TestAcquire_ValidatesInterfaceName(t *testing.T) {
	tests := []struct {
		name      string
		iface     string
		expectErr bool
	}{
		{"valid interface", "wlan0", false},
		{"valid interface with dash", "wlan-0", false},
		{"valid interface with underscore", "wlan_0", false},
		{"empty interface", "", true},
		{"interface with semicolon", "wlan0;rm -rf /", true},
		{"interface with space", "wlan 0", true},
		{"interface too long", "thisinterfaceistoolong", true},
		{"interface starting with number", "0wlan", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := newMockExecutor()
			// Setup commands to not fail on valid interfaces
			executor.commands["pkill -9 -f udhcpc.*"+tt.iface] = ""
			executor.commands["pkill -9 -f dhclient.*"+tt.iface] = ""
			executor.commands["rm -f /var/lib/dhcp/dhclient."+tt.iface+".leases /run/net/dhclient."+tt.iface+".leases"] = ""
			executor.commands["rm -f /run/net/dhclient."+tt.iface+".conf"] = ""
			executor.commands["timeout 15 dhclient -v "+tt.iface] = ""
			executor.commands["ip addr show "+tt.iface] = "inet 192.168.1.50/24"
			logger := &mockLogger{}
			manager := NewManager(executor, logger)

			err := manager.Acquire(tt.iface, "")
			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid interface")
			} else {
				// May succeed or fail for other reasons, just check no validation error
				if err != nil {
					assert.NotContains(t, err.Error(), "invalid interface")
				}
			}
		})
	}
}

func TestAcquire_ValidatesHostname(t *testing.T) {
	tests := []struct {
		name      string
		hostname  string
		expectErr bool
	}{
		{"empty hostname", "", false},
		{"valid hostname", "myhost", false},
		{"valid hostname with dash", "my-host", false},
		{"valid FQDN", "my-host.example.com", false},
		{"hostname with semicolon", "host;rm -rf /", true},
		{"hostname with quotes", "host\"test", true},
		{"hostname too long", strings.Repeat("a", 300), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := newMockExecutor()
			executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
			executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
			executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
			executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
			executor.commands["timeout 15 dhclient -v wlan0"] = ""
			executor.commands["timeout 15 dhclient -v -cf /run/net/dhclient.wlan0.conf wlan0"] = ""
			executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
			logger := &mockLogger{}
			manager := NewManager(executor, logger)

			err := manager.Acquire("wlan0", tt.hostname)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid hostname")
			} else {
				if err != nil {
					assert.NotContains(t, err.Error(), "invalid hostname")
				}
			}
		})
	}
}

func TestAcquire_UsesUdhcpcWhenAvailable(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = true
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.commands["udhcpc -i wlan0 -n -q"] = ""
	executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Acquire("wlan0", "")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "udhcpc -i wlan0 -n -q")
	// Note: pkill for dhclient is still called during Release() cleanup,
	// but actual dhclient command (timeout 15 dhclient -v) is not executed
	executor.assertCommandNotExecuted(t, "timeout 15 dhclient")
}

func TestAcquire_UsesDhclientAsFallback(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = false
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.commands["timeout 15 dhclient -v wlan0"] = ""
	executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Acquire("wlan0", "")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "dhclient -v wlan0")
}

func TestAcquire_WithHostname_Udhcpc(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = true
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.commands["udhcpc -i wlan0 -n -q -x hostname:myhost"] = ""
	executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Acquire("wlan0", "myhost")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "hostname:myhost")
}

func TestAcquire_WithHostname_Dhclient(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = false
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.commands["install -m 0600 /dev/stdin /run/net/dhclient.wlan0.conf"] = ""
	executor.commands["timeout 15 dhclient -v -cf /run/net/dhclient.wlan0.conf wlan0"] = ""
	executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Acquire("wlan0", "myhost")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "-cf /run/net/dhclient.wlan0.conf")
}

func TestAcquire_InterfaceSpecificConfigPath(t *testing.T) {
	// Verify different interfaces use different config files (no race condition)
	executor1 := newMockExecutor()
	executor1.hasCommands["udhcpc"] = false
	executor1.commands["pkill -9 -f udhcpc.*eth0"] = ""
	executor1.commands["pkill -9 -f dhclient.*eth0"] = ""
	executor1.commands["rm -f /var/lib/dhcp/dhclient.eth0.leases /run/net/dhclient.eth0.leases"] = ""
	executor1.commands["rm -f /run/net/dhclient.eth0.conf"] = ""
	executor1.commands["install -m 0600 /dev/stdin /run/net/dhclient.eth0.conf"] = ""
	executor1.commands["timeout 15 dhclient -v -cf /run/net/dhclient.eth0.conf eth0"] = ""
	executor1.commands["ip addr show eth0"] = "inet 10.0.0.50/24"
	logger1 := &mockLogger{}
	manager1 := NewManager(executor1, logger1)

	executor2 := newMockExecutor()
	executor2.hasCommands["udhcpc"] = false
	executor2.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor2.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor2.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
	executor2.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor2.commands["install -m 0600 /dev/stdin /run/net/dhclient.wlan0.conf"] = ""
	executor2.commands["timeout 15 dhclient -v -cf /run/net/dhclient.wlan0.conf wlan0"] = ""
	executor2.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
	logger2 := &mockLogger{}
	manager2 := NewManager(executor2, logger2)

	err1 := manager1.Acquire("eth0", "host1")
	err2 := manager2.Acquire("wlan0", "host2")

	assert.NoError(t, err1)
	assert.NoError(t, err2)

	// Verify each used interface-specific config path
	executor1.assertCommandExecuted(t, "dhclient.eth0.conf")
	executor2.assertCommandExecuted(t, "dhclient.wlan0.conf")
}

func TestAcquire_DhcpClientFails(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = false
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.errors["timeout 15 dhclient -v wlan0"] = errors.New("dhclient: no lease obtained")
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Acquire("wlan0", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dhclient failed")
}

// Tests for Release

func TestRelease_ValidatesInterfaceName(t *testing.T) {
	executor := newMockExecutor()
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Release("wlan0;rm -rf /")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid interface")
}

func TestRelease_KillsBothClients(t *testing.T) {
	executor := newMockExecutor()
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Release("wlan0")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "pkill -9 -f udhcpc.*wlan0")
	executor.assertCommandExecuted(t, "pkill -9 -f dhclient.*wlan0")
}

func TestRelease_CleansUpLeaseFiles(t *testing.T) {
	executor := newMockExecutor()
	executor.commands["pkill -9 -f udhcpc.*eth0"] = ""
	executor.commands["pkill -9 -f dhclient.*eth0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.eth0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.eth0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.eth0.conf"] = ""
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Release("eth0")
	assert.NoError(t, err)
	// Verify lease file cleanup was attempted
	executor.assertCommandExecuted(t, "dhclient.eth0.leases")
}

func TestRelease_CleansUpInterfaceSpecificConfig(t *testing.T) {
	executor := newMockExecutor()
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Release("wlan0")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "dhclient.wlan0.conf")
}

func TestRelease_LogsCleanupErrors(t *testing.T) {
	executor := newMockExecutor()
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.errors["rm -f /var/lib/dhcp/dhclient.wlan0.leases"] = errors.New("permission denied")
	executor.commands["rm -f /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	// Should succeed (best-effort cleanup)
	err := manager.Release("wlan0")
	assert.NoError(t, err)
	// Should have logged the error
	assert.NotEmpty(t, logger.debugMsgs)
}

// Tests for Renew

func TestRenew_DelegatesToAcquire(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = false
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.commands["timeout 15 dhclient -v wlan0"] = ""
	executor.commands["ip addr show wlan0"] = "inet 192.168.1.50/24"
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Renew("wlan0", "")
	assert.NoError(t, err)
	executor.assertCommandExecuted(t, "dhclient -v wlan0")
}

// Tests for parseIPAddress

func TestParseIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected string
	}{
		{
			name: "standard inet line",
			output: `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic wlan0`,
			expected: "192.168.1.50",
		},
		{
			name: "multiple inet lines",
			output: `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.50/24 scope global wlan0
    inet 10.0.0.1/8 scope global secondary wlan0`,
			expected: "192.168.1.50", // Returns first
		},
		{
			name:     "no inet line",
			output:   `2: wlan0: <NO-CARRIER>`,
			expected: "",
		},
		{
			name:     "empty output",
			output:   "",
			expected: "",
		},
		{
			name:     "invalid CIDR",
			output:   "inet notanip/24",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &Manager{}
			ip := manager.parseIPAddress(tt.output)
			if tt.expected == "" {
				assert.Nil(t, ip)
			} else {
				assert.NotNil(t, ip)
				assert.Equal(t, tt.expected, ip.String())
			}
		})
	}
}

// Tests for dhclient config creation failure as hard error

func TestAcquire_DhclientConfigCreationFailure(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = false
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	// Simulate config creation failure
	executor.errors["install -m 0600 /dev/stdin /run/net/dhclient.wlan0.conf"] = errors.New("permission denied")
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	// When hostname is specified, config creation failure should be a hard error
	err := manager.Acquire("wlan0", "myhost")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create dhclient config")
}

// Tests for cleanup on DHCP acquisition failure

func TestAcquire_CleansUpOnUdhcpcFailure(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = true
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.errors["udhcpc -i wlan0 -n -q"] = errors.New("no lease obtained")
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Acquire("wlan0", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "udhcpc failed")

	// Count how many times Release was called (pkill commands)
	// Should be called twice: once before acquire attempt, once after failure
	pkillCount := 0
	for _, cmd := range executor.executedCmds {
		if strings.Contains(cmd, "pkill") && strings.Contains(cmd, "udhcpc") {
			pkillCount++
		}
	}
	assert.Equal(t, 2, pkillCount, "Release should be called both before and after udhcpc failure")
}

func TestAcquire_CleansUpOnDhclientFailure(t *testing.T) {
	executor := newMockExecutor()
	executor.hasCommands["udhcpc"] = false
	executor.commands["pkill -9 -f udhcpc.*wlan0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan0.conf"] = ""
	executor.errors["timeout 15 dhclient -v wlan0"] = errors.New("no lease obtained")
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Acquire("wlan0", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dhclient failed")

	// Count how many times Release was called (pkill commands)
	// Should be called twice: once before acquire attempt, once after failure
	pkillCount := 0
	for _, cmd := range executor.executedCmds {
		if strings.Contains(cmd, "pkill") && strings.Contains(cmd, "dhclient") {
			pkillCount++
		}
	}
	assert.Equal(t, 2, pkillCount, "Release should be called both before and after dhclient failure")
}

// Tests for regex escape in pkill patterns

func TestRelease_UsesRegexpQuoteMeta(t *testing.T) {
	// Verify that regexp.QuoteMeta is called on interface names
	// For valid interface names (letters, digits, dash, underscore), QuoteMeta
	// doesn't change the string, but it's defensive programming for future-proofing.
	// We verify the code path works correctly with a normal interface name.
	executor := newMockExecutor()
	executor.commands["pkill -9 -f udhcpc.*wlan-0"] = ""
	executor.commands["pkill -9 -f dhclient.*wlan-0"] = ""
	executor.commands["rm -f /var/lib/dhcp/dhclient.wlan-0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan-0.leases"] = ""
	executor.commands["rm -f /run/net/dhclient.wlan-0.conf"] = ""
	logger := &mockLogger{}
	manager := NewManager(executor, logger)

	err := manager.Release("wlan-0")
	assert.NoError(t, err)
	// Verify the command was executed with the interface name
	executor.assertCommandExecuted(t, "udhcpc.*wlan-0")
	executor.assertCommandExecuted(t, "dhclient.*wlan-0")
}

// Tests for timeout constants

func TestTimeoutConstants(t *testing.T) {
	assert.Equal(t, 10*time.Second, UdhcpcTimeout)
	assert.Equal(t, 15*time.Second, DhclientTimeout)
	assert.Equal(t, 500*time.Millisecond, CleanupTimeout)
	assert.Equal(t, 2*time.Second, IPCheckTimeout)
}
