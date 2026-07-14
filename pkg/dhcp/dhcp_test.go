package dhcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// startFakeProcess starts a background process whose /proc/pid/comm matches
// the given name. Returns the PID as a string and a cleanup function.
func startFakeProcess(name string) (string, func()) {
	tmpDir, err := os.MkdirTemp("", "fakeproc-*")
	if err != nil {
		return "1", func() {}
	}

	fakeBin := filepath.Join(tmpDir, name)
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\nsleep 300\n"), 0755); err != nil {
		os.RemoveAll(tmpDir)
		return "1", func() {}
	}

	cmd := exec.Command(fakeBin)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return "1", func() {}
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	return pid, func() {
		cmd.Process.Kill()
		cmd.Wait()
		os.RemoveAll(tmpDir)
	}
}

// Mock implementations
type mockExecutor struct {
	commands map[string]string
	errors   map[string]error
	called   []string // records all commands executed, in order
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		commands: make(map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *mockExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}

	m.called = append(m.called, fullCmd)

	// Check for errors first
	if err, hasErr := m.errors[fullCmd]; hasErr {
		output := ""
		if val, ok := m.commands[fullCmd]; ok {
			output = val
		}
		return output, err
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
	return m.Execute(cmd, args...)
}

func (m *mockExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return m.ExecuteWithInput(cmd, input, args...)
}

func (m *mockExecutor) HasCommand(cmd string) bool {
	return true // mock always has the command
}

type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}

// Test helpers
func setupTestManager() (*dhcpManagerImpl, *mockExecutor) {
	executor := newMockExecutor()
	logger := &mockLogger{}
	mgr := NewDHCPManager(executor, logger).(*dhcpManagerImpl)

	// Use temp files for testing
	tmpDir := os.TempDir()
	mgr.dnsmasqPidFile = filepath.Join(tmpDir, "test_dnsmasq_dhcp.pid")
	mgr.dnsmasqConfFile = filepath.Join(tmpDir, "test_dnsmasq_dhcp.conf")
	mgr.stateFile = filepath.Join(tmpDir, "test_dhcp_state")

	return mgr, executor
}

func cleanup(mgr *dhcpManagerImpl) {
	os.Remove(mgr.dnsmasqPidFile)
	os.Remove(mgr.dnsmasqConfFile)
	os.Remove(mgr.stateFile)
}

// Tests
func TestNewDHCPManager(t *testing.T) {
	executor := newMockExecutor()
	logger := &mockLogger{}

	mgr := NewDHCPManager(executor, logger)

	assert.NotNil(t, mgr)
}

func TestStart_Success(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
		DNS:       []string{"8.8.8.8"},
		LeaseTime: "24h",
	}

	// Mock successful commands
	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	err := mgr.Start(config)

	assert.NoError(t, err)
	assert.NotNil(t, mgr.currentConfig)
	assert.Equal(t, "eth0", mgr.currentConfig.Interface)

	// Verify configuration file was created
	assert.FileExists(t, mgr.dnsmasqConfFile)
}

func TestStart_InvalidConfig(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tests := []struct {
		name   string
		config *types.DHCPServerConfig
		errMsg string
	}{
		{
			name:   "missing interface",
			config: &types.DHCPServerConfig{Gateway: "192.168.1.1", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "interface is required",
		},
		{
			name:   "missing gateway",
			config: &types.DHCPServerConfig{Interface: "eth0", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "gateway is required",
		},
		{
			name:   "missing IP range",
			config: &types.DHCPServerConfig{Interface: "eth0", Gateway: "192.168.1.1"},
			errMsg: "IP range is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.Start(tt.config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestStart_AlreadyRunning(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	// Simulate running process with correct /proc/pid/comm name
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)

	// Mock commands
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestStart_InterfaceDownFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	executor.errors["ip link set eth0 down"] = fmt.Errorf("operation not permitted")

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to bring interface down")
}

func TestStart_DnsmasqFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.errors[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = fmt.Errorf("dnsmasq failed")

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start dnsmasq")
}

func TestStop_Success(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
	}

	// Create fake process with correct /proc/pid/comm name
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)

	executor.commands["kill "+dnsmasqPid] = ""
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Stop()

	assert.NoError(t, err)
	assert.Nil(t, mgr.currentConfig)
	assert.NoFileExists(t, mgr.dnsmasqPidFile)
}

func TestStop_NotRunning(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	err := mgr.Stop()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
}

func TestStop_KillFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.DHCPServerConfig{
		Interface: "eth0",
	}

	// Create fake process with correct /proc/pid/comm name
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)

	executor.errors["kill "+dnsmasqPid] = fmt.Errorf("no such process")

	err := mgr.Stop()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stop dnsmasq")
}

func TestIsRunning(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	// Test when not running
	assert.False(t, mgr.IsRunning())

	// Test when running - need fake process with correct comm name
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)
	assert.True(t, mgr.IsRunning())
}

func TestGenerateDnsmasqConfig_WithCustomDNS(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		IPRange:   "192.168.100.50,192.168.100.150",
		Gateway:   "192.168.100.1",
		DNS:       []string{"1.1.1.1", "1.0.0.1"},
		LeaseTime: "24h",
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interface=eth0")
	assert.Contains(t, content, "dhcp-range=192.168.100.50,192.168.100.150,24h")
	assert.Contains(t, content, "server=1.1.1.1")
	assert.Contains(t, content, "server=1.0.0.1")
	assert.Contains(t, content, "dhcp-option=3,192.168.100.1")
	assert.Contains(t, content, "dhcp-option=6,1.1.1.1,1.0.0.1")
}

func TestGenerateDnsmasqConfig_WithDefaultDNS(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		IPRange:   "192.168.100.50,192.168.100.150",
		Gateway:   "192.168.100.1",
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interface=eth0")
	assert.Contains(t, content, "dhcp-range=192.168.100.50,192.168.100.150,12h")
	assert.Contains(t, content, "server=8.8.8.8")
	assert.Contains(t, content, "server=8.8.4.4")
	assert.Contains(t, content, "dhcp-option=6,8.8.8.8,8.8.4.4")
}

func TestGenerateDnsmasqConfig_CustomLeaseTime(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		IPRange:   "192.168.100.50,192.168.100.150",
		Gateway:   "192.168.100.1",
		LeaseTime: "1h",
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "dhcp-range=192.168.100.50,192.168.100.150,1h")
}

func TestDnsmasqRunning(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	// Test when PID file doesn't exist
	assert.False(t, mgr.dnsmasqRunning())

	// Test when PID file exists but process doesn't
	os.WriteFile(mgr.dnsmasqPidFile, []byte("99999"), 0644)
	assert.False(t, mgr.dnsmasqRunning())

	// Test when PID file exists but process name doesn't match
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644) // PID 1 is systemd, not dnsmasq
	assert.False(t, mgr.dnsmasqRunning())

	// Test when PID file exists and process name matches
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)
	assert.True(t, mgr.dnsmasqRunning())
}

// Tests for configurable netmask (Issue 6 fix)

func TestStart_WithCustomNetmask(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "10.0.0.1",
		IPRange:   "10.0.0.50,10.0.0.150",
		Netmask:   "16", // Use /16 instead of default /24
	}

	// Mock successful commands with custom netmask
	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 10.0.0.1/16 dev eth0"] = "" // Should use /16 not /24
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	err := mgr.Start(config)

	assert.NoError(t, err)
}

func TestStart_WithDefaultNetmask(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
		// Netmask not specified - should default to /24
	}

	// Mock successful commands
	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = "" // Should default to /24
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	err := mgr.Start(config)

	assert.NoError(t, err)
}

func TestGenerateDnsmasqConfig_IncludesLeasefile(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		IPRange:   "192.168.100.50,192.168.100.150",
		Gateway:   "192.168.100.1",
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "dhcp-leasefile="+mgr.leasesFile)
}

func TestGetLeases_ValidEntries(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	// Use temp file for leases
	tmpFile, err := os.CreateTemp("", "test_leases_*")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	mgr.leasesFile = tmpFile.Name()

	content := "1709568000 aa:bb:cc:dd:ee:ff 192.168.100.51 laptop 01:aa:bb:cc:dd:ee:ff\n" +
		"1709571600 11:22:33:44:55:66 192.168.100.52 * 01:11:22:33:44:55:66\n"
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)

	leases, err := mgr.GetLeases()
	assert.NoError(t, err)
	assert.Len(t, leases, 2)

	assert.Equal(t, "aa:bb:cc:dd:ee:ff", leases[0].MAC)
	assert.Equal(t, "192.168.100.51", leases[0].IP)
	assert.Equal(t, "laptop", leases[0].Hostname)
	assert.Equal(t, int64(1709568000), leases[0].Expiry.Unix())

	// Hostname "*" should become empty
	assert.Equal(t, "11:22:33:44:55:66", leases[1].MAC)
	assert.Equal(t, "", leases[1].Hostname)
}

func TestGetLeases_EmptyFile(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tmpFile, err := os.CreateTemp("", "test_leases_*")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	mgr.leasesFile = tmpFile.Name()

	leases, err := mgr.GetLeases()
	assert.NoError(t, err)
	assert.Empty(t, leases)
}

func TestGetLeases_MissingFile(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)
	mgr.leasesFile = "/tmp/nonexistent_leases_file_test"

	leases, err := mgr.GetLeases()
	assert.NoError(t, err)
	assert.Nil(t, leases)
}

func TestGetLeases_MalformedLines(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tmpFile, err := os.CreateTemp("", "test_leases_*")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	mgr.leasesFile = tmpFile.Name()

	content := "notanumber aa:bb:cc:dd:ee:ff 192.168.100.51 laptop clientid\n" + // bad expiry -> skip
		"1709568000 aa:bb:cc 192.168.100.52\n" + // only 3 fields (<4) -> skip
		"too few fields\n" + // fewer than 4 fields -> skip
		"\n" + // blank line -> skip
		"1709568000 aa:bb:cc:dd:ee:ff 192.168.100.52 myhost clientid\n" + // valid (5 fields)
		"1709571600 11:22:33:44:55:66 192.168.100.53 phone clientid\n" // valid
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)

	leases, err := mgr.GetLeases()
	assert.NoError(t, err)
	// Should parse: line 5 and line 6
	assert.Len(t, leases, 2)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", leases[0].MAC)
	assert.Equal(t, "192.168.100.52", leases[0].IP)
	assert.Equal(t, "myhost", leases[0].Hostname)
	assert.Equal(t, "11:22:33:44:55:66", leases[1].MAC)
	assert.Equal(t, "phone", leases[1].Hostname)
}

func TestGetLeases_MultipleClients(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tmpFile, err := os.CreateTemp("", "test_leases_*")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	mgr.leasesFile = tmpFile.Name()

	// Simulate a realistic multi-client lease file
	content := "1709568000 aa:bb:cc:dd:ee:01 192.168.100.51 client-1 01:aa:bb:cc:dd:ee:01\n" +
		"1709568100 aa:bb:cc:dd:ee:02 192.168.100.52 client-2 01:aa:bb:cc:dd:ee:02\n" +
		"1709568200 aa:bb:cc:dd:ee:03 192.168.100.53 * 01:aa:bb:cc:dd:ee:03\n" +
		"1709568300 aa:bb:cc:dd:ee:04 192.168.100.54 client-4 01:aa:bb:cc:dd:ee:04\n"
	os.WriteFile(tmpFile.Name(), []byte(content), 0644)

	leases, err := mgr.GetLeases()
	assert.NoError(t, err)
	assert.Len(t, leases, 4)

	// Verify ordering is preserved
	assert.Equal(t, "192.168.100.51", leases[0].IP)
	assert.Equal(t, "192.168.100.54", leases[3].IP)

	// Verify the * hostname is empty
	assert.Equal(t, "", leases[2].Hostname)
	assert.Equal(t, "client-4", leases[3].Hostname)
}

func TestGetLeases_WhitespaceOnly(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tmpFile, err := os.CreateTemp("", "test_leases_*")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	mgr.leasesFile = tmpFile.Name()

	os.WriteFile(tmpFile.Name(), []byte("   \n  \n\n"), 0644)

	leases, err := mgr.GetLeases()
	assert.NoError(t, err)
	assert.Empty(t, leases)
}

func TestGetCurrentConfig(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	assert.Nil(t, mgr.GetCurrentConfig())

	config := &types.DHCPServerConfig{Interface: "eth0"}
	mgr.currentConfig = config
	assert.Equal(t, config, mgr.GetCurrentConfig())
}

func TestStop_CleansUpLeaseFile(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	// Create a temp leases file
	tmpFile, err := os.CreateTemp("", "test_leases_cleanup_*")
	assert.NoError(t, err)
	mgr.leasesFile = tmpFile.Name()
	os.WriteFile(tmpFile.Name(), []byte("1709568000 aa:bb:cc:dd:ee:ff 192.168.100.51 laptop id\n"), 0644)

	mgr.currentConfig = &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
	}

	// Create fake process
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)

	executor.commands["kill "+dnsmasqPid] = ""
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip link set eth0 down"] = ""

	err = mgr.Stop()
	assert.NoError(t, err)

	// Lease file should be cleaned up
	_, err = os.Stat(tmpFile.Name())
	assert.True(t, os.IsNotExist(err), "lease file should be removed after stop")
}

func TestStart_Success_SetsLeasefile(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
		DNS:       []string{"8.8.8.8"},
		LeaseTime: "24h",
	}

	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	err := mgr.Start(config)
	assert.NoError(t, err)

	// Verify generated config contains leasefile directive
	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "dhcp-leasefile=")
}

func TestValidateConfig_InvalidInterfaceName(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tests := []struct {
		name  string
		iface string
	}{
		{"space", "eth 0"},
		{"tab", "eth\t0"},
		{"newline", "eth\n0"},
		{"slash", "eth/0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &types.DHCPServerConfig{
				Interface: tt.iface,
				Gateway:   "192.168.100.1",
				IPRange:   "192.168.100.50,192.168.100.150",
			}
			err := mgr.Start(config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid interface name")
		})
	}
}

func TestValidateConfig_InvalidGateway(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "not-an-ip",
		IPRange:   "192.168.100.50,192.168.100.150",
	}
	err := mgr.Start(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid gateway")
}

func TestValidateConfig_InvalidIPRange(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tests := []struct {
		name    string
		ipRange string
	}{
		{"single ip", "192.168.100.50"},
		{"bad start ip", "bad,192.168.100.150"},
		{"bad end ip", "192.168.100.50,bad"},
		{"three parts", "192.168.100.50,192.168.100.100,192.168.100.150"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &types.DHCPServerConfig{
				Interface: "eth0",
				Gateway:   "192.168.100.1",
				IPRange:   tt.ipRange,
			}
			err := mgr.Start(config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid")
		})
	}
}

func TestValidateConfig_InvalidDNS(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
		DNS:       []string{"not-a-dns"},
	}
	err := mgr.Start(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DNS")
}

// Tests for NAT/IP forwarding (internet sharing)

func TestStart_SetsUpNAT(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	// Mock standard commands
	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	// Mock NAT commands - outbound via wlan0
	executor.commands["ip route show default"] = "default via 192.168.1.1 dev wlan0 proto dhcp"
	executor.commands["sh -c echo 1 > /proc/sys/net/ipv4/ip_forward"] = ""

	err := mgr.Start(config)
	assert.NoError(t, err)

	// Verify NAT commands were called
	assert.Contains(t, executor.called, "sh -c echo 1 > /proc/sys/net/ipv4/ip_forward")
	assert.Contains(t, executor.called, "iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE")
	assert.Contains(t, executor.called, "iptables -A FORWARD -i eth0 -j ACCEPT")
	assert.Contains(t, executor.called, "iptables -A FORWARD -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
}

func TestStart_NATSkippedWhenNoOutboundInterface(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	// No default route - NAT can't be set up but Start should still succeed
	executor.commands["ip route show default"] = ""
	executor.commands["sh -c echo 1 > /proc/sys/net/ipv4/ip_forward"] = ""

	err := mgr.Start(config)
	assert.NoError(t, err)

	// Masquerade should NOT have been called (no outbound interface)
	for _, cmd := range executor.called {
		assert.NotContains(t, cmd, "MASQUERADE")
	}
}

func TestStart_NATExcludesDHCPInterface(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	// DHCP server on eth0, but default route is also via eth0
	// Should not use eth0 as outbound — look for the next dev entry
	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	// Default route only via eth0 (same as DHCP interface) — no other route
	executor.commands["ip route show default"] = "default via 192.168.1.1 dev eth0"
	executor.commands["sh -c echo 1 > /proc/sys/net/ipv4/ip_forward"] = ""

	err := mgr.Start(config)
	assert.NoError(t, err)

	// Should NOT masquerade to itself
	for _, cmd := range executor.called {
		assert.NotContains(t, cmd, "MASQUERADE")
	}
}

func TestStop_CleansUpNAT(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
	}
	mgr.outInterface = "wlan0"

	// Create fake process
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)

	executor.commands["kill "+dnsmasqPid] = ""
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Stop()
	assert.NoError(t, err)

	// Verify NAT cleanup commands were issued
	assert.Contains(t, executor.called, "iptables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE")
	assert.Contains(t, executor.called, "iptables -D FORWARD -i eth0 -j ACCEPT")
	assert.Contains(t, executor.called, "iptables -D FORWARD -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
	assert.Contains(t, executor.called, "sh -c echo 0 > /proc/sys/net/ipv4/ip_forward")
}

func TestStop_RecoverStateFromFile(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	// Write state file (simulating crash recovery — no currentConfig or outInterface in memory)
	os.WriteFile(mgr.stateFile, []byte("eth0|wlan0"), 0600)

	// Create fake process
	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)

	executor.commands["kill "+dnsmasqPid] = ""
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Stop()
	assert.NoError(t, err)

	// Should have recovered outInterface from state file and cleaned up NAT
	assert.Contains(t, executor.called, "iptables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE")
}

// Teardown must restore the pre-server ip_forward value, not force it to 0.
func TestStop_RestoresPriorIPForward(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.DHCPServerConfig{Interface: "eth0"}
	mgr.outInterface = "wlan0"
	mgr.prevIPForward = "1" // host had forwarding enabled before us

	dnsmasqPid, cleanDnsmasq := startFakeProcess("dnsmasq")
	defer cleanDnsmasq()
	os.WriteFile(mgr.dnsmasqPidFile, []byte(dnsmasqPid), 0644)
	executor.commands["kill "+dnsmasqPid] = ""
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Stop()
	assert.NoError(t, err)
	assert.Contains(t, executor.called, "sh -c echo 1 > /proc/sys/net/ipv4/ip_forward",
		"must restore prior ip_forward=1 rather than forcing 0")
	assert.NotContains(t, executor.called, "sh -c echo 0 > /proc/sys/net/ipv4/ip_forward")
}

// If dnsmasq died on its own but state remains, Stop must still tear down the
// NAT rules and ip_forward it left behind.
func TestStop_CleansNATWhenDaemonAlreadyDead(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	// State on disk, but no running dnsmasq (no pidfile / process).
	os.WriteFile(mgr.stateFile, []byte("eth0|wlan0|0"), 0600)
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Stop()
	assert.NoError(t, err)
	assert.Contains(t, executor.called, "iptables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE",
		"NAT masquerade rule must be removed even when the daemon already died")
	assert.Contains(t, executor.called, "sh -c echo 0 > /proc/sys/net/ipv4/ip_forward")
}

func TestStart_PersistsStateFile(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""
	executor.commands["ip route show default"] = "default via 192.168.1.1 dev wlan0"
	executor.commands["sh -c echo 1 > /proc/sys/net/ipv4/ip_forward"] = ""

	err := mgr.Start(config)
	assert.NoError(t, err)

	// State file should exist with interface, outbound interface, and the
	// recorded prior ip_forward value (empty here — the test mock doesn't
	// return one for `cat /proc/.../ip_forward`).
	data, err := os.ReadFile(mgr.stateFile)
	assert.NoError(t, err)
	assert.Equal(t, "eth0|wlan0|", string(data))
}

func TestStart_WithDifferentNetmasks(t *testing.T) {
	tests := []struct {
		name     string
		netmask  string
		expected string
	}{
		{"classA", "8", "/8"},
		{"classB", "16", "/16"},
		{"classC", "24", "/24"},
		{"slash25", "25", "/25"},
		{"slash28", "28", "/28"},
		{"slash30", "30", "/30"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, executor := setupTestManager()
			defer cleanup(mgr)

			config := &types.DHCPServerConfig{
				Interface: "eth0",
				Gateway:   "10.0.0.1",
				IPRange:   "10.0.0.50,10.0.0.150",
				Netmask:   tt.netmask,
			}

			// Mock successful commands
			executor.commands["ip link set eth0 down"] = ""
			executor.commands["ip link set eth0 up"] = ""
			executor.commands["ip addr add 10.0.0.1"+tt.expected+" dev eth0"] = ""
			executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

			err := mgr.Start(config)
			assert.NoError(t, err)
		})
	}
}
