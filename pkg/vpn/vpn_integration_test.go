//go:build integration

package vpn

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/angelfreak/net/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWireGuardConnect_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoWireGuard(t)
	testutil.SkipIfMissingCmd(t, "wg")
	testutil.SkipIfMissingCmd(t, "ip")

	ns := testutil.NewTestNamespace(t)

	// Create WireGuard interface in namespace
	wg := testutil.NewWireGuardInterface(t, ns, "wg-test", "10.100.100.1/24")

	// Verify interface was created
	output, err := wg.Show()
	require.NoError(t, err)
	assert.Contains(t, output, "wg-test")
	t.Logf("WireGuard interface:\n%s", output)

	// Verify interface is listed
	linkOutput, err := ns.ExecOutput("ip", "link", "show", "type", "wireguard")
	require.NoError(t, err)
	assert.Contains(t, linkOutput, "wg-test")
	t.Logf("WireGuard links:\n%s", linkOutput)

	// Verify IP was assigned
	addrOutput, err := ns.ExecOutput("ip", "addr", "show", "wg-test")
	require.NoError(t, err)
	assert.Contains(t, addrOutput, "10.100.100.1")
	t.Logf("Interface address:\n%s", addrOutput)
}

func TestWireGuardWithPeer_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoWireGuard(t)
	testutil.SkipIfMissingCmd(t, "wg")

	ns := testutil.NewTestNamespace(t)

	// Create interface
	wg := testutil.NewWireGuardInterface(t, ns, "wg-peer-test", "10.100.101.1/24")

	// Generate a peer key pair for testing
	_, peerPubKey, err := generateTestKeyPair()
	require.NoError(t, err)

	// Add a peer
	err = wg.AddPeer(testutil.WireGuardPeer{
		PublicKey:  peerPubKey,
		AllowedIPs: "10.100.101.0/24",
	})
	require.NoError(t, err)

	// Verify peer was added
	output, err := wg.Show()
	require.NoError(t, err)
	assert.Contains(t, output, "peer:")
	assert.Contains(t, output, peerPubKey)
	t.Logf("WireGuard with peer:\n%s", output)
}

func TestWireGuardDisconnect_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoWireGuard(t)
	testutil.SkipIfMissingCmd(t, "wg")

	ns := testutil.NewTestNamespace(t)

	// Create interface manually (without testutil cleanup)
	ifName := "wg-disc-test"
	err := ns.Exec("ip", "link", "add", "dev", ifName, "type", "wireguard")
	require.NoError(t, err)

	// Verify it exists
	output, err := ns.ExecOutput("ip", "link", "show", "type", "wireguard")
	require.NoError(t, err)
	assert.Contains(t, output, ifName)

	// Delete the interface
	err = ns.Exec("ip", "link", "del", ifName)
	require.NoError(t, err)

	// Verify it's gone
	output, err = ns.ExecOutput("ip", "link", "show", "type", "wireguard")
	require.NoError(t, err)
	assert.NotContains(t, output, ifName)
}

func TestVPNManagerConnect_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoWireGuard(t)
	testutil.SkipIfMissingCmd(t, "wg")

	// Ensure runtime directory exists
	runtimeDir := types.RuntimeDir
	err := os.MkdirAll(runtimeDir, 0755)
	require.NoError(t, err)

	// Clean up any existing test interface
	_ = exec.Command("ip", "link", "del", "wg-mgr-test").Run()
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "wg-mgr-test").Run()
		_ = os.Remove(filepath.Join(runtimeDir, "active-vpn"))
	})

	// Generate keys for test config
	privateKey, _, err := generateTestKeyPair()
	require.NoError(t, err)
	_, peerPubKey, err := generateTestKeyPair()
	require.NoError(t, err)

	// Create a mock config manager with test VPN config
	configMgr := &testConfigManager{
		vpnConfig: &types.VPNConfig{
			Type:      "wireguard",
			Interface: "wg-mgr-test",
			Address:   "10.200.1.1/24",
			Gateway:   false, // Don't modify routing table
			Config: strings.Join([]string{
				"[Interface]",
				"PrivateKey = " + privateKey,
				"",
				"[Peer]",
				"PublicKey = " + peerPubKey,
				"AllowedIPs = 10.200.1.0/24",
			}, "\n"),
		},
	}

	executor := &testExecutor{t: t}
	logger := &testLogger{t: t}
	manager := NewManager(executor, logger, configMgr)

	// Connect
	err = manager.Connect("test-vpn")
	require.NoError(t, err)

	// Verify interface was created
	output, err := exec.Command("ip", "link", "show", "wg-mgr-test").CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "wg-mgr-test")
	t.Logf("Created interface:\n%s", output)

	// Verify active VPN state file was created
	// Format is: vpn-name|interface|type|originalGateway|originalInterface
	stateFile := filepath.Join(runtimeDir, "active-vpn")
	content, err := os.ReadFile(stateFile)
	require.NoError(t, err)
	stateContent := strings.TrimSpace(string(content))
	stateParts := strings.Split(stateContent, "|")
	assert.Equal(t, "test-vpn", stateParts[0], "VPN name should be first part of state file")

	// Disconnect
	err = manager.Disconnect("test-vpn")
	require.NoError(t, err)

	// Verify interface was removed (command should fail or show "does not exist")
	output, err = exec.Command("ip", "link", "show", "wg-mgr-test").CombinedOutput()
	assert.Error(t, err, "ip link show should fail for removed interface")
	assert.Contains(t, string(output), "does not exist")

	// Verify state file was removed
	_, err = os.Stat(stateFile)
	assert.True(t, os.IsNotExist(err))
}

func TestVPNManagerList_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testutil.SkipIfNoWireGuard(t)
	testutil.SkipIfMissingCmd(t, "wg")

	// Clean up before test
	_ = exec.Command("ip", "link", "del", "wg-list-test").Run()
	_ = os.Remove(filepath.Join(types.RuntimeDir, "active-vpn"))

	// Ensure runtime directory exists
	err := os.MkdirAll(types.RuntimeDir, 0755)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "wg-list-test").Run()
		_ = os.Remove(filepath.Join(types.RuntimeDir, "active-vpn"))
	})

	// Generate keys
	privateKey, _, err := generateTestKeyPair()
	require.NoError(t, err)
	_, peerPubKey, err := generateTestKeyPair()
	require.NoError(t, err)

	configMgr := &testConfigManager{
		vpnConfig: &types.VPNConfig{
			Type:      "wireguard",
			Interface: "wg-list-test",
			Address:   "10.200.2.1/24",
			Gateway:   false,
			Config: strings.Join([]string{
				"[Interface]",
				"PrivateKey = " + privateKey,
				"",
				"[Peer]",
				"PublicKey = " + peerPubKey,
				"AllowedIPs = 10.200.2.0/24",
			}, "\n"),
		},
		config: &types.Config{
			VPN: map[string]types.VPNConfig{
				"test-vpn": {
					Type:      "wireguard",
					Interface: "wg-list-test",
				},
			},
		},
	}

	executor := &testExecutor{t: t}
	logger := &testLogger{t: t}
	manager := NewManager(executor, logger, configMgr)

	// List VPNs before connect - should show not connected
	vpns, err := manager.ListVPNs()
	require.NoError(t, err)
	t.Logf("VPNs before connect: %+v", vpns)

	// Connect
	err = manager.Connect("test-vpn")
	require.NoError(t, err)

	// List VPNs after connect - should show connected
	vpns, err = manager.ListVPNs()
	require.NoError(t, err)
	t.Logf("VPNs after connect: %+v", vpns)

	found := false
	for _, vpn := range vpns {
		if vpn.Name == "test-vpn" {
			found = true
			assert.True(t, vpn.Connected, "VPN should be connected")
			assert.Equal(t, "wireguard", vpn.Type)
		}
	}
	assert.True(t, found, "test-vpn should be in the list")

	// Disconnect
	err = manager.Disconnect("test-vpn")
	require.NoError(t, err)
}

// generateTestKeyPair generates a WireGuard key pair for testing.
func generateTestKeyPair() (privateKey, publicKey string, err error) {
	output, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", err
	}
	privateKey = strings.TrimSpace(string(output))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	output, err = cmd.Output()
	if err != nil {
		return "", "", err
	}
	publicKey = strings.TrimSpace(string(output))

	return privateKey, publicKey, nil
}

// testConfigManager implements types.ConfigManager for integration tests
type testConfigManager struct {
	vpnConfig *types.VPNConfig
	config    *types.Config
}

func (c *testConfigManager) LoadConfig(path string) (*types.Config, error) {
	return c.config, nil
}

func (c *testConfigManager) GetConfig() *types.Config {
	return c.config
}

func (c *testConfigManager) GetNetworkConfig(name string) (*types.NetworkConfig, error) {
	return nil, nil
}

func (c *testConfigManager) MergeWithCommon(networkName string, config *types.NetworkConfig) *types.NetworkConfig {
	return config
}

func (c *testConfigManager) GetVPNConfig(name string) (*types.VPNConfig, error) {
	return c.vpnConfig, nil
}

func (c *testConfigManager) GetIgnoredInterfaces() []string {
	return nil
}

// testExecutor implements types.SystemExecutor for integration tests
type testExecutor struct {
	t *testing.T
}

func (e *testExecutor) Execute(name string, args ...string) (string, error) {
	e.t.Logf("Execute: %s %v", name, args)
	output, err := exec.Command(name, args...).CombinedOutput()
	return string(output), err
}

func (e *testExecutor) ExecuteContext(ctx context.Context, name string, args ...string) (string, error) {
	e.t.Logf("ExecuteContext: %s %v", name, args)
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (e *testExecutor) ExecuteWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return e.ExecuteContext(ctx, name, args...)
}

func (e *testExecutor) ExecuteWithInput(name, input string, args ...string) (string, error) {
	e.t.Logf("ExecuteWithInput: %s %v (input: %d bytes)", name, args, len(input))
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (e *testExecutor) ExecuteWithInputContext(ctx context.Context, name string, input string, args ...string) (string, error) {
	e.t.Logf("ExecuteWithInputContext: %s %v (input: %d bytes)", name, args, len(input))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (e *testExecutor) HasCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// testLogger implements types.Logger for integration tests
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debug(msg string, args ...interface{}) {
	l.t.Logf("[DEBUG] "+msg, args...)
}

func (l *testLogger) Info(msg string, args ...interface{}) {
	l.t.Logf("[INFO] "+msg, args...)
}

func (l *testLogger) Warn(msg string, args ...interface{}) {
	l.t.Logf("[WARN] "+msg, args...)
}

func (l *testLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("[ERROR] "+msg, args...)
}
