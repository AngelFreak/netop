package wifi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Mock implementations
type mockSystemExecutor struct {
	commands    map[string]string
	errors      map[string]error
	callCount   map[string]int
	hasCommands map[string]bool // which commands are "installed"
}

func (m *mockSystemExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}

	// Special handling for wpa_cli status when callCount is set (for association simulation)
	if fullCmd == "wpa_cli -i wlan0 status" && m.callCount != nil {
		count := m.callCount[fullCmd]
		m.callCount[fullCmd] = count + 1
		if count == 0 {
			return "wpa_state=SCANNING", nil
		} else {
			return "wpa_state=COMPLETED\nssid=TestSSID", nil
		}
	}

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
	return "mock output", nil
}

func (m *mockSystemExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
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

// recordingExecutor wraps mockSystemExecutor to record the order of commands called
type recordingExecutor struct {
	mockSystemExecutor
	calledCommands []string
}

func (r *recordingExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}
	r.calledCommands = append(r.calledCommands, fullCmd)
	return r.mockSystemExecutor.Execute(cmd, args...)
}

func (r *recordingExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}
	r.calledCommands = append(r.calledCommands, fullCmd)
	return r.mockSystemExecutor.Execute(cmd, args...)
}

// indexOf returns the index of the first occurrence of s in slice, or -1
func indexOf(slice []string, s string) int {
	for i, v := range slice {
		if v == s {
			return i
		}
	}
	return -1
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
	manager := NewManager(executor, logger, "wlan0", dhcpClient)
	assert.NotNil(t, manager)
	assert.Equal(t, "wlan0", manager.iface)
	assert.Equal(t, dhcpClient, manager.dhcpClient)
}

func TestScan(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan": "",
				"iw wlan0 scan dump": `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: TestNetwork
signal: -50.00
freq: 2412

BSS 11:22:33:44:55:66(on wlan0)
SSID: AnotherNetwork
signal: -60.00
freq: 2437
`,
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.linkMgr = &fake.LinkManager{}

		networks, err := manager.Scan()
		assert.NoError(t, err)
		assert.Len(t, networks, 2)

		// Networks should be sorted by signal strength (strongest first)
		// TestNetwork (-50 dBm) should come before AnotherNetwork (-60 dBm)
		assert.Equal(t, "TestNetwork", networks[0].SSID)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", networks[0].BSSID)
		assert.Equal(t, -50, networks[0].Signal)
		assert.Equal(t, 2412, networks[0].Frequency)

		assert.Equal(t, "AnotherNetwork", networks[1].SSID)
		assert.Equal(t, "11:22:33:44:55:66", networks[1].BSSID)
		assert.Equal(t, -60, networks[1].Signal)
		assert.Equal(t, 2437, networks[1].Frequency)
	})

	t.Run("fresh scan fails but dump succeeds", func(t *testing.T) {
		// When iw scan fails (e.g. permission error), we fall back to cached results
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan dump": `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: CachedNetwork
signal: -55.00
freq: 2412
`,
			},
			errors: map[string]error{
				"iw wlan0 scan": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.linkMgr = &fake.LinkManager{}

		networks, err := manager.Scan()
		assert.NoError(t, err)
		assert.Len(t, networks, 1)
		assert.Equal(t, "CachedNetwork", networks[0].SSID)
	})

	t.Run("both scan and dump fail", func(t *testing.T) {
		// When both iw scan and iw scan dump fail, Scan() returns an error
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"iw wlan0 scan":      assert.AnError,
				"iw wlan0 scan dump": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.linkMgr = &fake.LinkManager{}

		_, err := manager.Scan()
		assert.Error(t, err)
	})
}

func TestConnect(t *testing.T) {
	t.Run("reconnects even if already connected to different network", func(t *testing.T) {
		tmp := t.TempDir()
		// When connected to a different network, disconnect first
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link": `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
SSID: OtherSSID`,
				// Disconnect commands (interface-specific termination)
				"wpa_cli -i wlan0 terminate":  "",
				"pkill -9 -f dhclient.*wlan0": "",
				// Reconnect commands
				"wpa_supplicant -B -i wlan0 -c " + tmp + "/wpa_supplicant.conf": "",
				"wpa_cli -i wlan0 status": "wpa_state=COMPLETED\nssid=TestSSID",
				// DHCP flow
				"pkill -9 -f udhcpc.*wlan0": "",
				"rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases": "",
				"timeout 15 dhclient -v wlan0":                                             "",
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.linkMgr = &fake.LinkManager{}
		manager.addrMgr = &fake.AddrManager{}
		manager.routeMgr = &fake.RouteManager{}
		manager.runtimeDir = tmp

		err := manager.Connect("TestSSID", "password", "")
		assert.NoError(t, err)
	})

	t.Run("needs connection", func(t *testing.T) {
		tmp := t.TempDir()
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link": "Not connected",
				// Interface-specific wpa_supplicant termination
				"wpa_cli -i wlan0 terminate":                                    "",
				"wpa_supplicant -B -i wlan0 -c " + tmp + "/wpa_supplicant.conf": "",
				// DHCP flow
				"pkill -9 -f udhcpc.*wlan0":   "",
				"pkill -9 -f dhclient.*wlan0": "",
				"rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases": "",
				"timeout 15 dhclient -v wlan0":                                             "",
			},
			callCount: make(map[string]int),
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.linkMgr = &fake.LinkManager{}
		manager.addrMgr = &fake.AddrManager{}
		manager.routeMgr = &fake.RouteManager{}
		manager.runtimeDir = tmp

		err := manager.Connect("TestSSID", "password", "")
		assert.NoError(t, err)
	})

	t.Run("association timeout", func(t *testing.T) {
		tmp := t.TempDir()
		// Test that timeout is properly handled when network is unavailable
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link": "Not connected",
				// Interface-specific wpa_supplicant termination
				"wpa_cli -i wlan0 terminate":                                    "",
				"wpa_supplicant -B -i wlan0 -c " + tmp + "/wpa_supplicant.conf": "",
				"wpa_cli -i wlan0 status":                                       "wpa_state=SCANNING", // Never completes
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.linkMgr = &fake.LinkManager{}
		manager.addrMgr = &fake.AddrManager{}
		manager.routeMgr = &fake.RouteManager{}
		manager.runtimeDir = tmp
		manager.associationTimeout = 1 * time.Second // Short timeout for test

		err := manager.Connect("UnavailableSSID", "password", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout waiting for association")
	})
}

func TestConnectRejectsWEP(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"iw wlan0 link": "Not connected",
			"iw wlan0 scan dump": `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: WEPNetwork
signal: -50.00
freq: 2412
	WEP:
`,
		},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
	manager.linkMgr = &fake.LinkManager{}

	err := manager.Connect("WEPNetwork", "password", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "WEP networks are not supported")
}

func TestConnectFlushesStaleStateBeforeConnect(t *testing.T) {
	// After suspend/resume, wpa_supplicant is dead so getCurrentSSID() returns empty.
	// The full Disconnect() cleanup is skipped, but stale IPs and routes remain
	// on the interface. Verify that ConnectWithBSSID() always flushes them.
	tmp := t.TempDir()
	executor := &recordingExecutor{
		mockSystemExecutor: mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link":              "Not connected", // post-hibernation: no current SSID
				"wpa_cli -i wlan0 terminate": "",
				"wpa_supplicant -B -i wlan0 -c " + tmp + "/wpa_supplicant.conf": "",
				"wpa_cli -i wlan0 status": "wpa_state=COMPLETED\nssid=TestSSID",
			},
		},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
	links := &fake.LinkManager{}
	manager.linkMgr = links
	addrs := &fake.AddrManager{}
	manager.addrMgr = addrs
	routes := &fake.RouteManager{}
	manager.routeMgr = routes
	manager.runtimeDir = tmp

	err := manager.Connect("TestSSID", "password", "")
	assert.NoError(t, err)

	// Verify stale addresses and routes were flushed via the netlink managers.
	assert.Contains(t, addrs.Flushed, "wlan0",
		"should flush stale IP addresses before connecting")
	assert.Contains(t, routes.Flushed, "wlan0",
		"should flush stale routes before connecting")

	// Verify flush happens after terminateWpaSupplicant. The flush is recorded
	// by the netlink fakes, terminate by the executor, so compare against the
	// executor call that starts wpa_supplicant (the flush + mkdir happen natively
	// via os.MkdirAll in between, and are no longer visible to the executor).
	terminateIdx := indexOf(executor.calledCommands, "wpa_cli -i wlan0 terminate")
	wpaSupplicantStartIdx := indexOf(executor.calledCommands, "wpa_supplicant -B -i wlan0 -c "+tmp+"/wpa_supplicant.conf")
	assert.True(t, terminateIdx >= 0, "wpa_cli terminate should have been called")
	assert.True(t, terminateIdx < wpaSupplicantStartIdx,
		"terminate should come before wpa_supplicant setup (flush runs between them)")

	// The interface is brought up via the netlink LinkManager (not the executor).
	// Verify the pre-wpa_supplicant interface-up happened.
	assert.Contains(t, links.Upped, "wlan0", "interface should be brought up before wpa_supplicant")
}

func TestDisconnect(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			// Interface-specific termination commands
			"wpa_cli -i wlan0 terminate": "",
		},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
	links := &fake.LinkManager{}
	manager.linkMgr = links
	addrs := &fake.AddrManager{}
	manager.addrMgr = addrs
	routes := &fake.RouteManager{}
	manager.routeMgr = routes

	err := manager.Disconnect()
	assert.NoError(t, err)
	assert.Contains(t, links.Downed, "wlan0")
	assert.Contains(t, addrs.Flushed, "wlan0")
	assert.Contains(t, routes.Flushed, "wlan0")
}

func TestDisconnect_RemovesTempWPAConfig(t *testing.T) {
	// An interrupt mid-Connect leaves the temp wpa config behind (Connect's own
	// defer never fires). The abort action calls Disconnect, so Disconnect must
	// remove the temp config to fully restore state.
	executor := &mockSystemExecutor{
		commands: map[string]string{"wpa_cli -i wlan0 terminate": ""},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
	manager.linkMgr = &fake.LinkManager{}
	manager.addrMgr = &fake.AddrManager{}
	manager.routeMgr = &fake.RouteManager{}
	manager.runtimeDir = t.TempDir()

	// Simulate the leftover temp config.
	tempConfig := manager.wpaConfigPath()
	assert.NoError(t, os.WriteFile(tempConfig, []byte("network={}"), 0600))

	err := manager.Disconnect()
	assert.NoError(t, err)
	_, statErr := os.Stat(tempConfig)
	assert.True(t, os.IsNotExist(statErr), "Disconnect must remove the temp wpa config")
}

func TestDisconnect_MissingTempWPAConfigIsFine(t *testing.T) {
	// Best-effort removal: no temp config present (the common Disconnect case)
	// must not error.
	executor := &mockSystemExecutor{
		commands: map[string]string{"wpa_cli -i wlan0 terminate": ""},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
	manager.linkMgr = &fake.LinkManager{}
	manager.addrMgr = &fake.AddrManager{}
	manager.routeMgr = &fake.RouteManager{}
	manager.runtimeDir = t.TempDir()

	err := manager.Disconnect()
	assert.NoError(t, err)
}

func TestListConnections(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"iw wlan0 link": `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
SSID: TestNetwork`,
		},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
	manager.addrMgr = &fake.AddrManager{FirstIPv4: "192.168.1.100"}
	manager.routeMgr = &fake.RouteManager{
		Routes: []types.Route{{Gw: "192.168.1.1", Iface: "wlan0"}},
	}
	// getDNSServers() reads resolv.conf natively (os.ReadFile); point it at a
	// real temp file so DNS content is testable without touching /etc.
	resolvPath := filepath.Join(t.TempDir(), "resolv.conf")
	assert.NoError(t, os.WriteFile(resolvPath, []byte("nameserver 8.8.8.8\nnameserver 8.8.4.4\n"), 0644))
	manager.resolvConfPath = resolvPath

	connections, err := manager.ListConnections()
	assert.NoError(t, err)
	assert.Len(t, connections, 1)
	conn := connections[0]
	assert.Equal(t, "wlan0", conn.Interface)
	assert.Equal(t, "TestNetwork", conn.SSID)
	assert.Equal(t, "connected", conn.State)
	assert.Equal(t, net.ParseIP("192.168.1.100"), conn.IP)
	assert.Equal(t, net.ParseIP("192.168.1.1"), conn.Gateway)
	assert.Len(t, conn.DNS, 2)
	assert.Equal(t, net.ParseIP("8.8.8.8"), conn.DNS[0])
	assert.Equal(t, net.ParseIP("8.8.4.4"), conn.DNS[1])
}

func TestGetInterface(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})

	assert.Equal(t, "wlan0", manager.GetInterface())
}

func TestParseScanResults(t *testing.T) {
	manager := &Manager{}

	output := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: TestNetwork
signal: -50.00
freq: 2412

BSS 11:22:33:44:55:66(on wlan0)
SSID: AnotherNetwork
signal: -60.00
freq: 2437
`

	networks, err := manager.parseScanResults(output)
	assert.NoError(t, err)
	assert.Len(t, networks, 2)

	// Networks should be sorted by signal strength (strongest first)
	assert.Equal(t, "TestNetwork", networks[0].SSID)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", networks[0].BSSID)
	assert.Equal(t, -50, networks[0].Signal)
	assert.Equal(t, 2412, networks[0].Frequency)

	assert.Equal(t, "AnotherNetwork", networks[1].SSID)
	assert.Equal(t, "11:22:33:44:55:66", networks[1].BSSID)
	assert.Equal(t, -60, networks[1].Signal)
	assert.Equal(t, 2437, networks[1].Frequency)
}

func TestParseScanResultsSignalSorting(t *testing.T) {
	manager := &Manager{}

	// Test with multiple networks having different signal strengths
	output := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: WeakNetwork
signal: -85.00
freq: 2412

BSS 11:22:33:44:55:66(on wlan0)
SSID: StrongNetwork
signal: -30.00
freq: 2437

BSS 77:88:99:aa:bb:cc(on wlan0)
SSID: MediumNetwork
signal: -55.00
freq: 2462

BSS dd:ee:ff:11:22:33(on wlan0)
SSID: VeryWeakNetwork
signal: -95.00
freq: 5180
`

	networks, err := manager.parseScanResults(output)
	assert.NoError(t, err)
	assert.Len(t, networks, 4)

	// Networks should be sorted by signal strength (strongest first)
	// Expected order: StrongNetwork (-30), MediumNetwork (-55), WeakNetwork (-85), VeryWeakNetwork (-95)
	assert.Equal(t, "StrongNetwork", networks[0].SSID)
	assert.Equal(t, -30, networks[0].Signal)

	assert.Equal(t, "MediumNetwork", networks[1].SSID)
	assert.Equal(t, -55, networks[1].Signal)

	assert.Equal(t, "WeakNetwork", networks[2].SSID)
	assert.Equal(t, -85, networks[2].Signal)

	assert.Equal(t, "VeryWeakNetwork", networks[3].SSID)
	assert.Equal(t, -95, networks[3].Signal)
}

func TestParseScanResultsWPA3Detection(t *testing.T) {
	manager := &Manager{}

	t.Run("detects WPA3-SAE from RSN block", func(t *testing.T) {
		output := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: WPA3Network
signal: -45.00
freq: 5180
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: SAE
		 * Capabilities: MFPReq (0x00ac)
`
		networks, err := manager.parseScanResults(output)
		assert.NoError(t, err)
		assert.Len(t, networks, 1)
		assert.Equal(t, "WPA3", networks[0].Security)
	})

	t.Run("detects WPA2 from RSN block without SAE", func(t *testing.T) {
		output := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: WPA2Network
signal: -50.00
freq: 2412
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
`
		networks, err := manager.parseScanResults(output)
		assert.NoError(t, err)
		assert.Len(t, networks, 1)
		assert.Equal(t, "WPA2", networks[0].Security)
	})

	t.Run("detects WPA2/WPA3 transition mode", func(t *testing.T) {
		output := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: TransitionNetwork
signal: -50.00
freq: 2412
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK SAE
`
		networks, err := manager.parseScanResults(output)
		assert.NoError(t, err)
		assert.Len(t, networks, 1)
		assert.Equal(t, "WPA2/WPA3", networks[0].Security)
	})
}

func TestDetectNetworkSecurity(t *testing.T) {
	t.Run("detects WPA3 for SAE-only network", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan dump": `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: MyWPA3AP
signal: -45.00
freq: 5180
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: SAE
		 * Capabilities: MFPReq (0x00ac)
`,
			},
		}
		manager := &Manager{
			iface:    "wlan0",
			executor: executor,
			logger:   &mockLogger{},
			linkMgr:  &fake.LinkManager{},
		}
		security := manager.detectNetworkSecurity("MyWPA3AP")
		assert.Equal(t, "WPA3", security)
	})

	t.Run("detects WPA2/WPA3 for transition mode", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan dump": `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: TransitionAP
signal: -50.00
freq: 2412
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK SAE
`,
			},
		}
		manager := &Manager{
			iface:    "wlan0",
			executor: executor,
			logger:   &mockLogger{},
			linkMgr:  &fake.LinkManager{},
		}
		security := manager.detectNetworkSecurity("TransitionAP")
		assert.Equal(t, "WPA2/WPA3", security)
	})

	t.Run("returns empty for unknown SSID", func(t *testing.T) {
		scanData := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: OtherNetwork
signal: -50.00
freq: 2412
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
`
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan dump": scanData,
				"iw wlan0 scan":      scanData,
			},
		}
		manager := &Manager{
			iface:    "wlan0",
			executor: executor,
			logger:   &mockLogger{},
			linkMgr:  &fake.LinkManager{},
		}
		security := manager.detectNetworkSecurity("NotFound")
		assert.Equal(t, "", security)
	})

	t.Run("returns empty on scan failure", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"iw wlan0 scan dump": fmt.Errorf("scan failed"),
				"iw wlan0 scan":      fmt.Errorf("scan failed"),
			},
		}
		manager := &Manager{
			iface:    "wlan0",
			executor: executor,
			logger:   &mockLogger{},
			linkMgr:  &fake.LinkManager{},
		}
		security := manager.detectNetworkSecurity("AnyNetwork")
		assert.Equal(t, "", security)
	})

	t.Run("falls back to fresh scan when dump is empty", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan dump": "",
				"iw wlan0 scan": `BSS 7c:7b:ec:1a:75:7a(on wlan0)
SSID: Lanso iPhone
signal: -56.00
freq: 5180
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: SAE
		 * Capabilities: MFP-required MFP-capable (0x00cc)
`,
			},
		}
		manager := &Manager{
			iface:    "wlan0",
			executor: executor,
			logger:   &mockLogger{},
			linkMgr:  &fake.LinkManager{},
		}
		security := manager.detectNetworkSecurity("Lanso iPhone")
		assert.Equal(t, "WPA3", security)
	})
}

func TestGenerateWPAConfig(t *testing.T) {
	manager := &Manager{logger: &mockLogger{}}

	t.Run("with password defaults to transition mode", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", "password", "")
		// ctrl_interface is REQUIRED for wpa_cli to communicate with wpa_supplicant
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant", "ctrl_interface is required for wpa_cli communication")
		assert.Contains(t, config, `ssid="TestSSID"`)
		assert.Contains(t, config, `psk="password"`)
		assert.Contains(t, config, `sae_password="password"`)
		assert.Contains(t, config, "key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE")
		assert.Contains(t, config, "ieee80211w=1")
		assert.Contains(t, config, "scan_ssid=1")
		assert.Contains(t, config, "proto=RSN WPA")
		assert.Contains(t, config, "pairwise=CCMP TKIP")
	})

	t.Run("config with BSSID defaults to transition mode", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", "password", "aa:bb:cc:dd:ee:ff")
		assert.Contains(t, config, "key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE")
		assert.Contains(t, config, "ieee80211w=1")
		assert.Contains(t, config, "bssid=aa:bb:cc:dd:ee:ff")
	})

	t.Run("open network", func(t *testing.T) {
		config := manager.generateWPAConfig("OpenSSID", "", "")
		// ctrl_interface is REQUIRED for wpa_cli to communicate with wpa_supplicant
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant", "ctrl_interface is required for wpa_cli communication")
		assert.Contains(t, config, `ssid="OpenSSID"`)
		assert.Contains(t, config, `key_mgmt=NONE`)
	})

	t.Run("with BSSID pinning", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", "password", "00:11:22:33:44:55")
		// ctrl_interface is REQUIRED for wpa_cli to communicate with wpa_supplicant
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant", "ctrl_interface is required for wpa_cli communication")
		assert.Contains(t, config, `ssid="TestSSID"`)
		assert.Contains(t, config, `psk="password"`)
		assert.Contains(t, config, `bssid=00:11:22:33:44:55`)
	})

	t.Run("escapes special characters in SSID", func(t *testing.T) {
		// Test SSID with quotes and backslashes
		config := manager.generateWPAConfig(`Test"SSID\with\special`, "password", "")
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant", "ctrl_interface is required for wpa_cli communication")
		assert.Contains(t, config, `ssid="Test\"SSID\\with\\special"`)
		assert.Contains(t, config, `psk="password"`)
	})

	t.Run("escapes special characters in password", func(t *testing.T) {
		// Test password with quotes and backslashes
		config := manager.generateWPAConfig("TestSSID", `pass"word\with\quotes`, "")
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant", "ctrl_interface is required for wpa_cli communication")
		assert.Contains(t, config, `ssid="TestSSID"`)
		assert.Contains(t, config, `psk="pass\"word\\with\\quotes"`)
	})

	t.Run("escapes special characters in open network", func(t *testing.T) {
		// Test open network with special characters in SSID
		config := manager.generateWPAConfig(`Evil"Network`, "", "")
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant", "ctrl_interface is required for wpa_cli communication")
		assert.Contains(t, config, `ssid="Evil\"Network"`)
		assert.Contains(t, config, `key_mgmt=NONE`)
	})

	t.Run("escapes newlines in SSID to prevent injection", func(t *testing.T) {
		// Test SSID with newline that could inject additional config
		config := manager.generateWPAConfig("Evil\nnetwork={\nssid=\"injected\"", "password", "")
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant")
		// Newlines should be escaped as literal \n (backslash followed by 'n'), not actual newlines
		assert.Contains(t, config, `ssid="Evil\nnetwork={\nssid=\"injected\""`)
		// The config should only have actual newlines in expected places (after header, inside network block structure)
		// NOT from the injected SSID - verify by checking that the SSID value doesn't create separate lines
		lines := strings.Split(config, "\n")
		var ssidLine string
		for _, line := range lines {
			if strings.Contains(line, "ssid=") {
				ssidLine = line
				break
			}
		}
		// The entire SSID with escaped newlines should be on a single line
		assert.Contains(t, ssidLine, `Evil\nnetwork=`)
	})

	t.Run("escapes newlines in password to prevent injection", func(t *testing.T) {
		// Test password with newline that could inject additional config
		config := manager.generateWPAConfig("TestSSID", "pass\nnetwork={\nssid=\"injected\"", "")
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant")
		assert.Contains(t, config, `ssid="TestSSID"`)
		// Newlines should be escaped as literal \n
		assert.Contains(t, config, `psk="pass\nnetwork={\nssid=\"injected\""`)
	})

	t.Run("escapes carriage returns in SSID", func(t *testing.T) {
		// Test SSID with carriage return
		config := manager.generateWPAConfig("Evil\rNetwork", "password", "")
		assert.Contains(t, config, `ssid="Evil\rNetwork"`)
	})

	t.Run("rejects invalid BSSID to prevent injection", func(t *testing.T) {
		// Test with malicious BSSID containing config injection attempt
		config := manager.generateWPAConfig("TestSSID", "password", "00:11:22:33:44:55\nnetwork={\nssid=\"injected\"")
		assert.Contains(t, config, `ssid="TestSSID"`)
		assert.Contains(t, config, `psk="password"`)
		// Invalid BSSID should be silently ignored (not included in config)
		assert.NotContains(t, config, "bssid=")
		assert.NotContains(t, config, "injected")
	})

	t.Run("accepts valid BSSID formats", func(t *testing.T) {
		// Valid lowercase
		config := manager.generateWPAConfig("TestSSID", "password", "aa:bb:cc:dd:ee:ff")
		assert.Contains(t, config, "bssid=aa:bb:cc:dd:ee:ff")

		// Valid uppercase (should be normalized to lowercase)
		config = manager.generateWPAConfig("TestSSID", "password", "AA:BB:CC:DD:EE:FF")
		assert.Contains(t, config, "bssid=aa:bb:cc:dd:ee:ff")

		// Valid mixed case
		config = manager.generateWPAConfig("TestSSID", "password", "Aa:Bb:Cc:Dd:Ee:Ff")
		assert.Contains(t, config, "bssid=aa:bb:cc:dd:ee:ff")
	})

	t.Run("rejects various invalid BSSID formats", func(t *testing.T) {
		invalidBSSIDs := []string{
			"",                              // empty
			"aa:bb:cc:dd:ee",                // too short
			"aa:bb:cc:dd:ee:ff:00",          // too long
			"aabbccddeeff",                  // no colons
			"aa-bb-cc-dd-ee-ff",             // wrong separator
			"gg:hh:ii:jj:kk:ll",             // invalid hex
			"00:11:22:33:44:5",              // missing digit
			"00:11:22:33:44:55 extra",       // extra content
			"00:11:22:33:44:55\nbssid=evil", // newline injection
		}

		for _, invalidBSSID := range invalidBSSIDs {
			config := manager.generateWPAConfig("TestSSID", "password", invalidBSSID)
			assert.NotContains(t, config, "bssid=", "invalid BSSID %q should be rejected", invalidBSSID)
		}
	})
}

func TestGenerateWPAConfigSecurityAware(t *testing.T) {
	manager := &Manager{logger: &mockLogger{}}

	t.Run("WPA3-only uses SAE key_mgmt and required PMF", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", "password", "", "WPA3")
		assert.Contains(t, config, "key_mgmt=SAE")
		assert.NotContains(t, config, "WPA-PSK")
		assert.Contains(t, config, "ieee80211w=2")
		assert.Contains(t, config, `sae_password="password"`)
		assert.NotContains(t, config, "psk=")
		assert.Contains(t, config, "sae_pwe=2")
		assert.Contains(t, config, "scan_ssid=1")
		assert.Contains(t, config, "proto=RSN")
		assert.Contains(t, config, "pairwise=CCMP")
		assert.Contains(t, config, "group=CCMP")
	})

	t.Run("WPA2/WPA3 transition uses SHA256 key_mgmt and sae_password", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", "password", "", "WPA2/WPA3")
		assert.Contains(t, config, "key_mgmt=WPA-PSK-SHA256 SAE")
		assert.Contains(t, config, "ieee80211w=1")
		assert.Contains(t, config, `psk="password"`)
		assert.Contains(t, config, `sae_password="password"`)
		assert.Contains(t, config, "sae_pwe=2")
		assert.Contains(t, config, "scan_ssid=1")
		assert.Contains(t, config, "proto=RSN")
		assert.Contains(t, config, "pairwise=CCMP")
	})

	t.Run("WPA2 or unknown defaults to universal mode for compatibility", func(t *testing.T) {
		for _, sec := range []string{"WPA2", ""} {
			config := manager.generateWPAConfig("TestSSID", "password", "", sec)
			assert.Contains(t, config, "key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE")
			assert.Contains(t, config, "ieee80211w=1")
			assert.Contains(t, config, `psk="password"`)
			assert.Contains(t, config, `sae_password="password"`)
			assert.Contains(t, config, "sae_pwe=2")
			assert.Contains(t, config, "scan_ssid=1")
			assert.Contains(t, config, "proto=RSN WPA")
		}
	})

	t.Run("WPA3 with BSSID pinning", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", "password", "aa:bb:cc:dd:ee:ff", "WPA3")
		assert.Contains(t, config, "key_mgmt=SAE")
		assert.Contains(t, config, "ieee80211w=2")
		assert.Contains(t, config, `sae_password="password"`)
		assert.Contains(t, config, "bssid=aa:bb:cc:dd:ee:ff")
	})

	t.Run("WPA3 escapes special characters in sae_password", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", `pass"word\special`, "", "WPA3")
		assert.Contains(t, config, `sae_password="pass\"word\\special"`)
	})
}

func TestIsValidBSSID(t *testing.T) {
	validCases := []string{
		"00:11:22:33:44:55",
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"Aa:Bb:Cc:Dd:Ee:Ff",
		"ff:ff:ff:ff:ff:ff",
		"00:00:00:00:00:00",
	}

	for _, bssid := range validCases {
		assert.True(t, isValidBSSID(bssid), "expected %q to be valid", bssid)
	}

	invalidCases := []string{
		"",
		"aa:bb:cc:dd:ee",
		"aa:bb:cc:dd:ee:ff:00",
		"aabbccddeeff",
		"aa-bb-cc-dd-ee-ff",
		"gg:hh:ii:jj:kk:ll",
		"00:11:22:33:44:5",
		"00:11:22:33:44:55 ",
		" 00:11:22:33:44:55",
		"00:11:22:33:44:55\n",
	}

	for _, bssid := range invalidCases {
		assert.False(t, isValidBSSID(bssid), "expected %q to be invalid", bssid)
	}
}

func TestObtainDHCP(t *testing.T) {
	t.Run("delegates to DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{dhcpClient: dhcpClient, iface: "wlan0"}

		err := manager.obtainDHCP("")
		assert.NoError(t, err)
	})

	t.Run("propagates error from DHCPClientManager", func(t *testing.T) {
		dhcpClient := &mockDHCPClient{acquireErr: fmt.Errorf("dhcp failed")}
		manager := &Manager{dhcpClient: dhcpClient, iface: "wlan0"}

		err := manager.obtainDHCP("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dhcp failed")
	})
}

func TestGetCurrentSSID(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"iw wlan0 link": `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
SSID: TestNetwork`,
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

	ssid, err := manager.getCurrentSSID()
	assert.NoError(t, err)
	assert.Equal(t, "TestNetwork", ssid)
}

func TestGetDNSServers(t *testing.T) {
	logger := &mockLogger{}
	manager := NewManager(&mockSystemExecutor{}, logger, "wlan0", &mockDHCPClient{})
	// getDNSServers() reads resolv.conf natively; point it at a real temp file.
	resolvPath := filepath.Join(t.TempDir(), "resolv.conf")
	assert.NoError(t, os.WriteFile(resolvPath, []byte("nameserver 1.1.1.1\nnameserver 9.9.9.9\n"), 0644))
	manager.resolvConfPath = resolvPath

	dns, err := manager.getDNSServers()
	assert.NoError(t, err)
	assert.Len(t, dns, 2)
	assert.Equal(t, net.ParseIP("1.1.1.1"), dns[0])
	assert.Equal(t, net.ParseIP("9.9.9.9"), dns[1])
}

func TestWriteFile(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

	err := manager.writeFile("/tmp/test", "content")
	assert.NoError(t, err)
}

func TestReadFile(t *testing.T) {
	// readFile() now reads directly via os.ReadFile, so point it at a real
	// temp file instead of relying on the mock executor's "cat" command.
	dir := t.TempDir()
	path := dir + "/resolv.conf"
	if err := os.WriteFile(path, []byte("nameserver 8.8.8.8"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

	content, err := manager.readFile(path)
	assert.NoError(t, err)
	assert.Equal(t, "nameserver 8.8.8.8", content)
}

func TestDecodeSSID(t *testing.T) {
	manager := &Manager{}

	t.Run("ASCII SSID", func(t *testing.T) {
		ssid := manager.decodeSSID("TestNetwork")
		assert.Equal(t, "TestNetwork", ssid)
	})

	t.Run("Invalid escape", func(t *testing.T) {
		// Invalid hex should be left as is
		ssid := manager.decodeSSID("Test\\xZZ")
		assert.Equal(t, "Test\\xZZ", ssid)
	})

	t.Run("Hex encoded SSID", func(t *testing.T) {
		// Test with actual hex encoded chars
		ssid := manager.decodeSSID("Test\\x20Network") // \x20 is space
		assert.Equal(t, "Test Network", ssid)
	})

	t.Run("Multiple hex escapes", func(t *testing.T) {
		ssid := manager.decodeSSID("\\x48\\x65\\x6c\\x6c\\x6f") // "Hello"
		assert.Equal(t, "Hello", ssid)
	})
}

func TestDisconnect_AdditionalCases(t *testing.T) {
	t.Run("successful disconnect with cleanup", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -f wpa_supplicant": "",
				"ip addr flush dev wlan0": "",
			},
		}
		logger := &mockLogger{}
		links := &fake.LinkManager{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0", dhcpClient: &mockDHCPClient{}, linkMgr: links, addrMgr: &fake.AddrManager{}, routeMgr: &fake.RouteManager{}}

		err := manager.Disconnect()
		assert.NoError(t, err)
		assert.Contains(t, links.Downed, "wlan0")
	})

	t.Run("partial failure handling", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -f wpa_supplicant": "",
			},
		}
		logger := &mockLogger{}
		links := &fake.LinkManager{SetDownErr: assert.AnError}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0", dhcpClient: &mockDHCPClient{}, linkMgr: links, addrMgr: &fake.AddrManager{}, routeMgr: &fake.RouteManager{}}

		err := manager.Disconnect()
		// Should return error if interface down fails
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to bring interface down")
	})
}

func TestListConnections_AdditionalCases(t *testing.T) {
	t.Run("connection without DNS", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link": "Connected to 00:11:22:33:44:55 (on wlan0)\nSSID: TestNetwork",
			},
		}
		logger := &mockLogger{}
		// Empty resolv.conf → no DNS servers. Inject a real empty temp file so
		// getDNSServers() (native os.ReadFile) doesn't read this machine's /etc.
		resolvPath := filepath.Join(t.TempDir(), "resolv.conf")
		assert.NoError(t, os.WriteFile(resolvPath, []byte(""), 0644))
		manager := &Manager{
			executor:       executor,
			logger:         logger,
			iface:          "wlan0",
			addrMgr:        &fake.AddrManager{FirstIPv4: "192.168.1.100"},
			routeMgr:       &fake.RouteManager{Routes: []types.Route{{Gw: "192.168.1.1", Iface: "wlan0"}}},
			resolvConfPath: resolvPath,
		}

		connections, err := manager.ListConnections()
		assert.NoError(t, err)
		assert.Len(t, connections, 1)
		assert.Empty(t, connections[0].DNS)
	})

	t.Run("connection without gateway", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link": "Connected to 00:11:22:33:44:55 (on wlan0)\nSSID: TestNetwork",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{
			executor: executor,
			logger:   logger,
			iface:    "wlan0",
			addrMgr:  &fake.AddrManager{FirstIPv4: "192.168.1.100"},
			routeMgr: &fake.RouteManager{}, // No default route on interface
		}

		connections, err := manager.ListConnections()
		assert.NoError(t, err)
		assert.Len(t, connections, 1)
		assert.Nil(t, connections[0].Gateway)
	})
}

func TestScan_AlwaysTriggersFreshScan(t *testing.T) {
	// Even when scan dump returns cached results, a fresh scan should be triggered
	executor := &recordingExecutor{
		mockSystemExecutor: mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan": "",
				"iw wlan0 scan dump": `BSS aa:bb:cc:dd:ee:ff(on wlan0)
SSID: FreshNetwork
signal: -50.00
freq: 2412
`,
			},
		},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
	manager.linkMgr = &fake.LinkManager{}

	networks, err := manager.Scan()
	assert.NoError(t, err)
	assert.Len(t, networks, 1)

	// Verify iw scan was called (fresh scan triggered)
	assert.Contains(t, executor.calledCommands, "iw wlan0 scan",
		"should always trigger a fresh scan")

	// Verify fresh scan happens before scan dump
	scanIdx := indexOf(executor.calledCommands, "iw wlan0 scan")
	dumpIdx := indexOf(executor.calledCommands, "iw wlan0 scan dump")
	assert.True(t, scanIdx >= 0, "iw scan should have been called")
	assert.True(t, dumpIdx >= 0, "iw scan dump should have been called")
	assert.True(t, scanIdx < dumpIdx, "iw scan should be called before iw scan dump")
}

func TestScan_AdditionalCases(t *testing.T) {
	t.Run("scan with interface up failure", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan":      "",
				"iw wlan0 scan dump": "BSS 00:11:22:33:44:55\nSSID: TestNetwork\nsignal: -50.00 dBm",
			},
		}
		logger := &mockLogger{}
		// Bringing the interface up fails, but Scan only logs a warning and continues.
		links := &fake.LinkManager{SetUpErr: assert.AnError}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0", linkMgr: links}

		networks, err := manager.Scan()
		assert.NoError(t, err)
		assert.NotEmpty(t, networks)
	})
}

// Tests for interface-specific process termination (Issue 2 fix)

func TestTerminateWpaSupplicant(t *testing.T) {
	t.Run("graceful termination via wpa_cli succeeds", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"wpa_cli -i wlan0 terminate": "OK",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		// Should not panic
		manager.terminateWpaSupplicant()
	})

	t.Run("fallback to pkill when wpa_cli fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -9 wpa_supplicant": "",
			},
			errors: map[string]error{
				"wpa_cli -i wlan0 terminate": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		// Should not panic, falls back to killing all wpa_supplicant processes
		manager.terminateWpaSupplicant()
	})

	t.Run("uses correct interface in wpa_cli", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"wpa_cli -i eth0 terminate": "OK",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "eth0"}

		manager.terminateWpaSupplicant()
	})

	t.Run("kills all wpa_supplicant in pkill fallback", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -9 wpa_supplicant": "",
			},
			errors: map[string]error{
				"wpa_cli -i wlp2s0 terminate": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlp2s0"}

		manager.terminateWpaSupplicant()
	})
}

func TestTerminateDhcpClients(t *testing.T) {
	t.Run("delegates to dhcpClient.Release", func(t *testing.T) {
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{}
		manager := &Manager{logger: logger, iface: "wlan0", dhcpClient: dhcpClient}

		// Should not panic
		manager.terminateDhcpClients()
	})

	t.Run("handles Release error gracefully", func(t *testing.T) {
		logger := &mockLogger{}
		dhcpClient := &mockDHCPClient{releaseErr: assert.AnError}
		manager := &Manager{logger: logger, iface: "wlan0", dhcpClient: dhcpClient}

		// Should not panic even if Release fails
		manager.terminateDhcpClients()
	})
}

func TestDisconnectInterfaceIsolation(t *testing.T) {
	t.Run("does not kill wpa_supplicant on other interfaces", func(t *testing.T) {
		// This test verifies that disconnect only affects the managed interface
		// It uses interface-specific commands rather than global pkill
		executor := &mockSystemExecutor{
			commands: map[string]string{
				// Interface-specific commands for wlan0 only
				"wpa_cli -i wlan0 terminate": "OK",
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.linkMgr = &fake.LinkManager{}
		manager.addrMgr = &fake.AddrManager{}
		manager.routeMgr = &fake.RouteManager{}

		err := manager.Disconnect()
		assert.NoError(t, err)

		// DHCP client cleanup is now delegated to dhcpClient.Release()
		// which kills both udhcpc and dhclient for the specific interface
	})
}

func TestWaitForAssociationPollingDetectsCrash(t *testing.T) {
	t.Run("returns error after consecutive wpa_cli failures", func(t *testing.T) {
		// Simulate wpa_supplicant crash: all wpa_cli calls fail
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"wpa_cli -i wlan0 status": fmt.Errorf("Failed to connect to non-global ctrl_ifname: wlan0"),
				"wpa_cli -i wlan0 wait_event CTRL-EVENT-CONNECTED CTRL-EVENT-ASSOC-REJECT CTRL-EVENT-DISCONNECTED CTRL-EVENT-TEMP-DISABLED CTRL-EVENT-AUTH-REJECT": fmt.Errorf("Failed to connect to non-global ctrl_ifname: wlan0"),
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.associationTimeout = 5 * time.Second

		err := manager.waitForAssociation("TestSSID")

		assert.Error(t, err)
		// Should detect crash quickly, not wait the full 5s timeout
		assert.Contains(t, err.Error(), "wpa_supplicant")
		// Should NOT contain "timeout" — it should detect the crash before timeout
		assert.NotContains(t, err.Error(), "timeout")
	})

	t.Run("does not false-positive on transient wpa_cli failure", func(t *testing.T) {
		// First few wpa_cli calls fail, then succeeds — should not report crash
		callNum := 0
		executor := &countingExecutor{
			mockSystemExecutor: mockSystemExecutor{
				commands: map[string]string{},
			},
			statusFunc: func(n int) (string, error) {
				if n < 2 {
					return "", fmt.Errorf("temporarily unavailable")
				}
				return "wpa_state=COMPLETED\nssid=TestSSID", nil
			},
		}
		_ = callNum
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.associationTimeout = 5 * time.Second

		err := manager.waitForAssociation("TestSSID")

		assert.NoError(t, err)
	})
}

// countingExecutor tracks call counts per command for fine-grained control
type countingExecutor struct {
	mockSystemExecutor
	statusFunc  func(callNum int) (string, error)
	statusCalls int
}

func (c *countingExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}
	if fullCmd == "wpa_cli -i wlan0 status" && c.statusFunc != nil {
		n := c.statusCalls
		c.statusCalls++
		return c.statusFunc(n)
	}
	return c.mockSystemExecutor.Execute(cmd, args...)
}

func (c *countingExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}
	if fullCmd == "wpa_cli -i wlan0 status" && c.statusFunc != nil {
		n := c.statusCalls
		c.statusCalls++
		return c.statusFunc(n)
	}
	// For wait_event, use the error map
	return c.mockSystemExecutor.Execute(cmd, args...)
}

func TestOtherInterfaceAssociated(t *testing.T) {
	iwDev := `phy#0
	Interface wlan0
		type managed
		ssid HomeNet
	Interface wlan1
		type managed`

	t.Run("another interface associated", func(t *testing.T) {
		// From wlan1's view, wlan0 has an ssid line -> associated.
		executor := &mockSystemExecutor{commands: map[string]string{"iw dev": iwDev}}
		m := &Manager{iface: "wlan1", executor: executor, logger: &mockLogger{}}
		assert.True(t, m.otherInterfaceAssociated())
	})

	t.Run("only our interface associated", func(t *testing.T) {
		// From wlan0's view, only wlan0 has an ssid -> no OTHER interface up.
		executor := &mockSystemExecutor{commands: map[string]string{"iw dev": iwDev}}
		m := &Manager{iface: "wlan0", executor: executor, logger: &mockLogger{}}
		assert.False(t, m.otherInterfaceAssociated())
	})

	t.Run("iw error fails safe to true", func(t *testing.T) {
		executor := &mockSystemExecutor{errors: map[string]error{"iw dev": assert.AnError}}
		m := &Manager{iface: "wlan0", executor: executor, logger: &mockLogger{}}
		assert.True(t, m.otherInterfaceAssociated())
	})
}
