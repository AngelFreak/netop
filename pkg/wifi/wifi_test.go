package wifi

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

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
				"ip link set wlan0 up": "",
				"iw wlan0 scan":        "",
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

	t.Run("scan fails", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip link set wlan0 up": "",
				"iw wlan0 scan":        "",
			},
			errors: map[string]error{
				"iw wlan0 scan": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})

		_, err := manager.Scan()
		assert.Error(t, err)
	})
}

func TestConnect(t *testing.T) {
	t.Run("reconnects even if already connected to different network", func(t *testing.T) {
		// When connected to a different network, disconnect first
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link": `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
SSID: OtherSSID`,
				// Disconnect commands (interface-specific termination)
				"wpa_cli -i wlan0 terminate":                        "",
				"pkill -9 -f dhclient.*wlan0":                       "",
				"ip addr flush dev wlan0":                           "",
				"ip route flush dev wlan0":                          "",
				"ip link set wlan0 down":                            "",
				// Reconnect commands
				"ip link set wlan0 up":                              "",
				"mkdir -p /run/wpa_supplicant":                      "",
				"wpa_supplicant -B -i wlan0 -c /run/net/wpa_supplicant.conf -C /run/wpa_supplicant": "",
				"wpa_cli -i wlan0 status":                           "wpa_state=COMPLETED\nssid=TestSSID",
				// DHCP flow
				"pkill -9 -f udhcpc.*wlan0":                         "",
				"rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases": "",
				"timeout 15 dhclient -v wlan0":                      "",
				"ip addr show wlan0":                                "inet 192.168.1.100/24",
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})

		err := manager.Connect("TestSSID", "password", "")
		assert.NoError(t, err)
	})

	t.Run("needs connection", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link":           "Not connected",
				"ip link set wlan0 up":    "",
				// Interface-specific wpa_supplicant termination
				"wpa_cli -i wlan0 terminate": "",
				"mkdir -p /run/wpa_supplicant": "",
				"wpa_supplicant -B -i wlan0 -c /run/net/wpa_supplicant.conf -C /run/wpa_supplicant": "",
				// DHCP flow
				"pkill -9 -f udhcpc.*wlan0":   "",
				"pkill -9 -f dhclient.*wlan0":   "",
				"rm -f /var/lib/dhcp/dhclient.wlan0.leases /run/net/dhclient.wlan0.leases": "",
				"timeout 15 dhclient -v wlan0": "",
				"ip addr show wlan0":         "inet 192.168.1.100/24",
			},
			callCount: make(map[string]int),
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})

		err := manager.Connect("TestSSID", "password", "")
		assert.NoError(t, err)
	})

	t.Run("association timeout", func(t *testing.T) {
		// Test that timeout is properly handled when network is unavailable
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link":           "Not connected",
				"ip link set wlan0 up":    "",
				// Interface-specific wpa_supplicant termination
				"wpa_cli -i wlan0 terminate": "",
				"mkdir -p /run/wpa_supplicant": "",
				"wpa_supplicant -B -i wlan0 -c /run/net/wpa_supplicant.conf -C /run/wpa_supplicant": "",
				"wpa_cli -i wlan0 status": "wpa_state=SCANNING", // Never completes
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})
		manager.associationTimeout = 1 * time.Second // Short timeout for test

		err := manager.Connect("UnavailableSSID", "password", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout waiting for association")
	})
}

func TestDisconnect(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			// Interface-specific termination commands
			"wpa_cli -i wlan0 terminate":                        "",
			"pkill -9 -f dhclient.*wlan0":                       "",
			"ip addr flush dev wlan0":                           "",
			"ip route flush dev wlan0":                          "",
			"ip link set wlan0 down":                            "",
		},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})

	err := manager.Disconnect()
	assert.NoError(t, err)
}

func TestListConnections(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"ip addr show wlan0": `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0
       valid_lft forever preferred_lft forever`,
			"ip route show dev wlan0": `default via 192.168.1.1 dev wlan0`,
			"iw wlan0 link": `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
SSID: TestNetwork`,
			"cat /etc/resolv.conf": `nameserver 8.8.8.8
nameserver 1.1.1.1`,
		},
	}
	logger := &mockLogger{}
	manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})

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

func TestGenerateWPAConfig(t *testing.T) {
	manager := &Manager{logger: &mockLogger{}}

	t.Run("with password", func(t *testing.T) {
		config := manager.generateWPAConfig("TestSSID", "password", "")
		// ctrl_interface is REQUIRED for wpa_cli to communicate with wpa_supplicant
		assert.Contains(t, config, "ctrl_interface=/run/wpa_supplicant", "ctrl_interface is required for wpa_cli communication")
		assert.Contains(t, config, `ssid="TestSSID"`)
		assert.Contains(t, config, `psk="password"`)
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
			"",                               // empty
			"aa:bb:cc:dd:ee",                 // too short
			"aa:bb:cc:dd:ee:ff:00",           // too long
			"aabbccddeeff",                   // no colons
			"aa-bb-cc-dd-ee-ff",              // wrong separator
			"gg:hh:ii:jj:kk:ll",              // invalid hex
			"00:11:22:33:44:5",               // missing digit
			"00:11:22:33:44:55 extra",        // extra content
			"00:11:22:33:44:55\nbssid=evil",  // newline injection
		}

		for _, invalidBSSID := range invalidBSSIDs {
			config := manager.generateWPAConfig("TestSSID", "password", invalidBSSID)
			assert.NotContains(t, config, "bssid=", "invalid BSSID %q should be rejected", invalidBSSID)
		}
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

func TestParseIPAddress(t *testing.T) {
	manager := &Manager{}

	output := `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0
       valid_lft forever preferred_lft forever`

	ip := manager.parseIPAddress(output)
	assert.Equal(t, net.ParseIP("192.168.1.100"), ip)
}

func TestParseGateway(t *testing.T) {
	manager := &Manager{}

	output := `default via 192.168.1.1 dev wlan0`

	gateway := manager.parseGateway(output)
	assert.Equal(t, net.ParseIP("192.168.1.1"), gateway)
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
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"cat /etc/resolv.conf": `nameserver 8.8.8.8
nameserver 1.1.1.1`,
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

	dns, err := manager.getDNSServers()
	assert.NoError(t, err)
	assert.Len(t, dns, 2)
	assert.Equal(t, net.ParseIP("8.8.8.8"), dns[0])
	assert.Equal(t, net.ParseIP("1.1.1.1"), dns[1])
}

func TestWriteFile(t *testing.T) {
	executor := &mockSystemExecutor{}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

	err := manager.writeFile("/tmp/test", "content")
	assert.NoError(t, err)
}

func TestReadFile(t *testing.T) {
	executor := &mockSystemExecutor{
		commands: map[string]string{
			"cat /etc/resolv.conf": "nameserver 8.8.8.8",
		},
	}
	logger := &mockLogger{}
	manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

	content, err := manager.readFile("/etc/resolv.conf")
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

func TestHasValidIP(t *testing.T) {
	t.Run("valid IP", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr show wlan0": `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0`,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.hasValidIP()
		assert.True(t, result)
	})

	t.Run("link-local IP", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr show wlan0": `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 169.254.1.1/16 brd 169.254.255.255 scope link wlan0`,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.hasValidIP()
		assert.False(t, result)
	})

	t.Run("loopback IP", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr show wlan0": `1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo`,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.hasValidIP()
		assert.False(t, result)
	})

	t.Run("no IP", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ip addr show wlan0": `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>`,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.hasValidIP()
		assert.False(t, result)
	})

	t.Run("error executing command", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"ip addr show wlan0": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.hasValidIP()
		assert.False(t, result)
	})
}

func TestCheckCaptivePortal(t *testing.T) {
	t.Run("no captive portal - ping works", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"ping -c 1 -W 2 8.8.8.8": "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.checkCaptivePortal()
		assert.False(t, result)
	})

	t.Run("no captive portal - getent works", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"getent hosts google.com": "142.250.185.78 google.com",
			},
			errors: map[string]error{
				"ping -c 1 -W 2 8.8.8.8": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.checkCaptivePortal()
		assert.False(t, result)
	})

	t.Run("no captive portal - dig works", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"dig +short google.com": "142.250.185.78",
			},
			errors: map[string]error{
				"ping -c 1 -W 2 8.8.8.8": assert.AnError,
				"getent hosts google.com": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.checkCaptivePortal()
		assert.False(t, result)
	})

	t.Run("captive portal detected", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"ping -c 1 -W 2 8.8.8.8":  assert.AnError,
				"getent hosts google.com": assert.AnError,
				"dig +short google.com":   assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		result := manager.checkCaptivePortal()
		assert.True(t, result)
	})
}

func TestDisconnect_AdditionalCases(t *testing.T) {
	t.Run("successful disconnect with cleanup", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -f wpa_supplicant": "",
				"ip link set wlan0 down":  "",
				"ip addr flush dev wlan0": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		err := manager.Disconnect()
		assert.NoError(t, err)
	})

	t.Run("partial failure handling", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -f wpa_supplicant": "",
			},
			errors: map[string]error{
				"ip link set wlan0 down": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

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
				"iw wlan0 link":          "Connected to 00:11:22:33:44:55 (on wlan0)\nSSID: TestNetwork",
				"ip addr show wlan0":     "inet 192.168.1.100/24",
				"ip route show dev wlan0": "default via 192.168.1.1",
				"cat /etc/resolv.conf":   "", // No DNS
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		connections, err := manager.ListConnections()
		assert.NoError(t, err)
		assert.Len(t, connections, 1)
		assert.Equal(t, "TestNetwork", connections[0].SSID)
		assert.Len(t, connections[0].DNS, 0)
	})

	t.Run("connection without gateway", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 link":          "Connected to 00:11:22:33:44:55 (on wlan0)\nSSID: TestNetwork",
				"ip addr show wlan0":     "inet 192.168.1.100/24",
				"ip route show dev wlan0": "", // No gateway
				"cat /etc/resolv.conf":   "nameserver 8.8.8.8",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		connections, err := manager.ListConnections()
		assert.NoError(t, err)
		assert.Len(t, connections, 1)
		assert.Nil(t, connections[0].Gateway)
	})
}

func TestScan_AdditionalCases(t *testing.T) {
	t.Run("scan with interface up failure", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"iw wlan0 scan":      "",
				"iw wlan0 scan dump": "BSS 00:11:22:33:44:55\nSSID: TestNetwork\nsignal: -50.00 dBm",
			},
			errors: map[string]error{
				"ip link set wlan0 up": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

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
				"pkill -9 -f wpa_supplicant.*-i[[:space:]]+wlan0": "",
			},
			errors: map[string]error{
				"wpa_cli -i wlan0 terminate": assert.AnError,
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		// Should not panic, falls back to pkill
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

	t.Run("uses correct interface pattern in pkill fallback", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -9 -f wpa_supplicant.*-i[[:space:]]+wlp2s0": "",
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

func TestTerminateDhclient(t *testing.T) {
	t.Run("kills dhclient for specific interface", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -9 -f dhclient.*wlan0": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		// Should not panic
		manager.terminateDhclient()
	})

	t.Run("uses correct interface pattern", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{
				"pkill -9 -f dhclient.*eth0": "",
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "eth0"}

		manager.terminateDhclient()
	})

	t.Run("handles no matching process gracefully", func(t *testing.T) {
		executor := &mockSystemExecutor{
			commands: map[string]string{},
			errors: map[string]error{
				"pkill -9 -f dhclient.*wlan0": assert.AnError, // No process found
			},
		}
		logger := &mockLogger{}
		manager := &Manager{executor: executor, logger: logger, iface: "wlan0"}

		// Should not panic even if no process found
		manager.terminateDhclient()
	})
}

func TestDisconnectInterfaceIsolation(t *testing.T) {
	t.Run("does not kill wpa_supplicant on other interfaces", func(t *testing.T) {
		// This test verifies that disconnect only affects the managed interface
		// It uses interface-specific commands rather than global pkill
		executor := &mockSystemExecutor{
			commands: map[string]string{
				// Interface-specific commands for wlan0 only
				"wpa_cli -i wlan0 terminate":  "OK",
				"pkill -9 -f dhclient.*wlan0": "",
				"ip addr flush dev wlan0":    "",
				"ip route flush dev wlan0":   "",
				"ip link set wlan0 down":     "",
			},
		}
		logger := &mockLogger{}
		manager := NewManager(executor, logger, "wlan0", &mockDHCPClient{})

		err := manager.Disconnect()
		assert.NoError(t, err)

		// Note: The key verification is that we're NOT calling global
		// "pkill -9 -f wpa_supplicant" or "pkill -9 -f dhclient"
		// which would kill processes on other interfaces
	})
}
