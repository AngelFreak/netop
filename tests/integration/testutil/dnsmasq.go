//go:build integration

package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// DHCPServerConfig holds configuration for a test DHCP server.
type DHCPServerConfig struct {
	Interface   string
	RangeStart  string // e.g., "192.168.100.10"
	RangeEnd    string // e.g., "192.168.100.50"
	Gateway     string // e.g., "192.168.100.1"
	Netmask     string // e.g., "255.255.255.0"
	LeaseTime   string // e.g., "1h"
	DNS         string // e.g., "8.8.8.8"
	Domain      string // e.g., "test.local"
}

// TestDHCPServer represents a running dnsmasq DHCP server for testing.
type TestDHCPServer struct {
	Config    DHCPServerConfig
	cmd       *exec.Cmd
	confFile  string
	leaseFile string
	pidFile   string
	t         *testing.T
}

// StartDHCPServer starts a dnsmasq DHCP server for testing.
func StartDHCPServer(t *testing.T, cfg DHCPServerConfig) *TestDHCPServer {
	t.Helper()
	SkipIfNotRoot(t)
	SkipIfMissingCmd(t, "dnsmasq")

	// Apply defaults
	if cfg.Netmask == "" {
		cfg.Netmask = "255.255.255.0"
	}
	if cfg.LeaseTime == "" {
		cfg.LeaseTime = "1h"
	}
	if cfg.DNS == "" {
		cfg.DNS = "8.8.8.8"
	}

	server := &TestDHCPServer{
		Config: cfg,
		t:      t,
	}

	// Create temp files
	confFile, err := os.CreateTemp("", "dnsmasq-*.conf")
	if err != nil {
		t.Fatalf("failed to create dnsmasq config file: %v", err)
	}
	server.confFile = confFile.Name()

	leaseFile, err := os.CreateTemp("", "dnsmasq-leases-*")
	if err != nil {
		os.Remove(server.confFile)
		t.Fatalf("failed to create lease file: %v", err)
	}
	server.leaseFile = leaseFile.Name()
	leaseFile.Close()

	pidFile, err := os.CreateTemp("", "dnsmasq-pid-*")
	if err != nil {
		os.Remove(server.confFile)
		os.Remove(server.leaseFile)
		t.Fatalf("failed to create pid file: %v", err)
	}
	server.pidFile = pidFile.Name()
	pidFile.Close()

	// Generate config
	confContent := server.generateConfig()
	if _, err := confFile.WriteString(confContent); err != nil {
		confFile.Close()
		server.cleanup()
		t.Fatalf("failed to write dnsmasq config: %v", err)
	}
	confFile.Close()

	// Start dnsmasq
	server.cmd = exec.Command("dnsmasq",
		"--conf-file="+server.confFile,
		"--keep-in-foreground",
		"--no-daemon",
		"--log-queries",
		"--log-dhcp",
	)

	if err := server.cmd.Start(); err != nil {
		server.cleanup()
		t.Fatalf("failed to start dnsmasq: %v", err)
	}

	// Register cleanup
	t.Cleanup(server.Stop)

	// Wait for dnsmasq to be ready
	time.Sleep(500 * time.Millisecond)

	// Verify it's still running
	if server.cmd.ProcessState != nil && server.cmd.ProcessState.Exited() {
		t.Fatalf("dnsmasq exited unexpectedly")
	}

	t.Logf("Started DHCP server: interface=%s, range=%s-%s",
		cfg.Interface, cfg.RangeStart, cfg.RangeEnd)

	return server
}

// generateConfig generates dnsmasq configuration content.
func (s *TestDHCPServer) generateConfig() string {
	cfg := s.Config

	config := fmt.Sprintf(`# Test DHCP server configuration
interface=%s
bind-interfaces
dhcp-range=%s,%s,%s,%s
dhcp-option=option:router,%s
dhcp-option=option:dns-server,%s
dhcp-leasefile=%s
pid-file=%s
`, cfg.Interface, cfg.RangeStart, cfg.RangeEnd, cfg.Netmask, cfg.LeaseTime,
		cfg.Gateway, cfg.DNS, s.leaseFile, s.pidFile)

	if cfg.Domain != "" {
		config += fmt.Sprintf("domain=%s\n", cfg.Domain)
	}

	// Disable DNS server functionality (we only want DHCP)
	config += "port=0\n"

	return config
}

// Stop stops the DHCP server.
func (s *TestDHCPServer) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	s.cleanup()
}

// cleanup removes temporary files.
func (s *TestDHCPServer) cleanup() {
	if s.confFile != "" {
		_ = os.Remove(s.confFile)
	}
	if s.leaseFile != "" {
		_ = os.Remove(s.leaseFile)
	}
	if s.pidFile != "" {
		_ = os.Remove(s.pidFile)
	}
}

// GetLeases reads and returns the current DHCP leases.
func (s *TestDHCPServer) GetLeases() (string, error) {
	content, err := os.ReadFile(s.leaseFile)
	if err != nil {
		return "", fmt.Errorf("failed to read lease file: %v", err)
	}
	return string(content), nil
}

// IsRunning checks if dnsmasq is still running.
func (s *TestDHCPServer) IsRunning() bool {
	if s.cmd == nil || s.cmd.Process == nil {
		return false
	}
	return s.cmd.ProcessState == nil || !s.cmd.ProcessState.Exited()
}

// DHCPClient represents a simple DHCP client for testing.
type DHCPClient struct {
	Interface string
	ns        *TestNamespace
	cmd       *exec.Cmd
	t         *testing.T
}

// NewDHCPClient creates a DHCP client for the given interface.
func NewDHCPClient(t *testing.T, ns *TestNamespace, iface string) *DHCPClient {
	t.Helper()
	SkipIfNotRoot(t)

	// Check for available DHCP clients
	var dhcpCmd string
	if _, err := exec.LookPath("dhclient"); err == nil {
		dhcpCmd = "dhclient"
	} else if _, err := exec.LookPath("udhcpc"); err == nil {
		dhcpCmd = "udhcpc"
	} else {
		t.Skip("skipping: no DHCP client (dhclient or udhcpc) found")
	}

	_ = dhcpCmd // Will be used when requesting lease

	return &DHCPClient{
		Interface: iface,
		ns:        ns,
		t:         t,
	}
}

// RequestLease requests a DHCP lease.
func (c *DHCPClient) RequestLease() error {
	var err error

	// Try dhclient first, then udhcpc
	if _, lookErr := exec.LookPath("dhclient"); lookErr == nil {
		if c.ns != nil {
			err = c.ns.Exec("dhclient", "-v", "-1", c.Interface)
		} else {
			cmd := exec.Command("dhclient", "-v", "-1", c.Interface)
			output, cmdErr := cmd.CombinedOutput()
			if cmdErr != nil {
				err = fmt.Errorf("%v: %s", cmdErr, output)
			}
		}
	} else {
		// Use udhcpc
		if c.ns != nil {
			err = c.ns.Exec("udhcpc", "-i", c.Interface, "-n", "-q")
		} else {
			cmd := exec.Command("udhcpc", "-i", c.Interface, "-n", "-q")
			output, cmdErr := cmd.CombinedOutput()
			if cmdErr != nil {
				err = fmt.Errorf("%v: %s", cmdErr, output)
			}
		}
	}

	return err
}

// ReleaseLease releases the DHCP lease.
func (c *DHCPClient) ReleaseLease() error {
	var err error

	if _, lookErr := exec.LookPath("dhclient"); lookErr == nil {
		if c.ns != nil {
			err = c.ns.Exec("dhclient", "-r", c.Interface)
		} else {
			err = exec.Command("dhclient", "-r", c.Interface).Run()
		}
	}

	return err
}

// GetIP returns the IP address assigned to the interface.
func (c *DHCPClient) GetIP() (string, error) {
	var output string
	var err error

	if c.ns != nil {
		output, err = c.ns.ExecOutput("ip", "addr", "show", c.Interface)
	} else {
		out, cmdErr := exec.Command("ip", "addr", "show", c.Interface).CombinedOutput()
		output = string(out)
		err = cmdErr
	}

	if err != nil {
		return "", err
	}

	// Parse inet line for IP
	// Simple parsing - look for "inet X.X.X.X"
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}

	return "", fmt.Errorf("no IP address found")
}
