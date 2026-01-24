package system

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// testExecutor is a mock executor that tracks executed commands
type testExecutor struct {
	executedCommands []testCommand
	mockResponses    map[string]mockResponse
}

type testCommand struct {
	cmd   string
	args  []string
	input string
}

type mockResponse struct {
	output string
	err    error
}

func newTestExecutor() *testExecutor {
	return &testExecutor{
		mockResponses: make(map[string]mockResponse),
	}
}

func (e *testExecutor) Execute(cmd string, args ...string) (string, error) {
	e.executedCommands = append(e.executedCommands, testCommand{cmd: cmd, args: args})
	if resp, ok := e.mockResponses[cmd]; ok {
		return resp.output, resp.err
	}
	return "", nil
}

func (e *testExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return e.Execute(cmd, args...)
}

func (e *testExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return e.Execute(cmd, args...)
}

func (e *testExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	e.executedCommands = append(e.executedCommands, testCommand{cmd: cmd, args: args, input: input})
	if resp, ok := e.mockResponses[cmd]; ok {
		return resp.output, resp.err
	}
	return "", nil
}

func (e *testExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return e.ExecuteWithInput(cmd, input, args...)
}

func (e *testExecutor) HasCommand(cmd string) bool {
	return true
}

// testLogger is a mock logger for testing
type testLogger struct {
	debugMsgs []string
	infoMsgs  []string
	warnMsgs  []string
	errorMsgs []string
}

func (l *testLogger) Debug(msg string, fields ...interface{}) {
	l.debugMsgs = append(l.debugMsgs, msg)
}

func (l *testLogger) Info(msg string, fields ...interface{}) {
	l.infoMsgs = append(l.infoMsgs, msg)
}

func (l *testLogger) Warn(msg string, fields ...interface{}) {
	l.warnMsgs = append(l.warnMsgs, msg)
}

func (l *testLogger) Error(msg string, fields ...interface{}) {
	l.errorMsgs = append(l.errorMsgs, msg)
}

// Tests for KillProcessFast

func TestKillProcessFast(t *testing.T) {
	t.Run("executes pkill with SIGKILL", func(t *testing.T) {
		executor := newTestExecutor()
		logger := &testLogger{}

		KillProcessFast(executor, logger, "wpa_supplicant")

		assert.Len(t, executor.executedCommands, 1)
		cmd := executor.executedCommands[0]
		assert.Equal(t, "pkill", cmd.cmd)
		assert.Contains(t, cmd.args, "-9")
		assert.Contains(t, cmd.args, "-f")
		assert.Contains(t, cmd.args, "wpa_supplicant")
	})

	t.Run("logs debug on pkill failure", func(t *testing.T) {
		executor := newTestExecutor()
		executor.mockResponses["pkill"] = mockResponse{err: assert.AnError}
		logger := &testLogger{}

		KillProcessFast(executor, logger, "nonexistent")

		assert.Len(t, logger.debugMsgs, 1)
		assert.Contains(t, logger.debugMsgs[0], "No process to kill")
	})
}

// Tests for KillProcessGraceful

func TestKillProcessGraceful(t *testing.T) {
	t.Run("no process to kill", func(t *testing.T) {
		executor := newTestExecutor()
		executor.mockResponses["pkill"] = mockResponse{err: assert.AnError}
		logger := &testLogger{}

		KillProcessGraceful(executor, logger, "nonexistent")

		assert.Len(t, executor.executedCommands, 1)
		assert.Len(t, logger.debugMsgs, 1)
		assert.Contains(t, logger.debugMsgs[0], "No process to kill")
	})

	t.Run("process killed gracefully", func(t *testing.T) {
		executor := newTestExecutor()
		// First pkill (SIGTERM) succeeds
		executor.mockResponses["pkill"] = mockResponse{output: "", err: nil}
		// pgrep returns error (process no longer exists)
		executor.mockResponses["pgrep"] = mockResponse{err: assert.AnError}
		logger := &testLogger{}

		KillProcessGraceful(executor, logger, "openvpn")

		// Should have called pkill and pgrep
		assert.GreaterOrEqual(t, len(executor.executedCommands), 2)
	})
}

// Tests for KillProcessByPID

func TestKillProcessByPID(t *testing.T) {
	t.Run("PID file not found returns nil", func(t *testing.T) {
		executor := newTestExecutor()
		executor.mockResponses["cat"] = mockResponse{err: assert.AnError}
		logger := &testLogger{}

		err := KillProcessByPID(executor, logger, "/run/net/nonexistent.pid")

		assert.NoError(t, err)
		assert.Len(t, logger.debugMsgs, 1)
		assert.Contains(t, logger.debugMsgs[0], "PID file not found")
	})

	t.Run("empty PID file returns nil", func(t *testing.T) {
		executor := newTestExecutor()
		executor.mockResponses["cat"] = mockResponse{output: "  \n"}
		logger := &testLogger{}

		err := KillProcessByPID(executor, logger, "/run/net/empty.pid")

		assert.NoError(t, err)
		assert.Len(t, logger.debugMsgs, 1)
		assert.Contains(t, logger.debugMsgs[0], "PID file is empty")
	})

	t.Run("successfully kills process and cleans up PID file", func(t *testing.T) {
		executor := newTestExecutor()
		executor.mockResponses["cat"] = mockResponse{output: "12345"}
		executor.mockResponses["kill"] = mockResponse{} // kill -0 (still running check) returns success
		logger := &testLogger{}

		err := KillProcessByPID(executor, logger, "/run/net/test.pid")

		assert.NoError(t, err)
		// Should have: cat, kill, kill -0, kill -9, rm
		assert.GreaterOrEqual(t, len(executor.executedCommands), 3)
	})

	t.Run("process already dead returns nil", func(t *testing.T) {
		executor := newTestExecutor()
		executor.mockResponses["cat"] = mockResponse{output: "12345"}
		executor.mockResponses["kill"] = mockResponse{err: assert.AnError} // Process already dead
		logger := &testLogger{}

		err := KillProcessByPID(executor, logger, "/run/net/dead.pid")

		assert.NoError(t, err)
	})
}

// Tests for WriteSecureFile

func TestWriteSecureFile(t *testing.T) {
	t.Run("calls install with correct arguments", func(t *testing.T) {
		executor := newTestExecutor()

		err := WriteSecureFile(executor, "/tmp/test.conf", "test content")

		assert.NoError(t, err)
		assert.Len(t, executor.executedCommands, 1)
		cmd := executor.executedCommands[0]
		assert.Equal(t, "install", cmd.cmd)
		assert.Contains(t, cmd.args, "-m")
		assert.Contains(t, cmd.args, "0600")
		assert.Contains(t, cmd.args, "/dev/stdin")
		assert.Contains(t, cmd.args, "/tmp/test.conf")
		assert.Equal(t, "test content", cmd.input)
	})

	t.Run("returns error on failure", func(t *testing.T) {
		executor := newTestExecutor()
		executor.mockResponses["install"] = mockResponse{err: assert.AnError}

		err := WriteSecureFile(executor, "/tmp/test.conf", "content")

		assert.Error(t, err)
	})
}

// Tests for ParseIPFromOutput

func TestParseIPFromOutput(t *testing.T) {
	t.Run("parses valid IP address", func(t *testing.T) {
		output := `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic wlan0
       valid_lft 86400sec preferred_lft 86400sec`

		ip := ParseIPFromOutput(output)

		assert.NotNil(t, ip)
		assert.Equal(t, "192.168.1.100", ip.String())
	})

	t.Run("returns nil for no IP", func(t *testing.T) {
		output := `2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff`

		ip := ParseIPFromOutput(output)

		assert.Nil(t, ip)
	})

	t.Run("returns nil for empty output", func(t *testing.T) {
		ip := ParseIPFromOutput("")

		assert.Nil(t, ip)
	})

	t.Run("parses first IP when multiple present", func(t *testing.T) {
		output := `    inet 10.0.0.1/8 scope global eth0
    inet 192.168.1.1/24 scope global eth0`

		ip := ParseIPFromOutput(output)

		assert.NotNil(t, ip)
		assert.Equal(t, "10.0.0.1", ip.String())
	})

	t.Run("handles inet6 addresses", func(t *testing.T) {
		output := `    inet6 ::1/128 scope host
    inet 127.0.0.1/8 scope host lo`

		ip := ParseIPFromOutput(output)

		assert.NotNil(t, ip)
		assert.Equal(t, "127.0.0.1", ip.String())
	})
}

// Tests for ParseGatewayFromOutput

func TestParseGatewayFromOutput(t *testing.T) {
	t.Run("parses default gateway", func(t *testing.T) {
		output := `default via 192.168.1.1 dev wlan0 proto dhcp metric 600
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100`

		gateway := ParseGatewayFromOutput(output)

		assert.NotNil(t, gateway)
		assert.Equal(t, "192.168.1.1", gateway.String())
	})

	t.Run("returns nil for no default gateway", func(t *testing.T) {
		output := `192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100
10.0.0.0/8 dev eth0 proto kernel scope link src 10.0.0.50`

		gateway := ParseGatewayFromOutput(output)

		assert.Nil(t, gateway)
	})

	t.Run("returns nil for empty output", func(t *testing.T) {
		gateway := ParseGatewayFromOutput("")

		assert.Nil(t, gateway)
	})

	t.Run("handles IPv6 default route", func(t *testing.T) {
		output := `default via 10.10.10.1 dev eth0
default via fe80::1 dev eth0 proto kernel metric 256`

		gateway := ParseGatewayFromOutput(output)

		assert.NotNil(t, gateway)
		assert.Equal(t, "10.10.10.1", gateway.String())
	})
}

// Tests for ParseDNSFromResolvConf

func TestParseDNSFromResolvConf(t *testing.T) {
	t.Run("parses single nameserver", func(t *testing.T) {
		content := `# Generated by NetworkManager
nameserver 8.8.8.8`

		dns := ParseDNSFromResolvConf(content)

		assert.Len(t, dns, 1)
		assert.Equal(t, "8.8.8.8", dns[0].String())
	})

	t.Run("parses multiple nameservers", func(t *testing.T) {
		content := `nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1`

		dns := ParseDNSFromResolvConf(content)

		assert.Len(t, dns, 3)
		assert.Equal(t, "8.8.8.8", dns[0].String())
		assert.Equal(t, "8.8.4.4", dns[1].String())
		assert.Equal(t, "1.1.1.1", dns[2].String())
	})

	t.Run("ignores comments", func(t *testing.T) {
		content := `# This is a comment
# nameserver 9.9.9.9
nameserver 8.8.8.8`

		dns := ParseDNSFromResolvConf(content)

		assert.Len(t, dns, 1)
		assert.Equal(t, "8.8.8.8", dns[0].String())
	})

	t.Run("ignores other directives", func(t *testing.T) {
		content := `search example.com
options timeout:2
nameserver 8.8.8.8`

		dns := ParseDNSFromResolvConf(content)

		assert.Len(t, dns, 1)
	})

	t.Run("returns empty slice for no nameservers", func(t *testing.T) {
		content := `# Empty resolv.conf
search local`

		dns := ParseDNSFromResolvConf(content)

		assert.Empty(t, dns)
	})

	t.Run("returns empty slice for empty content", func(t *testing.T) {
		dns := ParseDNSFromResolvConf("")

		assert.Empty(t, dns)
	})

	t.Run("skips invalid IP addresses", func(t *testing.T) {
		content := `nameserver invalid-ip
nameserver 8.8.8.8
nameserver 256.256.256.256`

		dns := ParseDNSFromResolvConf(content)

		assert.Len(t, dns, 1)
		assert.Equal(t, "8.8.8.8", dns[0].String())
	})

	t.Run("handles IPv6 nameservers", func(t *testing.T) {
		content := `nameserver 8.8.8.8
nameserver 2001:4860:4860::8888`

		dns := ParseDNSFromResolvConf(content)

		assert.Len(t, dns, 2)
		assert.Equal(t, "8.8.8.8", dns[0].String())
		assert.True(t, dns[1].Equal(net.ParseIP("2001:4860:4860::8888")))
	})

	t.Run("handles leading/trailing whitespace", func(t *testing.T) {
		content := `  nameserver 8.8.8.8
	nameserver 1.1.1.1	`

		dns := ParseDNSFromResolvConf(content)

		assert.Len(t, dns, 2)
	})
}
